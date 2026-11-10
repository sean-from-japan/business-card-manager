"""Business card manager: Flask routes. Run with `flask --app app run`."""
import io
import json
import os
import secrets
import sys
from functools import wraps

from flask import Flask, abort, flash, g, redirect, render_template, request, send_file, session, url_for
from PIL import Image, UnidentifiedImageError
from werkzeug.security import check_password_hash, generate_password_hash

import access
import db
import extract

ALLOWED_FORMATS = {"JPEG": ".jpg", "PNG": ".png", "WEBP": ".webp"}
MAX_UPLOAD_BYTES = 5 * 1024 * 1024
MIN_PASSWORD_LEN = 8
HASH_METHOD = "pbkdf2:sha256"  # scrypt is missing from some Python builds (macOS system Python)


def create_app(config=None) -> Flask:
    app = Flask(__name__)
    app.config["DATA_DIR"] = os.environ.get("DATA_DIR", os.path.join(os.path.dirname(__file__), "data"))
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES + 64 * 1024
    app.config.update(config or {})
    data_dir = app.config["DATA_DIR"]
    for sub in ("images", "pending"):
        os.makedirs(os.path.join(data_dir, sub), exist_ok=True)
    app.config["DB_PATH"] = os.path.join(data_dir, "app.db")
    app.secret_key = os.environ.get("SECRET_KEY") or _persistent_secret(data_dir)

    conn = db.connect(app.config["DB_PATH"])
    db.init_db(conn)
    _ensure_initial_admin(conn)
    conn.close()

    _register_routes(app)
    return app


def _persistent_secret(data_dir: str) -> str:
    """Keep sessions valid across restarts without putting a secret in the repository."""
    path = os.path.join(data_dir, "secret_key")
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(secrets.token_hex(32))
        os.chmod(path, 0o600)
    with open(path) as f:
        return f.read().strip()


def _ensure_initial_admin(conn) -> None:
    if conn.execute("SELECT 1 FROM users WHERE role = 'admin'").fetchone():
        return
    email = db.normalize(os.environ.get("ADMIN_EMAIL", ""))
    password = os.environ.get("ADMIN_PASSWORD", "")
    if not email or len(password) < MIN_PASSWORD_LEN:
        print("app.py: no admin yet; set ADMIN_EMAIL and ADMIN_PASSWORD (8+ chars) and restart", file=sys.stderr)
        return
    conn.execute(
        "INSERT INTO users (email, password_hash, role) VALUES (?, ?, 'admin')",
        (email, generate_password_hash(password, method=HASH_METHOD)),
    )
    conn.commit()
    print(f"app.py: created initial admin {email}", file=sys.stderr)


def _register_routes(app: Flask) -> None:
    def get_db():
        if "db" not in g:
            g.db = db.connect(app.config["DB_PATH"])
        return g.db

    @app.teardown_appcontext
    def close_db(_exc):
        conn = g.pop("db", None)
        if conn is not None:
            conn.close()

    @app.before_request
    def load_user_and_check_csrf():
        uid = session.get("uid")
        # Role is read from the DB on every request, never from the session or the form.
        g.user = get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone() if uid else None
        if request.method == "POST":
            token = session.get("csrf")
            if not token or request.form.get("csrf") != token:
                abort(400)

    @app.context_processor
    def inject():
        if "csrf" not in session:
            session["csrf"] = secrets.token_hex(16)
        return {"csrf_token": session["csrf"], "user": g.get("user"), "FIELDS": extract.FIELDS}

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if g.user is None:
                return redirect(url_for("login", next=request.path))
            return view(*args, **kwargs)
        return wrapped

    def admin_required(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if g.user["role"] != "admin":
                abort(403)
            return view(*args, **kwargs)
        return wrapped

    def own_pending(token):
        row = get_db().execute(
            "SELECT * FROM pending WHERE token = ? AND user_id = ?", (token, g.user["id"])
        ).fetchone()
        if row is None:
            abort(404)
        return row

    def llm_status():
        """Provider name only; the key itself never reaches the browser."""
        key = extract.api_key()
        names = {"anthropic": "Claude", "openai": "GPT", "gemini": "Gemini"}
        return names.get(extract.detect_provider(key), "") if key else None

    def run_extraction(token, image_name):
        path = os.path.join(app.config["DATA_DIR"], "pending", image_name)
        try:
            result, error = extract.extract(path), None
        except extract.ExtractionError as e:
            result, error = None, str(e)
        except Exception as e:  # keep the upload so the user can retry or type the fields
            print(f"app.py: extraction failed {type(e).__name__}: {e}", file=sys.stderr)
            result, error = None, "AIの読み取り中に予期しないエラーが起きました。もう一度試すか、手で入力してください。"
        conn = get_db()
        conn.execute(
            "UPDATE pending SET result_json = ?, error = ? WHERE token = ?",
            (json.dumps(result, ensure_ascii=False) if result else None, error, token),
        )
        conn.commit()

    # --- auth ---

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            email = db.normalize(request.form.get("email", ""))
            row = get_db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            if row and check_password_hash(row["password_hash"], request.form.get("password", "")):
                session.clear()  # new session id contents on login
                session["uid"] = row["id"]
                session["csrf"] = secrets.token_hex(16)
                nxt = request.args.get("next", "")
                return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("cards"))
            flash("メールアドレスまたはパスワードが正しくありません。", "error")
        return render_template("login.html")

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    # --- cards ---

    @app.get("/")
    @login_required
    def index():
        return redirect(url_for("cards"))

    @app.get("/cards")
    @login_required
    def cards():
        q = request.args.get("q", "")
        return render_template("cards.html", cards=access.list_cards(get_db(), g.user, q), q=q)

    @app.get("/cards/<int:card_id>")
    @login_required
    def card_detail(card_id):
        card = access.get_card(get_db(), g.user, card_id)
        if card is None:
            abort(404)  # same answer for "missing" and "not allowed"
        return render_template("card.html", card=card)

    @app.get("/cards/<int:card_id>/image")
    @login_required
    def card_image(card_id):
        card = access.get_card(get_db(), g.user, card_id)
        if card is None:
            abort(404)
        resp = send_file(os.path.join(app.config["DATA_DIR"], "images", card["image_name"]))
        resp.headers["Cache-Control"] = "private, no-store"
        return resp

    @app.route("/cards/new", methods=["GET", "POST"])
    @login_required
    def card_new():
        if request.method == "GET":
            return render_template("upload.html", llm=llm_status())
        f = request.files.get("image")
        if not f or not f.filename:
            flash("画像ファイルを選んでください。", "error")
            return render_template("upload.html", llm=llm_status()), 400
        data = f.read()
        if len(data) > MAX_UPLOAD_BYTES:
            flash("画像が5MBを超えています。", "error")
            return render_template("upload.html", llm=llm_status()), 400
        try:
            with Image.open(io.BytesIO(data)) as img:
                fmt = img.format
                img.verify()
        except (UnidentifiedImageError, OSError, SyntaxError):
            fmt = None
        if fmt not in ALLOWED_FORMATS:
            flash("対応していない形式です。JPEG・PNG・WebPの画像を選んでください。", "error")
            return render_template("upload.html", llm=llm_status()), 400
        token = secrets.token_urlsafe(16)
        image_name = token + ALLOWED_FORMATS[fmt]
        with open(os.path.join(app.config["DATA_DIR"], "pending", image_name), "wb") as out:
            out.write(data)
        conn = get_db()
        conn.execute("INSERT INTO pending (token, user_id, image_name) VALUES (?, ?, ?)", (token, g.user["id"], image_name))
        conn.commit()
        run_extraction(token, image_name)
        return redirect(url_for("pending_view", token=token))

    @app.get("/cards/pending/<token>")
    @login_required
    def pending_view(token):
        row = own_pending(token)
        result = json.loads(row["result_json"]) if row["result_json"] else None
        values = result["fields"] if result else {k: "" for k in extract.KEYS}
        return render_template("confirm.html", token=token, result=result, error=row["error"], values=values)

    @app.get("/cards/pending/<token>/image")
    @login_required
    def pending_image(token):
        row = own_pending(token)
        resp = send_file(os.path.join(app.config["DATA_DIR"], "pending", row["image_name"]))
        resp.headers["Cache-Control"] = "private, no-store"
        return resp

    @app.post("/cards/pending/<token>/extract")
    @login_required
    def pending_retry(token):
        row = own_pending(token)
        run_extraction(token, row["image_name"])
        return redirect(url_for("pending_view", token=token))

    @app.post("/cards/pending/<token>/discard")
    @login_required
    def pending_discard(token):
        row = own_pending(token)
        conn = get_db()
        conn.execute("DELETE FROM pending WHERE token = ?", (token,))
        conn.commit()
        try:
            os.remove(os.path.join(app.config["DATA_DIR"], "pending", row["image_name"]))
        except OSError:
            pass
        flash("取り込んだ画像を破棄しました。", "info")
        return redirect(url_for("cards"))

    @app.post("/cards/pending/<token>/register")
    @login_required
    def pending_register(token):
        row = own_pending(token)
        values = {k: request.form.get(k, "").strip()[: extract.MAX_FIELD_LEN] for k in extract.KEYS}
        result = json.loads(row["result_json"]) if row["result_json"] else None
        if not values["name"]:
            flash("氏名は必須です。", "error")
            return render_template("confirm.html", token=token, result=result, error=row["error"], values=values), 400
        src = os.path.join(app.config["DATA_DIR"], "pending", row["image_name"])
        dst = os.path.join(app.config["DATA_DIR"], "images", row["image_name"])
        conn = get_db()
        try:
            os.replace(src, dst)
            try:
                cur = conn.execute(
                    """INSERT INTO cards (name, company, department, title, email, phone, address, website,
                       name_key, company_key, department_key, image_name, registered_by)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    [values[k] for k in extract.KEYS]
                    + [db.normalize(values["name"]), db.normalize(values["company"]),
                       db.normalize(values["department"]), row["image_name"], g.user["id"]],
                )
                conn.execute("DELETE FROM pending WHERE token = ?", (token,))
                conn.commit()
            except Exception:
                conn.rollback()
                os.replace(dst, src)
                raise
        except Exception as e:
            print(f"app.py: save failed {type(e).__name__}: {e}", file=sys.stderr)
            flash("保存に失敗しました。入力内容はそのままです。もう一度「登録」を押してください。", "error")
            return render_template("confirm.html", token=token, result=result, error=row["error"], values=values), 500
        flash("名刺を登録しました。", "info")
        return redirect(url_for("card_detail", card_id=cur.lastrowid))

    # --- admin ---

    @app.route("/admin/users", methods=["GET", "POST"])
    @admin_required
    def admin_users():
        conn = get_db()
        if request.method == "POST":
            email = db.normalize(request.form.get("email", ""))
            password = request.form.get("password", "")
            if "@" not in email:
                flash("メールアドレスを入力してください。", "error")
            elif len(password) < MIN_PASSWORD_LEN:
                flash(f"初期パスワードは{MIN_PASSWORD_LEN}文字以上にしてください。", "error")
            elif conn.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
                flash("そのメールアドレスは登録済みです。", "error")
            else:
                conn.execute(
                    "INSERT INTO users (email, password_hash, role) VALUES (?, ?, 'user')",
                    (email, generate_password_hash(password, method=HASH_METHOD)),
                )
                conn.commit()
                flash(f"{email} を一般利用者として追加しました。", "info")
                return redirect(url_for("admin_users"))
        users = conn.execute(
            """SELECT u.*, (SELECT COUNT(*) FROM grants WHERE user_id = u.id) AS grant_count
               FROM users u ORDER BY u.role, u.email"""
        ).fetchall()
        return render_template("admin_users.html", users=users)

    def target_user(user_id):
        u = get_db().execute("SELECT * FROM users WHERE id = ? AND role = 'user'", (user_id,)).fetchone()
        if u is None:
            abort(404)
        return u

    @app.get("/admin/users/<int:user_id>/grants")
    @admin_required
    def admin_grants(user_id):
        conn = get_db()
        u = target_user(user_id)
        grants = conn.execute(
            """SELECT g.*,
                 (SELECT company FROM cards WHERE company_key = g.company_key LIMIT 1) AS company_label,
                 (SELECT department FROM cards WHERE company_key = g.company_key
                    AND department_key = g.department_key LIMIT 1) AS department_label,
                 c.name AS card_name, c.company AS card_company
               FROM grants g LEFT JOIN cards c ON c.id = g.card_id
               WHERE g.user_id = ? ORDER BY g.kind, g.id""",
            (user_id,),
        ).fetchall()
        companies = conn.execute(
            "SELECT company_key, MIN(company) AS label, COUNT(*) AS n FROM cards WHERE company_key <> ''"
            " GROUP BY company_key ORDER BY label"
        ).fetchall()
        departments = conn.execute(
            "SELECT company_key, department_key, MIN(company) AS company, MIN(department) AS label, COUNT(*) AS n"
            " FROM cards WHERE company_key <> '' AND department_key <> ''"
            " GROUP BY company_key, department_key ORDER BY company, label"
        ).fetchall()
        people = conn.execute("SELECT id, name, company, department FROM cards ORDER BY name_key, id").fetchall()
        visible = access.list_cards(conn, u)
        return render_template(
            "admin_grants.html", target=u, grants=grants, companies=companies,
            departments=departments, people=people, visible=visible,
        )

    @app.post("/admin/users/<int:user_id>/grants")
    @admin_required
    def admin_grant_add(user_id):
        conn = get_db()
        target_user(user_id)
        kind = request.form.get("kind")
        company_key = department_key = ""
        card_id = None
        if kind == "company":
            company_key = request.form.get("company_key", "")
            ok = bool(company_key) and conn.execute(
                "SELECT 1 FROM cards WHERE company_key = ?", (company_key,)).fetchone()
        elif kind == "department":
            company_key, _, department_key = request.form.get("department", "").partition("\t")
            ok = bool(company_key and department_key) and conn.execute(
                "SELECT 1 FROM cards WHERE company_key = ? AND department_key = ?",
                (company_key, department_key)).fetchone()
        elif kind == "person":
            card_id = request.form.get("card_id", type=int)
            ok = card_id is not None and conn.execute("SELECT 1 FROM cards WHERE id = ?", (card_id,)).fetchone()
        else:
            ok = False
        if not ok:
            flash("許可する対象を選んでください。", "error")
        else:
            exists = conn.execute(
                "SELECT 1 FROM grants WHERE user_id = ? AND kind = ? AND company_key = ? AND department_key = ?"
                " AND card_id IS ?",
                (user_id, kind, company_key, department_key, card_id),
            ).fetchone()
            if exists:
                flash("同じ許可がすでにあります。", "info")
            else:
                conn.execute(
                    "INSERT INTO grants (user_id, kind, company_key, department_key, card_id, created_by)"
                    " VALUES (?, ?, ?, ?, ?, ?)",
                    (user_id, kind, company_key, department_key, card_id, g.user["id"]),
                )
                conn.commit()
                flash("閲覧許可を付与しました。", "info")
        return redirect(url_for("admin_grants", user_id=user_id))

    @app.post("/admin/grants/<int:grant_id>/delete")
    @admin_required
    def admin_grant_delete(grant_id):
        conn = get_db()
        row = conn.execute("SELECT user_id FROM grants WHERE id = ?", (grant_id,)).fetchone()
        if row is None:
            abort(404)
        conn.execute("DELETE FROM grants WHERE id = ?", (grant_id,))
        conn.commit()
        flash("閲覧許可を解除しました。", "info")
        return redirect(url_for("admin_grants", user_id=row["user_id"]))

    @app.errorhandler(413)
    def too_large(_e):
        flash("画像が5MBを超えています。", "error")
        return render_template("upload.html", llm=llm_status()), 413


if __name__ == "__main__":
    create_app().run(debug=False)
