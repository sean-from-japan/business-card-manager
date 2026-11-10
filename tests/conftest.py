import io
import os
import re
import sys

import pytest
from PIL import Image

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as app_module  # noqa: E402
import db  # noqa: E402
from werkzeug.security import generate_password_hash  # noqa: E402

ADMIN_EMAIL = "admin@example.test"
ADMIN_PASSWORD = "admin-pass-123"
PASSWORD = "user-pass-123"


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("ADMIN_EMAIL", ADMIN_EMAIL)
    monkeypatch.setenv("ADMIN_PASSWORD", ADMIN_PASSWORD)
    for name in ("LLM_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "LLM_PROVIDER"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("SECRET_KEY", raising=False)
    return app_module.create_app({"DATA_DIR": str(tmp_path), "TESTING": True})


@pytest.fixture
def conn(app):
    c = db.connect(app.config["DB_PATH"])
    yield c
    c.close()


def add_user(conn, email, role="user"):
    cur = conn.execute(
        "INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)",
        (email, generate_password_hash(PASSWORD, method="pbkdf2:sha256"), role),
    )
    conn.commit()
    return cur.lastrowid


def add_card(conn, app, registered_by, name, company="", department=""):
    image_name = f"img{conn.execute('SELECT COUNT(*) FROM cards').fetchone()[0]}.png"
    with open(os.path.join(app.config["DATA_DIR"], "images", image_name), "wb") as f:
        f.write(png_bytes())
    cur = conn.execute(
        """INSERT INTO cards (name, company, department, name_key, company_key, department_key, image_name, registered_by)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (name, company, department, db.normalize(name), db.normalize(company), db.normalize(department),
         image_name, registered_by),
    )
    conn.commit()
    return cur.lastrowid


def add_grant(conn, user_id, kind, company="", department="", card_id=None):
    cur = conn.execute(
        "INSERT INTO grants (user_id, kind, company_key, department_key, card_id, created_by) VALUES (?, ?, ?, ?, ?, 1)",
        (user_id, kind, db.normalize(company), db.normalize(department), card_id),
    )
    conn.commit()
    return cur.lastrowid


def png_bytes(fmt="PNG"):
    buf = io.BytesIO()
    Image.new("RGB", (60, 40), "white").save(buf, format=fmt)
    return buf.getvalue()


def csrf(client):
    client.get("/login")
    with client.session_transaction() as s:
        return s["csrf"]


def login(client, email, password=PASSWORD):
    token = csrf(client)
    return client.post("/login", data={"email": email, "password": password, "csrf": token})


def post(client, url, data=None, **kw):
    with client.session_transaction() as s:
        token = s.get("csrf")
    data = dict(data or {})
    data["csrf"] = token
    return client.post(url, data=data, **kw)


def ids_in(html):
    return sorted(int(x) for x in set(re.findall(r'href="/cards/(\d+)"', html)))
