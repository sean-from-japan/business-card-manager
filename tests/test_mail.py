import os
import re

from conftest import ADMIN_EMAIL, ADMIN_PASSWORD, add_user, csrf, login, post

SAME_MESSAGE = "登録されているメールアドレスであれば、再設定用のリンクを送りました。"


def outbox_files(app):
    d = os.path.join(app.config["DATA_DIR"], "outbox")
    return sorted(os.path.join(d, f) for f in os.listdir(d)) if os.path.isdir(d) else []


def request_reset(client, email):
    csrf(client)
    return post(client, "/password/forgot", {"email": email}, follow_redirects=True).get_data(as_text=True)


def test_unknown_email_same_message_and_no_mail(app):
    page = request_reset(app.test_client(), "nobody@example.test")
    assert SAME_MESSAGE in page
    assert outbox_files(app) == []


def test_reset_link_sets_new_password_and_is_single_use(app, conn):
    add_user(conn, "u@example.test")
    c = app.test_client()
    assert SAME_MESSAGE in request_reset(c, "u@example.test")
    files = outbox_files(app)
    assert len(files) == 1
    with open(files[0], encoding="utf-8") as f:
        path = re.search(r"http://localhost(/password/reset/\S+)", f.read()).group(1)
    # The raw token is not stored; only its hash is.
    assert conn.execute("SELECT COUNT(*) FROM password_resets WHERE token_hash = ?", (path.rsplit("/", 1)[1],)).fetchone()[0] == 0

    page = post(c, path, {"new": "brand-new-pass", "confirm": "brand-new-pass"}, follow_redirects=True).get_data(as_text=True)
    assert "パスワードを再設定しました" in page

    u = app.test_client()
    assert login(u, "u@example.test", "brand-new-pass").status_code == 302
    assert u.get("/cards").status_code == 200

    page = post(c, path, {"new": "another-pass-1", "confirm": "another-pass-1"}, follow_redirects=True).get_data(as_text=True)
    assert "リンクが無効か、期限が切れています。" in page
    v = app.test_client()
    login(v, "u@example.test", "another-pass-1")
    assert v.get("/cards").status_code == 302  # still logged out


def test_admin_adding_user_writes_invitation(app):
    c = app.test_client()
    login(c, ADMIN_EMAIL, ADMIN_PASSWORD)
    page = post(c, "/admin/users", {"email": "new@example.test", "password": "new-pass-123"}, follow_redirects=True).get_data(as_text=True)
    assert "招待メールを送りました" in page
    files = outbox_files(app)
    assert len(files) == 1
    with open(files[0], encoding="utf-8") as f:
        body = f.read()
    assert "To: new@example.test" in body
    assert "http://localhost/login" in body
    assert "new-pass-123" in body
