"""End-to-end checks through Flask routes: login, direct URLs, admin-only actions, upload flow."""
import io
import os

import pytest

import app as app_module
import extract
from conftest import ADMIN_EMAIL, ADMIN_PASSWORD, add_card, add_user, csrf, ids_in, login, png_bytes, post


def test_initial_admin_can_log_in_and_unknown_email_cannot(app):
    c = app.test_client()
    assert login(c, ADMIN_EMAIL, ADMIN_PASSWORD).status_code == 302
    c2 = app.test_client()
    r = login(c2, "nobody@example.test", ADMIN_PASSWORD)
    assert r.status_code == 200 and "正しくありません" in r.get_data(as_text=True)
    assert c2.get("/cards").status_code == 302  # still redirected to login


def test_logout_ends_session(app):
    c = app.test_client()
    login(c, ADMIN_EMAIL, ADMIN_PASSWORD)
    post(c, "/logout")
    assert c.get("/cards").status_code == 302


def test_direct_url_to_other_users_card_and_image_is_404(app, conn):
    a, b = add_user(conn, "a@example.test"), add_user(conn, "b@example.test")
    theirs = add_card(conn, app, b, "Hanako", "Acme")
    mine = add_card(conn, app, a, "Taro", "Acme")
    c = app.test_client()
    login(c, "a@example.test")
    assert ids_in(c.get("/cards").get_data(as_text=True)) == [mine]
    assert c.get(f"/cards/{theirs}").status_code == 404
    assert c.get(f"/cards/{theirs}/image").status_code == 404
    assert c.get(f"/cards/{mine}/image").status_code == 200
    assert ids_in(c.get("/cards?q=Hanako").get_data(as_text=True)) == []


def test_user_cannot_use_admin_pages_or_grant_self(app, conn):
    a = add_user(conn, "a@example.test")
    b = add_user(conn, "b@example.test")
    theirs = add_card(conn, app, b, "Hanako", "Acme")
    c = app.test_client()
    login(c, "a@example.test")
    assert c.get("/admin/users").status_code == 403
    assert post(c, f"/admin/users/{a}/grants", {"kind": "company", "company_key": "acme"}).status_code == 403
    assert post(c, "/admin/users", {"email": "x@example.test", "password": "12345678"}).status_code == 403
    assert conn.execute("SELECT COUNT(*) FROM grants").fetchone()[0] == 0
    assert c.get(f"/cards/{theirs}").status_code == 404


def test_post_without_csrf_token_is_rejected(app):
    c = app.test_client()
    csrf(c)
    assert c.post("/login", data={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}).status_code == 400


def test_admin_adds_user_and_grants_company(app, conn):
    owner = add_user(conn, "o@example.test")
    card = add_card(conn, app, owner, "Taro", "Acme")
    c = app.test_client()
    login(c, ADMIN_EMAIL, ADMIN_PASSWORD)
    post(c, "/admin/users", {"email": "New@Example.test", "password": "new-pass-123"})
    new_id = conn.execute("SELECT id, role FROM users WHERE email = 'new@example.test'").fetchone()
    assert new_id["role"] == "user"
    post(c, f"/admin/users/{new_id['id']}/grants", {"kind": "company", "company_key": "acme"})
    u = app.test_client()
    login(u, "new@example.test", "new-pass-123")
    post(u, "/account/password", {"current": "new-pass-123", "new": "changed-pass-1", "confirm": "changed-pass-1"})
    assert u.get(f"/cards/{card}").status_code == 200
    gid = conn.execute("SELECT id FROM grants").fetchone()["id"]
    post(c, f"/admin/grants/{gid}/delete")
    assert u.get(f"/cards/{card}").status_code == 404


FAKE = {
    "name": " 山田 太郎 ", "company": "株式会社テスト", "department": "営業部", "title": "課長",
    "email": "taro@example.test", "phone": "TEL 0000", "address": "", "website": "",
    "unclear_fields": ["title", "not-a-field"],
}


def test_upload_confirm_register_records_logged_in_user(app, conn, monkeypatch):
    a = add_user(conn, "a@example.test")
    monkeypatch.setattr(extract, "call_llm", lambda b64: (dict(FAKE), {"input_tokens": 1, "output_tokens": 1, "model": "fake"}))
    c = app.test_client()
    login(c, "a@example.test")
    r = post(c, "/cards/new", {"image": (io.BytesIO(png_bytes()), "card.png")}, content_type="multipart/form-data")
    assert r.status_code == 302
    page = c.get(r.headers["Location"]).get_data(as_text=True)
    assert 'value="山田 太郎"' in page  # stripped, not saved yet
    assert conn.execute("SELECT COUNT(*) FROM cards").fetchone()[0] == 0
    token = r.headers["Location"].rstrip("/").split("/")[-1]
    form = {k: FAKE[k].strip() for k in extract.KEYS}
    form["title"] = "部長"  # user correction
    form["registered_by"] = "1"  # spoofing attempt is ignored
    r = post(c, f"/cards/pending/{token}/register", form)
    assert r.status_code == 302
    row = conn.execute("SELECT * FROM cards").fetchone()
    assert (row["name"], row["title"], row["registered_by"]) == ("山田 太郎", "部長", a)
    assert os.path.exists(os.path.join(app.config["DATA_DIR"], "images", row["image_name"]))


def test_extraction_failure_allows_manual_entry(app, conn):
    add_user(conn, "a@example.test")  # no API key in tests -> ExtractionError
    c = app.test_client()
    login(c, "a@example.test")
    r = post(c, "/cards/new", {"image": (io.BytesIO(png_bytes("JPEG")), "card.jpg")}, content_type="multipart/form-data")
    page = c.get(r.headers["Location"]).get_data(as_text=True)
    assert "LLM_API_KEY" in page and "手で入力" in page
    token = r.headers["Location"].split("/")[-1]
    assert post(c, f"/cards/pending/{token}/register", {"name": ""}).status_code == 400  # name required
    assert post(c, f"/cards/pending/{token}/register", {"name": "手入力 花子"}).status_code == 302


def test_other_user_cannot_open_my_pending_upload(app, conn):
    add_user(conn, "a@example.test"); add_user(conn, "b@example.test")
    c = app.test_client()
    login(c, "a@example.test")
    r = post(c, "/cards/new", {"image": (io.BytesIO(png_bytes()), "card.png")}, content_type="multipart/form-data")
    url = r.headers["Location"]
    other = app.test_client()
    login(other, "b@example.test")
    assert other.get(url).status_code == 404
    assert other.get(url + "/image").status_code == 404


def test_rejects_non_image_upload(app, conn):
    add_user(conn, "a@example.test")
    c = app.test_client()
    login(c, "a@example.test")
    r = post(c, "/cards/new", {"image": (io.BytesIO(b"%PDF-1.4 not an image"), "card.png")}, content_type="multipart/form-data")
    assert r.status_code == 400 and "JPEG・PNG・WebP" in r.get_data(as_text=True)


def test_data_survives_restart(app, conn, monkeypatch):
    a = add_user(conn, "a@example.test")
    card = add_card(conn, app, a, "Taro", "Acme")
    again = app_module.create_app({"DATA_DIR": app.config["DATA_DIR"], "TESTING": True})
    c = again.test_client()
    login(c, "a@example.test")
    assert c.get(f"/cards/{card}").status_code == 200


def test_validate_coerces_bad_model_output():
    out = extract.validate({"name": 123, "email": "not-an-email", "unclear_fields": ["email", "x"]})
    assert out["fields"]["name"] == "" and set(out["fields"]) == set(extract.KEYS)
    assert out["unclear"] == ["email"]
    assert any("氏名" in w for w in out["warnings"]) and any("メール" in w for w in out["warnings"])
    with pytest.raises(extract.ExtractionError):
        extract.validate(["not", "a", "dict"])


@pytest.mark.parametrize("key,provider", [("sk-ant-x", "anthropic"), ("AIzaX", "gemini"), ("sk-proj-x", "openai"), ("abc", "")])
def test_detect_provider_from_key_prefix(key, provider, monkeypatch):
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    assert extract.detect_provider(key) == provider


def test_admin_can_issue_generated_password(app, conn):
    c = app.test_client()
    login(c, ADMIN_EMAIL, ADMIN_PASSWORD)
    page = post(c, "/admin/users", {"email": "gen@example.test", "password": ""}).get_data(as_text=True)
    import re
    shown = re.search(r'monospace; font-size:1.2rem">([^<]+)<', page).group(1)
    assert len(shown) == 12
    assert "二度と表示できません" in page
    u = app.test_client()
    assert login(u, "gen@example.test", shown).status_code == 302
    assert shown not in c.get("/admin/users").get_data(as_text=True)  # not shown again
    # First login with an issued password: everything redirects to the change page until changed.
    assert u.get("/cards").headers["Location"].endswith("/account/password")
    assert post(u, "/account/password", {"current": shown, "new": "my-own-pass-1", "confirm": "my-own-pass-1"}).status_code == 302
    assert u.get("/cards").status_code == 200
    again = app.test_client()
    assert login(again, "gen@example.test", "my-own-pass-1").status_code == 302


def test_admin_reissue_forces_change_again(app, conn):
    uid = add_user(conn, "a@example.test")
    c = app.test_client()
    login(c, ADMIN_EMAIL, ADMIN_PASSWORD)
    page = post(c, f"/admin/users/{uid}/reset").get_data(as_text=True)
    import re
    shown = re.search(r'monospace; font-size:1.2rem">([^<]+)<', page).group(1)
    u = app.test_client()
    login(u, "a@example.test", shown)
    assert u.get("/cards").status_code == 302
