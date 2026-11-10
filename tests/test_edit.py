"""Editing a registered card, and the per-card viewer panel for admins."""
from conftest import ADMIN_EMAIL, ADMIN_PASSWORD, add_card, add_grant, add_user, login, post


def test_owner_can_edit_and_keys_follow(app, conn):
    a = add_user(conn, "a@example.test")
    card = add_card(conn, app, a, "Taro", "Acme")
    c = app.test_client()
    login(c, "a@example.test")
    r = post(c, f"/cards/{card}/edit", {"name": "Taro", "company": "Globex", "email": "taro@example.test"})
    assert r.status_code == 302
    row = conn.execute("SELECT company, company_key, email FROM cards WHERE id = ?", (card,)).fetchone()
    assert tuple(row) == ("Globex", "globex", "taro@example.test")
    assert post(c, f"/cards/{card}/edit", {"name": ""}).status_code == 400  # name stays required


def test_viewer_by_grant_cannot_edit_and_stranger_gets_404(app, conn):
    owner, viewer, stranger = (add_user(conn, e) for e in ("o@example.test", "v@example.test", "s@example.test"))
    card = add_card(conn, app, owner, "Taro", "Acme")
    add_grant(conn, viewer, "company", "Acme")
    v = app.test_client(); login(v, "v@example.test")
    assert v.get(f"/cards/{card}").status_code == 200
    assert post(v, f"/cards/{card}/edit", {"name": "X"}).status_code == 403
    s = app.test_client(); login(s, "s@example.test")
    assert s.get(f"/cards/{card}/edit").status_code == 404


def test_admin_sees_who_can_view_and_grants_from_card(app, conn):
    owner, other = add_user(conn, "o@example.test"), add_user(conn, "x@example.test")
    card = add_card(conn, app, owner, "Taro", "Acme")
    c = app.test_client(); login(c, ADMIN_EMAIL, ADMIN_PASSWORD)
    page = c.get(f"/cards/{card}").get_data(as_text=True)
    assert "登録者" in page and "x@example.test" in page
    post(c, f"/admin/cards/{card}/grant", {"user_id": str(other)})
    x = app.test_client(); login(x, "x@example.test")
    assert x.get(f"/cards/{card}").status_code == 200


def test_help_page_is_readable_without_login(app):
    r = app.test_client().get("/help")
    assert r.status_code == 200 and "使い方" in r.get_data(as_text=True)
