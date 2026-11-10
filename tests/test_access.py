"""Visibility rules from the assignment, checked directly on the SQL condition."""
import access
from conftest import add_card, add_grant, add_user


def visible_ids(conn, uid):
    user = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    return sorted(c["id"] for c in access.list_cards(conn, user))


def test_user_without_grants_sees_only_own_cards(app, conn):
    a, b = add_user(conn, "a@example.test"), add_user(conn, "b@example.test")
    mine = add_card(conn, app, a, "Taro", "Acme")
    add_card(conn, app, b, "Hanako", "Acme")
    assert visible_ids(conn, a) == [mine]


def test_admin_sees_everything(app, conn):
    a = add_user(conn, "a@example.test")
    ids = [add_card(conn, app, a, "Taro", "Acme"), add_card(conn, app, a, "Jiro", "")]
    assert visible_ids(conn, 1) == ids


def test_same_department_name_in_other_company_is_not_granted(app, conn):
    owner, viewer = add_user(conn, "o@example.test"), add_user(conn, "v@example.test")
    acme_sales = add_card(conn, app, owner, "Taro", "Acme", "Sales")
    add_card(conn, app, owner, "Jiro", "Globex", "Sales")
    add_card(conn, app, owner, "Saburo", "Acme", "Legal")
    add_grant(conn, viewer, "department", "Acme", "Sales")
    assert visible_ids(conn, viewer) == [acme_sales]


def test_person_grant_does_not_spread_to_namesake(app, conn):
    owner, viewer = add_user(conn, "o@example.test"), add_user(conn, "v@example.test")
    target = add_card(conn, app, owner, "Yamada Taro", "Acme")
    add_card(conn, app, owner, "Yamada Taro", "Globex")
    add_card(conn, app, owner, "Yamada Taro", "Acme")  # same name, same company, different card
    add_grant(conn, viewer, "person", card_id=target)
    assert visible_ids(conn, viewer) == [target]


def test_company_grant_matches_width_and_space_variants_only(app, conn):
    owner, viewer = add_user(conn, "o@example.test"), add_user(conn, "v@example.test")
    c1 = add_card(conn, app, owner, "A", "ＡＢＣ 商事")
    c2 = add_card(conn, app, owner, "B", "ABC  商事")
    add_card(conn, app, owner, "C", "ABC商事株式会社")
    add_card(conn, app, owner, "D", "")  # empty company never matches a company grant
    add_grant(conn, viewer, "company", "abc 商事")
    assert visible_ids(conn, viewer) == [c1, c2]


def test_revoking_one_grant_keeps_access_from_another(app, conn):
    owner, viewer = add_user(conn, "o@example.test"), add_user(conn, "v@example.test")
    card = add_card(conn, app, owner, "Taro", "Acme", "Sales")
    g_company = add_grant(conn, viewer, "company", "Acme")
    add_grant(conn, viewer, "person", card_id=card)
    conn.execute("DELETE FROM grants WHERE id = ?", (g_company,))
    conn.commit()
    assert visible_ids(conn, viewer) == [card]
    conn.execute("DELETE FROM grants WHERE user_id = ?", (viewer,))
    conn.commit()
    assert visible_ids(conn, viewer) == []


def test_owner_keeps_access_after_grant_removed(app, conn):
    owner = add_user(conn, "o@example.test")
    card = add_card(conn, app, owner, "Taro", "Acme")
    gid = add_grant(conn, owner, "company", "Acme")
    conn.execute("DELETE FROM grants WHERE id = ?", (gid,))
    conn.commit()
    assert visible_ids(conn, owner) == [card]


def test_unidentified_user_sees_nothing(app, conn):
    add_card(conn, app, add_user(conn, "o@example.test"), "Taro", "Acme")
    assert access.list_cards(conn, None) == []
    assert access.get_card(conn, None, 1) is None
