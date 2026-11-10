import io

import extract
from conftest import add_user, login, png_bytes, post

FAKE = {
    "name": "山田 太郎", "company": "株式会社テスト", "department": "営業部", "title": "課長",
    "email": "taro@example.test", "phone": "0000", "address": "", "website": "",
    "unclear_fields": [],
}


def bulk_upload(client):
    files = [(io.BytesIO(png_bytes(fmt)), f"card{i}.{fmt.lower()}") for i, fmt in enumerate(["PNG", "JPEG", "GIF"])]
    files.append((io.BytesIO(b"not an image"), "notes.txt"))
    return post(client, "/cards/bulk", {"images": files}, content_type="multipart/form-data")


def test_bulk_creates_pending_rows_and_registers_nothing(app, conn, monkeypatch):
    a = add_user(conn, "a@example.test")
    monkeypatch.setattr(extract, "call_llm", lambda b64: (dict(FAKE), {"input_tokens": 1, "output_tokens": 1, "model": "fake"}))
    c = app.test_client()
    login(c, "a@example.test")
    r = bulk_upload(c)
    assert r.status_code == 200
    page = r.get_data(as_text=True)
    assert page.count("読み取り成功（氏名: 山田 太郎）") == 3
    assert "notes.txt" in page and "対応していない形式" in page
    assert page.count("確認して登録") == 3
    assert conn.execute("SELECT COUNT(*) FROM pending WHERE user_id = ?", (a,)).fetchone()[0] == 3
    assert conn.execute("SELECT COUNT(*) FROM cards").fetchone()[0] == 0
    listing = c.get("/cards/pending").get_data(as_text=True)
    assert listing.count("確認して登録") == 3


def test_other_user_cannot_see_bulk_pending(app, conn, monkeypatch):
    add_user(conn, "a@example.test"); add_user(conn, "b@example.test")
    monkeypatch.setattr(extract, "call_llm", lambda b64: (dict(FAKE), {"input_tokens": 1, "output_tokens": 1, "model": "fake"}))
    c = app.test_client()
    login(c, "a@example.test")
    bulk_upload(c)
    tokens = [r["token"] for r in conn.execute("SELECT token FROM pending")]
    other = app.test_client()
    login(other, "b@example.test")
    listing = other.get("/cards/pending").get_data(as_text=True)
    assert "確認して登録" not in listing and "0件" in listing
    for t in tokens:
        assert other.get(f"/cards/pending/{t}").status_code == 404


def test_bulk_without_key_saves_items_as_failed(app, conn):
    add_user(conn, "a@example.test")  # no API key -> ExtractionError, but images are kept for manual entry
    c = app.test_client()
    login(c, "a@example.test")
    page = bulk_upload(c).get_data(as_text=True)
    assert page.count("失敗（") == 3 and page.count("確認して登録") == 3
    assert conn.execute("SELECT COUNT(*) FROM pending").fetchone()[0] == 3
