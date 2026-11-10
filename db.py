"""SQLite storage: schema, connection, and text normalization for matching."""
import re
import sqlite3
import unicodedata

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'user')),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS cards (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL CHECK (name <> ''),
    company TEXT NOT NULL DEFAULT '',
    department TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL DEFAULT '',
    email TEXT NOT NULL DEFAULT '',
    phone TEXT NOT NULL DEFAULT '',
    address TEXT NOT NULL DEFAULT '',
    website TEXT NOT NULL DEFAULT '',
    name_key TEXT NOT NULL,
    company_key TEXT NOT NULL,
    department_key TEXT NOT NULL,
    image_name TEXT NOT NULL,
    registered_by INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS grants (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    kind TEXT NOT NULL CHECK (kind IN ('company', 'department', 'person')),
    company_key TEXT NOT NULL DEFAULT '',
    department_key TEXT NOT NULL DEFAULT '',
    card_id INTEGER REFERENCES cards(id),
    created_by INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (user_id, kind, company_key, department_key, card_id)
);
CREATE TABLE IF NOT EXISTS pending (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    image_name TEXT NOT NULL,
    result_json TEXT,
    error TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    cols = [r["name"] for r in conn.execute("PRAGMA table_info(users)")]
    if "must_change_password" not in cols:  # added after the first release; keep existing data
        conn.execute("ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0")
    conn.commit()


def normalize(text: str) -> str:
    """Key used to match company/department/name: width, spaces and case only."""
    text = unicodedata.normalize("NFKC", text or "")
    return re.sub(r"\s+", " ", text).strip().casefold()
