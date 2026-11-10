"""Who may see which card. Every card read in the app goes through this module."""
import sqlite3
from typing import List, Optional, Tuple

from db import normalize


def visibility_clause(user: Optional[sqlite3.Row]) -> Tuple[str, list]:
    """SQL condition on alias `c` (cards) that keeps only cards `user` may view."""
    if user is None:
        return "0", []
    if user["role"] == "admin":
        return "1", []
    if user["role"] != "user":
        return "0", []
    uid = user["id"]
    return (
        """(c.registered_by = ? OR EXISTS (
            SELECT 1 FROM grants g WHERE g.user_id = ? AND (
                (g.kind = 'company' AND c.company_key <> ''
                    AND g.company_key = c.company_key)
             OR (g.kind = 'department' AND c.company_key <> '' AND c.department_key <> ''
                    AND g.company_key = c.company_key AND g.department_key = c.department_key)
             OR (g.kind = 'person' AND g.card_id = c.id))))""",
        [uid, uid],
    )


def list_cards(conn: sqlite3.Connection, user, query: str = "") -> List[sqlite3.Row]:
    cond, params = visibility_clause(user)
    sql = f"SELECT c.*, u.email AS registered_by_email FROM cards c JOIN users u ON u.id = c.registered_by WHERE {cond}"
    key = normalize(query)
    if key:
        like = "%" + key.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        sql += " AND (c.name_key LIKE ? ESCAPE '\\' OR c.company_key LIKE ? ESCAPE '\\')"
        params = params + [like, like]
    sql += " ORDER BY c.created_at DESC, c.id DESC"
    return conn.execute(sql, params).fetchall()


def get_card(conn: sqlite3.Connection, user, card_id: int) -> Optional[sqlite3.Row]:
    cond, params = visibility_clause(user)
    return conn.execute(
        f"SELECT c.*, u.email AS registered_by_email FROM cards c JOIN users u ON u.id = c.registered_by"
        f" WHERE c.id = ? AND {cond}",
        [card_id] + params,
    ).fetchone()
