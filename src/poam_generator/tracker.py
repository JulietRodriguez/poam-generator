"""SQLite-backed remediation tracker for POAM findings."""

from __future__ import annotations

import sqlite3
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

DB_PATH = Path("poam_tracker.db")


def _connect(db_path: Path = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db(db_path: Path = DB_PATH) -> None:
    """Create tables if they don't exist."""
    with _connect(db_path) as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS findings (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                item_id          TEXT    NOT NULL UNIQUE,
                weakness_name    TEXT    NOT NULL,
                security_control TEXT    NOT NULL,
                severity         TEXT    NOT NULL,
                status           TEXT    NOT NULL,
                detection_date   TEXT    NOT NULL,
                scheduled_completion TEXT NOT NULL,
                office_org       TEXT    NOT NULL,
                point_of_contact TEXT    NOT NULL,
                last_updated     TEXT    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS status_history (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id  INTEGER NOT NULL REFERENCES findings(id),
                old_status  TEXT    NOT NULL,
                new_status  TEXT    NOT NULL,
                changed_at  TEXT    NOT NULL,
                notes       TEXT    NOT NULL DEFAULT ''
            );
        """)


def save_findings(items: list[dict], db_path: Path = DB_PATH) -> list[dict]:
    """
    Upsert findings into the database.
    Returns a list of change records: {item_id, field, old, new}.
    """
    init_db(db_path)
    now = datetime.utcnow().isoformat(timespec="seconds")
    changes: list[dict] = []

    with _connect(db_path) as conn:
        for item in items:
            item_id = item["item_id"]
            existing = conn.execute(
                "SELECT * FROM findings WHERE item_id = ?", (item_id,)
            ).fetchone()

            if existing is None:
                conn.execute(
                    """INSERT INTO findings
                       (item_id, weakness_name, security_control, severity, status,
                        detection_date, scheduled_completion, office_org, point_of_contact, last_updated)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        item_id,
                        item["weakness_name"],
                        item["security_control"],
                        item["severity"],
                        item["status"],
                        item["detection_date"],
                        item["scheduled_completion"],
                        item["office_org"],
                        item["point_of_contact"],
                        now,
                    ),
                )
                changes.append({"item_id": item_id, "type": "new", "value": item["weakness_name"]})
            else:
                # Check for status change
                if existing["status"] != item["status"]:
                    finding_id = existing["id"]
                    conn.execute(
                        """INSERT INTO status_history (finding_id, old_status, new_status, changed_at, notes)
                           VALUES (?, ?, ?, ?, ?)""",
                        (finding_id, existing["status"], item["status"], now, "Auto-detected on sync"),
                    )
                    changes.append({
                        "item_id": item_id,
                        "type": "status_change",
                        "old": existing["status"],
                        "new": item["status"],
                    })

                # Update record
                conn.execute(
                    """UPDATE findings SET
                       weakness_name=?, security_control=?, severity=?, status=?,
                       detection_date=?, scheduled_completion=?, office_org=?,
                       point_of_contact=?, last_updated=?
                       WHERE item_id=?""",
                    (
                        item["weakness_name"],
                        item["security_control"],
                        item["severity"],
                        item["status"],
                        item["detection_date"],
                        item["scheduled_completion"],
                        item["office_org"],
                        item["point_of_contact"],
                        now,
                        item_id,
                    ),
                )

    return changes


def update_status(
    item_id: str,
    new_status: str,
    notes: str = "",
    db_path: Path = DB_PATH,
) -> bool:
    """Update a finding's status and record in history. Returns True if found."""
    init_db(db_path)
    now = datetime.utcnow().isoformat(timespec="seconds")

    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT id, status FROM findings WHERE item_id = ?", (item_id,)
        ).fetchone()

        if row is None:
            return False

        old_status = row["status"]
        if old_status == new_status:
            return True

        conn.execute(
            """INSERT INTO status_history (finding_id, old_status, new_status, changed_at, notes)
               VALUES (?, ?, ?, ?, ?)""",
            (row["id"], old_status, new_status, now, notes),
        )
        conn.execute(
            "UPDATE findings SET status=?, last_updated=? WHERE item_id=?",
            (new_status, now, item_id),
        )

    return True


def get_all_findings(db_path: Path = DB_PATH) -> list[dict]:
    """Return all findings as dicts."""
    init_db(db_path)
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM findings ORDER BY severity, scheduled_completion"
        ).fetchall()
    return [dict(r) for r in rows]


def get_overdue_findings(db_path: Path = DB_PATH) -> list[dict]:
    """Return findings past their scheduled completion date that are not closed."""
    init_db(db_path)
    today = date.today().isoformat()
    with _connect(db_path) as conn:
        rows = conn.execute(
            """SELECT * FROM findings
               WHERE scheduled_completion < ?
               AND status NOT IN ('Closed', 'Risk Accepted')
               ORDER BY scheduled_completion""",
            (today,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_due_this_week(db_path: Path = DB_PATH) -> list[dict]:
    """Return open findings due within the next 7 days."""
    init_db(db_path)
    today = date.today()
    week_out = (today + timedelta(days=7)).isoformat()
    today_str = today.isoformat()
    with _connect(db_path) as conn:
        rows = conn.execute(
            """SELECT * FROM findings
               WHERE scheduled_completion BETWEEN ? AND ?
               AND status NOT IN ('Closed', 'Risk Accepted')
               ORDER BY scheduled_completion""",
            (today_str, week_out),
        ).fetchall()
    return [dict(r) for r in rows]


def get_status_history(item_id: str, db_path: Path = DB_PATH) -> list[dict]:
    """Return full status history for a finding."""
    init_db(db_path)
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT id FROM findings WHERE item_id = ?", (item_id,)
        ).fetchone()
        if row is None:
            return []
        rows = conn.execute(
            """SELECT old_status, new_status, changed_at, notes
               FROM status_history WHERE finding_id = ?
               ORDER BY changed_at DESC""",
            (row["id"],),
        ).fetchall()
    return [dict(r) for r in rows]


def days_remaining(scheduled_completion: str) -> int:
    """Days until due date (negative = overdue)."""
    try:
        due = date.fromisoformat(scheduled_completion)
        return (due - date.today()).days
    except ValueError:
        return 0
