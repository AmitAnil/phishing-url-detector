"""
database.py
-----------
SQLite persistence layer for scan history.
"""

import json
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "scan_history.db"


def init_db() -> None:
    """Creates the scans table if it doesn't already exist."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            domain TEXT,
            https INTEGER,
            risk_score INTEGER,
            risk_level TEXT,
            verdict TEXT,
            timestamp TEXT,
            raw_json TEXT
        )
        """
    )
    conn.commit()
    conn.close()


def save_scan(scan_result: dict) -> None:
    """Persists a single scan result."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO scans (url, domain, https, risk_score, risk_level, verdict, timestamp, raw_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_result.get("url"),
            scan_result.get("registered_domain"),
            int(scan_result.get("https", False)),
            scan_result.get("risk_score"),
            scan_result.get("risk_level"),
            scan_result.get("verdict"),
            scan_result.get("timestamp"),
            json.dumps(scan_result, default=str),
        ),
    )
    conn.commit()
    conn.close()


def get_history(limit: int = 50) -> list:
    """Returns the most recent scans, newest first."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def clear_history() -> None:
    """Deletes all rows from the scans table."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DELETE FROM scans")
    conn.commit()
    conn.close()


def delete_scan(scan_id: int) -> None:
    """Deletes a single scan by id."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    conn.commit()
    conn.close()
