"""
database/db.py
Database initialisation and connection helpers for the
Enterprise Ransomware Risk Assessment System.
"""

import sqlite3
import os

# Resolve paths relative to this file so the app can be run from any CWD.
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_SCHEMA_PATH = os.path.join(_BASE_DIR, "schema.sql")
_DB_PATH = os.path.join(_BASE_DIR, "ransomware_risk.db")


def get_db_path() -> str:
    """Return the absolute path to the SQLite database file."""
    return _DB_PATH


def get_connection() -> sqlite3.Connection:
    """Open and return a new SQLite connection with row-factory set."""
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db() -> None:
    """Create tables (if they do not exist) using schema.sql."""
    with open(_SCHEMA_PATH, "r", encoding="utf-8") as f:
        sql = f.read()

    conn = get_connection()
    try:
        conn.executescript(sql)
        conn.commit()
    finally:
        conn.close()


def log_action(action: str, risk_id: str = None, details: str = None) -> None:
    """Insert a row into the audit_log table."""
    conn = get_connection()
    try:
        conn.execute(
            "INSERT INTO audit_log (action, risk_id, details) VALUES (?, ?, ?)",
            (action, risk_id, details),
        )
        conn.commit()
    finally:
        conn.close()
