"""
database.py — QR-Secure Visitor Management System
Initializes and manages the SQLite database for visitor records.
All visitor PII (phone, purpose) is stored in encrypted form.
"""

import sqlite3
import os

# ── Configuration ──────────────────────────────────────────────
DB_NAME = "visitors.db"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.getenv("VISITOR_DB_PATH", os.path.join(BASE_DIR, DB_NAME))
if not os.path.isabs(DB_PATH):
    DB_PATH = os.path.join(BASE_DIR, DB_PATH)
DB_DIR = os.path.dirname(DB_PATH)
if DB_DIR:
    os.makedirs(DB_DIR, exist_ok=True)


def get_connection():
    """Return a new SQLite connection with WAL mode for better concurrency."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row          # Access columns by name
    conn.execute("PRAGMA journal_mode=WAL")  # Lightweight write-ahead logging
    return conn


def init_db():
    """
    Create the 'visitors' table if it does not already exist.

    Columns:
        id               — Auto-incrementing primary key.
        name             — Visitor's full name (plain text, for display only).
        encrypted_phone  — AES-256 encrypted phone number (base64 string).
        encrypted_purpose— AES-256 encrypted visit purpose (base64 string).
        timestamp        — ISO-8601 check-in time, defaults to current UTC.
        status           — Visit status: 'checked_in' or 'checked_out'.
    """
    conn = get_connection()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS visitors (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                name              TEXT    NOT NULL,
                encrypted_phone   TEXT    NOT NULL,
                encrypted_purpose TEXT    NOT NULL,
                timestamp         TEXT    NOT NULL DEFAULT (datetime('now', 'localtime')),
                status            TEXT    NOT NULL DEFAULT 'checked_in',
                verified_by       TEXT    DEFAULT NULL
            )
        """)
        conn.commit()

        # ── Migration: add verified_by to existing databases ──
        try:
            conn.execute("ALTER TABLE visitors ADD COLUMN verified_by TEXT DEFAULT NULL")
            conn.commit()
            print("[OK] Migrated: added verified_by column")
        except sqlite3.OperationalError:
            pass  # Column already exists — OK

        print(f"[OK] Database initialised: {DB_PATH}")
    except sqlite3.Error as e:
        print(f"[ERROR] Database error: {e}")
    finally:
        conn.close()


# ── CRUD Helpers ───────────────────────────────────────────────

def add_visitor(name: str, encrypted_phone: str, encrypted_purpose: str) -> int:
    """
    Insert a new visitor record and return the generated ID.

    Args:
        name             : Visitor's plain-text name.
        encrypted_phone  : Already-encrypted phone string.
        encrypted_purpose: Already-encrypted purpose string.

    Returns:
        The new row's integer ID.
    """
    conn = get_connection()
    try:
        cursor = conn.execute(
            "INSERT INTO visitors (name, encrypted_phone, encrypted_purpose) VALUES (?, ?, ?)",
            (name, encrypted_phone, encrypted_purpose),
        )
        conn.commit()
        visitor_id = cursor.lastrowid
        print(f"[OK] Visitor added -> ID {visitor_id}")
        return visitor_id
    except sqlite3.Error as e:
        print(f"[ERROR] Insert error: {e}")
        return -1
    finally:
        conn.close()


def get_visitor(visitor_id: int) -> dict | None:
    """
    Fetch a single visitor by ID.

    Returns:
        A dict with the visitor's columns, or None if not found.
    """
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM visitors WHERE id = ?", (visitor_id,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_all_visitors() -> list[dict]:
    """Return every visitor record as a list of dicts (most recent first)."""
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM visitors ORDER BY id DESC"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def update_status(visitor_id: int, new_status: str) -> bool:
    """
    Update a visitor's status (e.g. 'checked_out').

    Returns:
        True if the row was found and updated, False otherwise.
    """
    conn = get_connection()
    try:
        cursor = conn.execute(
            "UPDATE visitors SET status = ? WHERE id = ?",
            (new_status, visitor_id),
        )
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def set_verified_by(visitor_id: int, admin_username: str) -> bool:
    """
    Record which admin verified/scanned a visitor's QR pass.

    Args:
        visitor_id     : The visitor row to update.
        admin_username : The logged-in admin's username.

    Returns:
        True if the row was found and updated, False otherwise.
    """
    conn = get_connection()
    try:
        cursor = conn.execute(
            "UPDATE visitors SET verified_by = ? WHERE id = ?",
            (admin_username, visitor_id),
        )
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


# ── Standalone Execution ───────────────────────────────────────
if __name__ == "__main__":
    init_db()
