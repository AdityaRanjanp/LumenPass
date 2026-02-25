"""
database.py - QR-Secure Visitor Management System
Initializes and manages SQLite tables for visitor records and admin users.
"""

import os
import sqlite3

# Configuration
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
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    """Create required tables and run safe migrations."""
    conn = get_connection()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS visitors (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                name              TEXT    NOT NULL,
                encrypted_phone   TEXT    NOT NULL,
                encrypted_purpose TEXT    NOT NULL,
                timestamp         TEXT    NOT NULL DEFAULT (datetime('now', 'localtime')),
                status            TEXT    NOT NULL DEFAULT 'checked_in',
                verified_by       TEXT    DEFAULT NULL
            )
            """
        )
        conn.commit()

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id                   INTEGER PRIMARY KEY AUTOINCREMENT,
                username             TEXT    NOT NULL UNIQUE,
                password_hash        TEXT    NOT NULL,
                must_change_password INTEGER NOT NULL DEFAULT 1,
                created_at           TEXT    NOT NULL DEFAULT (datetime('now', 'localtime')),
                updated_at           TEXT    NOT NULL DEFAULT (datetime('now', 'localtime'))
            )
            """
        )
        conn.commit()

        # Migration for older visitors table
        try:
            conn.execute("ALTER TABLE visitors ADD COLUMN verified_by TEXT DEFAULT NULL")
            conn.commit()
            print("[OK] Migrated: added verified_by column")
        except sqlite3.OperationalError:
            pass

        # Migration for older users table
        try:
            conn.execute(
                "ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 1"
            )
            conn.commit()
            print("[OK] Migrated: added must_change_password column")
        except sqlite3.OperationalError:
            pass

        print(f"[OK] Database initialised: {DB_PATH}")
    except sqlite3.Error as e:
        print(f"[ERROR] Database error: {e}")
    finally:
        conn.close()


def add_visitor(name: str, encrypted_phone: str, encrypted_purpose: str) -> int:
    """Insert a new visitor record and return generated row id."""
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
    """Fetch one visitor by id."""
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM visitors WHERE id = ?",
            (visitor_id,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_all_visitors() -> list[dict]:
    """Return all visitors (newest first)."""
    conn = get_connection()
    try:
        rows = conn.execute("SELECT * FROM visitors ORDER BY id DESC").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def update_status(visitor_id: int, new_status: str) -> bool:
    """Update visitor status and return True when at least one row changed."""
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
    """Record which admin verified/scanned a visitor QR pass."""
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


def get_user(username: str) -> dict | None:
    """Fetch one user by username."""
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def ensure_default_admin(username: str, password_hash: str) -> None:
    """
    Create a default admin user only when it does not already exist.
    Existing user records are never overwritten.
    """
    conn = get_connection()
    try:
        cursor = conn.execute(
            "INSERT OR IGNORE INTO users (username, password_hash, must_change_password) VALUES (?, ?, 1)",
            (username, password_hash),
        )
        conn.commit()
        if cursor.rowcount > 0:
            print(f"[OK] Default admin user created: {username}")
    finally:
        conn.close()


def update_user_password(username: str, new_password_hash: str) -> bool:
    """Update a user's password hash and clear must_change_password flag."""
    conn = get_connection()
    try:
        cursor = conn.execute(
            """
            UPDATE users
               SET password_hash = ?,
                   must_change_password = 0,
                   updated_at = datetime('now', 'localtime')
             WHERE username = ?
            """,
            (new_password_hash, username),
        )
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


if __name__ == "__main__":
    init_db()
