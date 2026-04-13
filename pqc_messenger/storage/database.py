"""
SQLite база данных для хранения контактов, сообщений и сессий.

При превышении лимитов сообщений старые
сообщения удаляются автоматически.
"""

from __future__ import annotations

import os
import sqlite3
import time
from dataclasses import dataclass

from pqc_messenger.common.constants import (
    DB_FILENAME,
    DB_MAX_MESSAGES_PER_CONTACT,
    DB_MAX_TOTAL_MESSAGES,
    DB_PRUNE_KEEP,
    DEFAULT_DATA_DIR,
)
from pqc_messenger.common.exceptions import DatabaseError
from pqc_messenger.common.logging import get_logger

logger = get_logger("storage.database")

SCHEMA = """
CREATE TABLE IF NOT EXISTS contacts (
    id TEXT PRIMARY KEY,
    display_name TEXT DEFAULT '',
    x25519_public_key BLOB NOT NULL,
    kyber_public_key BLOB NOT NULL,
    kyber_mode INTEGER NOT NULL DEFAULT 0,
    added_at REAL DEFAULT (strftime('%s', 'now'))
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    contact_id TEXT NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    direction TEXT NOT NULL CHECK(direction IN ('sent', 'received')),
    encrypted_content BLOB NOT NULL,
    timestamp REAL DEFAULT (strftime('%s', 'now'))
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    contact_id TEXT NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    ratchet_state BLOB NOT NULL,
    created_at REAL DEFAULT (strftime('%s', 'now')),
    last_activity REAL DEFAULT (strftime('%s', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_messages_contact   ON messages(contact_id);
CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp);
CREATE INDEX IF NOT EXISTS idx_sessions_contact   ON sessions(contact_id);
"""


@dataclass
class Contact:
    id: str
    display_name: str
    x25519_public_key: bytes
    kyber_public_key: bytes
    # 1 = реальный ML-KEM/Kyber-768, 0 = X25519-эмуляция
    kyber_mode: int
    added_at: float


@dataclass
class Message:
    id: int
    contact_id: str
    direction: str
    content: str
    timestamp: float


class Database:
    def __init__(self, data_dir: str | None = None) -> None:
        if data_dir is None:
            data_dir = os.path.join(os.path.expanduser("~"), DEFAULT_DATA_DIR)
        self._data_dir = data_dir
        self._db_path  = os.path.join(data_dir, DB_FILENAME)
        self._conn: sqlite3.Connection | None = None

    def initialize(self) -> None:
        os.makedirs(self._data_dir, exist_ok=True)
        try:
            self._conn = sqlite3.connect(self._db_path)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(SCHEMA)
            self._conn.commit()

            # Запускаем миграции после создания/открытия схемы
            from pqc_messenger.storage.migrations import run_migrations
            run_migrations(self._conn)

            logger.info("База данных инициализирована: %s", self._db_path)
        except sqlite3.Error as e:
            raise DatabaseError(f"Ошибка инициализации БД: {e}") from e

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def _ensure_connection(self) -> sqlite3.Connection:
        if self._conn is None:
            raise DatabaseError("База данных не инициализирована")
        return self._conn

    def add_contact(
        self,
        contact_id: str,
        x25519_pub: bytes,
        kyber_pub: bytes,
        display_name: str = "",
        kyber_mode: int = 0,
    ) -> Contact:
        conn = self._ensure_connection()
        try:
            conn.execute(
                "INSERT INTO contacts "
                "(id, display_name, x25519_public_key, kyber_public_key, kyber_mode) "
                "VALUES (?, ?, ?, ?, ?)",
                (contact_id, display_name, x25519_pub, kyber_pub, kyber_mode),
            )
            conn.commit()
            logger.info("Контакт добавлен: %s...", contact_id[:16])
            return Contact(
                id=contact_id,
                display_name=display_name,
                x25519_public_key=x25519_pub,
                kyber_public_key=kyber_pub,
                kyber_mode=kyber_mode,
                added_at=time.time(),
            )
        except sqlite3.IntegrityError:
            raise DatabaseError(f"Контакт {contact_id[:16]}... уже существует")
        except sqlite3.Error as e:
            raise DatabaseError(f"Ошибка добавления контакта: {e}") from e

    def get_contact(self, contact_id: str) -> Contact | None:
        conn = self._ensure_connection()
        row = conn.execute(
            "SELECT id, display_name, x25519_public_key, kyber_public_key, "
            "kyber_mode, added_at "
            "FROM contacts WHERE id = ?",
            (contact_id,),
        ).fetchone()
        return Contact(*row) if row else None

    def get_all_contacts(self) -> list[Contact]:
        conn = self._ensure_connection()
        rows = conn.execute(
            "SELECT id, display_name, x25519_public_key, kyber_public_key, "
            "kyber_mode, added_at "
            "FROM contacts ORDER BY added_at DESC"
        ).fetchall()
        return [Contact(*row) for row in rows]

    def delete_contact(self, contact_id: str) -> None:
        conn = self._ensure_connection()
        conn.execute("DELETE FROM contacts WHERE id = ?", (contact_id,))
        conn.commit()
        logger.info("Контакт удалён: %s...", contact_id[:16])

    def get_messages(self, contact_id: str, limit: int = 100) -> list[tuple]:
        conn = self._ensure_connection()
        rows = conn.execute(
            "SELECT id, direction, encrypted_content, timestamp "
            "FROM messages WHERE contact_id = ? "
            "ORDER BY timestamp DESC LIMIT ?",
            (contact_id, limit),
        ).fetchall()
        return rows

    def store_message(
        self,
        contact_id: str,
        direction: str,
        encrypted_content: bytes,
    ) -> None:
        conn = self._ensure_connection()
        conn.execute(
            "INSERT INTO messages (contact_id, direction, encrypted_content) "
            "VALUES (?, ?, ?)",
            (contact_id, direction, encrypted_content),
        )
        conn.commit()
        self._prune_messages(conn, contact_id)

    def _prune_messages(self, conn: sqlite3.Connection, contact_id: str) -> None:
        count = conn.execute(
            "SELECT COUNT(*) FROM messages WHERE contact_id = ?", (contact_id,)
        ).fetchone()[0]
        if count > DB_MAX_MESSAGES_PER_CONTACT:
            conn.execute(
                "DELETE FROM messages WHERE contact_id = ? AND id NOT IN ("
                "  SELECT id FROM messages WHERE contact_id = ? "
                "  ORDER BY timestamp DESC LIMIT ?"
                ")",
                (contact_id, contact_id, DB_PRUNE_KEEP),
            )
            conn.commit()

        total = conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
        if total > DB_MAX_TOTAL_MESSAGES:
            conn.execute(
                "DELETE FROM messages WHERE id NOT IN ("
                "  SELECT id FROM messages ORDER BY timestamp DESC LIMIT ?"
                ")",
                (DB_MAX_TOTAL_MESSAGES,),
            )
            conn.commit()

    def store_session(
        self,
        session_id: str,
        contact_id: str,
        ratchet_state: bytes,
    ) -> None:
        conn = self._ensure_connection()
        conn.execute(
            "INSERT OR REPLACE INTO sessions "
            "(id, contact_id, ratchet_state, last_activity) "
            "VALUES (?, ?, ?, strftime('%s', 'now'))",
            (session_id, contact_id, ratchet_state),
        )
        conn.commit()

    def get_all_sessions(self) -> list[tuple]:
        conn = self._ensure_connection()
        return conn.execute(
            "SELECT id, contact_id, ratchet_state, last_activity FROM sessions"
        ).fetchall()

    def delete_expired_sessions(self, ttl: float) -> int:
        conn = self._ensure_connection()
        cutoff = time.time() - ttl
        cur = conn.execute(
            "DELETE FROM sessions WHERE last_activity < ?", (cutoff,)
        )
        conn.commit()
        return cur.rowcount

    def wipe_all(self) -> None:
        conn = self._ensure_connection()
        conn.execute("DELETE FROM messages")
        conn.execute("DELETE FROM sessions")
        conn.execute("DELETE FROM contacts")
        conn.commit()
        logger.warning("Все данные удалены из БД (WIPE)")
