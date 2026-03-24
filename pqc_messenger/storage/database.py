"""
SQLite база данных для хранения контактов, сообщений и сессий.

Пункт 3: автоматическое ограничение размера — при превышении
DB_MAX_MESSAGES_PER_CONTACT или DB_MAX_TOTAL_MESSAGES старые
сообщения удаляются, оставляя DB_PRUNE_KEEP последних.
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

    # ── Контакты ──────────────────────────────────────────────────────────────

    def add_contact(
        self,
        contact_id: str,
        x25519_pub: bytes,
        kyber_pub: bytes,
        display_name: str = "",
    ) -> Contact:
        conn = self._ensure_connection()
        try:
            conn.execute(
                "INSERT INTO contacts (id, display_name, x25519_public_key, kyber_public_key) "
                "VALUES (?, ?, ?, ?)",
                (contact_id, display_name, x25519_pub, kyber_pub),
            )
            conn.commit()
            logger.info("Контакт добавлен: %s...", contact_id[:16])
            return Contact(
                id=contact_id,
                display_name=display_name,
                x25519_public_key=x25519_pub,
                kyber_public_key=kyber_pub,
                added_at=time.time(),
            )
        except sqlite3.IntegrityError:
            raise DatabaseError(f"Контакт {contact_id[:16]}... уже существует")
        except sqlite3.Error as e:
            raise DatabaseError(f"Ошибка добавления контакта: {e}") from e

    def get_contact(self, contact_id: str) -> Contact | None:
        conn = self._ensure_connection()
        row = conn.execute(
            "SELECT id, display_name, x25519_public_key, kyber_public_key, added_at "
            "FROM contacts WHERE id = ?",
            (contact_id,),
        ).fetchone()
        return Contact(*row) if row else None

    def get_all_contacts(self) -> list[Contact]:
        conn = self._ensure_connection()
        rows = conn.execute(
            "SELECT id, display_name, x25519_public_key, kyber_public_key, added_at "
            "FROM contacts ORDER BY added_at DESC"
        ).fetchall()
        return [Contact(*row) for row in rows]

    def delete_contact(self, contact_id: str) -> None:
        """Пункт 7: удалить контакт и все связанные данные."""
        conn = self._ensure_connection()
        conn.execute("DELETE FROM contacts WHERE id = ?", (contact_id,))
        conn.commit()
        logger.info("Контакт удалён: %s...", contact_id[:16])

    # ── Сообщения ─────────────────────────────────────────────────────────────

    def store_message(
        self,
        contact_id: str,
        direction: str,
        encrypted_content: bytes,
    ) -> int:
        conn = self._ensure_connection()
        try:
            cursor = conn.execute(
                "INSERT INTO messages (contact_id, direction, encrypted_content) "
                "VALUES (?, ?, ?)",
                (contact_id, direction, encrypted_content),
            )
            conn.commit()
            msg_id = cursor.lastrowid or 0

            # Пункт 3: проверяем лимиты и при необходимости чистим
            self._prune_messages_if_needed(contact_id)

            return msg_id
        except sqlite3.Error as e:
            raise DatabaseError(f"Ошибка сохранения сообщения: {e}") from e

    def _prune_messages_if_needed(self, contact_id: str) -> None:
        """
        Пункт 3: Удалить старые сообщения если превышен лимит.

        Проверяем два лимита:
        - DB_MAX_MESSAGES_PER_CONTACT — на конкретный контакт
        - DB_MAX_TOTAL_MESSAGES       — суммарно по всей БД
        """
        conn = self._ensure_connection()

        # Лимит на контакт
        (count_contact,) = conn.execute(
            "SELECT COUNT(*) FROM messages WHERE contact_id = ?",
            (contact_id,),
        ).fetchone()

        if count_contact > DB_MAX_MESSAGES_PER_CONTACT:
            to_delete = count_contact - DB_PRUNE_KEEP
            conn.execute(
                "DELETE FROM messages WHERE contact_id = ? AND id IN ("
                "  SELECT id FROM messages WHERE contact_id = ? "
                "  ORDER BY timestamp ASC LIMIT ?"
                ")",
                (contact_id, contact_id, to_delete),
            )
            conn.commit()
            logger.info(
                "Очистка БД: удалено %d старых сообщений для %s...",
                to_delete, contact_id[:16],
            )

        # Суммарный лимит
        (count_total,) = conn.execute(
            "SELECT COUNT(*) FROM messages"
        ).fetchone()

        if count_total > DB_MAX_TOTAL_MESSAGES:
            to_delete = count_total - DB_PRUNE_KEEP
            conn.execute(
                "DELETE FROM messages WHERE id IN ("
                "  SELECT id FROM messages ORDER BY timestamp ASC LIMIT ?"
                ")",
                (to_delete,),
            )
            conn.commit()
            logger.info("Очистка БД: удалено %d старых сообщений (суммарный лимит)", to_delete)

    def get_messages(
        self,
        contact_id: str,
        limit: int = 100,
        offset: int = 0,
    ) -> list[tuple[int, str, bytes, float]]:
        conn = self._ensure_connection()
        rows = conn.execute(
            "SELECT id, direction, encrypted_content, timestamp "
            "FROM messages WHERE contact_id = ? "
            "ORDER BY timestamp ASC LIMIT ? OFFSET ?",
            (contact_id, limit, offset),
        ).fetchall()
        return rows

    def count_messages(self, contact_id: str | None = None) -> int:
        """Получить количество сообщений (для контакта или всего)."""
        conn = self._ensure_connection()
        if contact_id:
            (n,) = conn.execute(
                "SELECT COUNT(*) FROM messages WHERE contact_id = ?", (contact_id,)
            ).fetchone()
        else:
            (n,) = conn.execute("SELECT COUNT(*) FROM messages").fetchone()
        return n

    def delete_messages(self, contact_id: str) -> int:
        conn = self._ensure_connection()
        cursor = conn.execute(
            "DELETE FROM messages WHERE contact_id = ?", (contact_id,)
        )
        conn.commit()
        return cursor.rowcount

    # ── Сессии ────────────────────────────────────────────────────────────────

    def store_session(
        self,
        session_id: str,
        contact_id: str,
        ratchet_state: bytes,
    ) -> None:
        conn = self._ensure_connection()
        conn.execute(
            "INSERT OR REPLACE INTO sessions (id, contact_id, ratchet_state, last_activity) "
            "VALUES (?, ?, ?, ?)",
            (session_id, contact_id, ratchet_state, time.time()),
        )
        conn.commit()

    def get_session(self, contact_id: str) -> tuple[str, bytes] | None:
        conn = self._ensure_connection()
        row = conn.execute(
            "SELECT id, ratchet_state FROM sessions WHERE contact_id = ? "
            "ORDER BY last_activity DESC LIMIT 1",
            (contact_id,),
        ).fetchone()
        return row

    def get_all_sessions(self) -> list[tuple[str, str, bytes, float]]:
        """Получить все сессии: (session_id, contact_id, ratchet_state, last_activity)."""
        conn = self._ensure_connection()
        rows = conn.execute(
            "SELECT id, contact_id, ratchet_state, last_activity FROM sessions"
        ).fetchall()
        return rows

    def delete_session(self, session_id: str) -> None:
        conn = self._ensure_connection()
        conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
        conn.commit()

    def delete_expired_sessions(self, ttl: float) -> int:
        """
        Пункт 4: удалить сессии старше ttl секунд.
        Возвращает количество удалённых записей.
        """
        conn  = self._ensure_connection()
        cutoff = time.time() - ttl
        cursor = conn.execute(
            "DELETE FROM sessions WHERE last_activity < ?", (cutoff,)
        )
        conn.commit()
        n = cursor.rowcount
        if n:
            logger.info("Удалено %d истёкших сессий", n)
        return n

    # ── Очистка ───────────────────────────────────────────────────────────────

    def wipe_all(self) -> None:
        conn = self._ensure_connection()
        conn.execute("DELETE FROM sessions")
        conn.execute("DELETE FROM messages")
        conn.execute("DELETE FROM contacts")
        conn.execute("VACUUM")
        conn.commit()
        logger.warning("Все данные БД удалены (WIPE)")
