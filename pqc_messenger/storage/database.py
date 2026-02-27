"""
SQLite база данных для хранения контактов, сообщений и сессий.

Все текстовые данные сообщений хранятся в зашифрованном виде (AES-256-GCM).
Ключи хранятся отдельно в KeyStore.

Используется aiosqlite для асинхронного доступа.
"""

from __future__ import annotations

import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from pqc_messenger.common.constants import DB_FILENAME, DEFAULT_DATA_DIR
from pqc_messenger.common.exceptions import DatabaseError
from pqc_messenger.common.logging import get_logger

logger = get_logger("storage.database")

# SQL-схема базы данных
SCHEMA = """
-- Контакты
CREATE TABLE IF NOT EXISTS contacts (
    id TEXT PRIMARY KEY,                              -- SHA-256(x25519_pub || kyber_pub)
    display_name TEXT DEFAULT '',
    x25519_public_key BLOB NOT NULL,
    kyber_public_key BLOB NOT NULL,
    added_at REAL DEFAULT (strftime('%s', 'now'))
);

-- Сообщения (контент зашифрован на мастер-ключе)
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    contact_id TEXT NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    direction TEXT NOT NULL CHECK(direction IN ('sent', 'received')),
    encrypted_content BLOB NOT NULL,                  -- AES-256-GCM encrypted text
    timestamp REAL DEFAULT (strftime('%s', 'now'))
);

-- Сессии (ratchet state зашифрован)
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    contact_id TEXT NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    ratchet_state BLOB NOT NULL,                      -- Зашифрованное состояние ratchet
    created_at REAL DEFAULT (strftime('%s', 'now')),
    last_activity REAL DEFAULT (strftime('%s', 'now'))
);

-- Индексы для производительности
CREATE INDEX IF NOT EXISTS idx_messages_contact ON messages(contact_id);
CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp);
CREATE INDEX IF NOT EXISTS idx_sessions_contact ON sessions(contact_id);
"""


@dataclass
class Contact:
    """Модель контакта."""
    id: str
    display_name: str
    x25519_public_key: bytes
    kyber_public_key: bytes
    added_at: float


@dataclass
class Message:
    """Модель сообщения (расшифрованного)."""
    id: int
    contact_id: str
    direction: str  # 'sent' | 'received'
    content: str    # Расшифрованный текст
    timestamp: float


class Database:
    """
    Менеджер SQLite базы данных.

    Обеспечивает CRUD-операции для контактов, сообщений и сессий.
    Все данные сообщений шифруются перед записью.
    """

    def __init__(self, data_dir: str | None = None) -> None:
        if data_dir is None:
            data_dir = os.path.join(os.path.expanduser("~"), DEFAULT_DATA_DIR)
        self._data_dir = data_dir
        self._db_path = os.path.join(data_dir, DB_FILENAME)
        self._conn: sqlite3.Connection | None = None

    def initialize(self) -> None:
        """Инициализировать базу данных и создать таблицы."""
        os.makedirs(self._data_dir, exist_ok=True)

        try:
            self._conn = sqlite3.connect(self._db_path)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(SCHEMA)
            self._conn.commit()
            logger.info(f"База данных инициализирована: {self._db_path}")
        except sqlite3.Error as e:
            raise DatabaseError(f"Ошибка инициализации БД: {e}") from e

    def close(self) -> None:
        """Закрыть подключение к базе данных."""
        if self._conn:
            self._conn.close()
            self._conn = None

    def _ensure_connection(self) -> sqlite3.Connection:
        """Убедиться, что подключение активно."""
        if self._conn is None:
            raise DatabaseError("База данных не инициализирована")
        return self._conn

    # ── Контакты ──────────────────────────────────────────

    def add_contact(
        self,
        contact_id: str,
        x25519_pub: bytes,
        kyber_pub: bytes,
        display_name: str = "",
    ) -> Contact:
        """Добавить новый контакт."""
        conn = self._ensure_connection()
        try:
            conn.execute(
                "INSERT INTO contacts (id, display_name, x25519_public_key, kyber_public_key) "
                "VALUES (?, ?, ?, ?)",
                (contact_id, display_name, x25519_pub, kyber_pub),
            )
            conn.commit()
            logger.info(f"Контакт добавлен: {contact_id[:16]}...")
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
        """Получить контакт по ID."""
        conn = self._ensure_connection()
        row = conn.execute(
            "SELECT id, display_name, x25519_public_key, kyber_public_key, added_at "
            "FROM contacts WHERE id = ?",
            (contact_id,),
        ).fetchone()

        if row is None:
            return None
        return Contact(*row)

    def get_all_contacts(self) -> list[Contact]:
        """Получить все контакты."""
        conn = self._ensure_connection()
        rows = conn.execute(
            "SELECT id, display_name, x25519_public_key, kyber_public_key, added_at "
            "FROM contacts ORDER BY added_at DESC"
        ).fetchall()
        return [Contact(*row) for row in rows]

    def delete_contact(self, contact_id: str) -> None:
        """Удалить контакт и все связанные данные."""
        conn = self._ensure_connection()
        conn.execute("DELETE FROM contacts WHERE id = ?", (contact_id,))
        conn.commit()
        logger.info(f"Контакт удалён: {contact_id[:16]}...")

    # ── Сообщения ──────────────────────────────────────

    def store_message(
        self,
        contact_id: str,
        direction: str,
        encrypted_content: bytes,
    ) -> int:
        """
        Сохранить зашифрованное сообщение.

        Returns:
            ID сохранённого сообщения.
        """
        conn = self._ensure_connection()
        try:
            cursor = conn.execute(
                "INSERT INTO messages (contact_id, direction, encrypted_content) "
                "VALUES (?, ?, ?)",
                (contact_id, direction, encrypted_content),
            )
            conn.commit()
            return cursor.lastrowid or 0
        except sqlite3.Error as e:
            raise DatabaseError(f"Ошибка сохранения сообщения: {e}") from e

    def get_messages(
        self,
        contact_id: str,
        limit: int = 100,
        offset: int = 0,
    ) -> list[tuple[int, str, bytes, float]]:
        """
        Получить зашифрованные сообщения для контакта.

        Returns:
            Список кортежей (id, direction, encrypted_content, timestamp).
        """
        conn = self._ensure_connection()
        rows = conn.execute(
            "SELECT id, direction, encrypted_content, timestamp "
            "FROM messages WHERE contact_id = ? "
            "ORDER BY timestamp ASC LIMIT ? OFFSET ?",
            (contact_id, limit, offset),
        ).fetchall()
        return rows

    def delete_messages(self, contact_id: str) -> int:
        """Удалить все сообщения для контакта."""
        conn = self._ensure_connection()
        cursor = conn.execute(
            "DELETE FROM messages WHERE contact_id = ?",
            (contact_id,),
        )
        conn.commit()
        return cursor.rowcount

    # ── Сессии ──────────────────────────────────────────

    def store_session(
        self,
        session_id: str,
        contact_id: str,
        ratchet_state: bytes,
    ) -> None:
        """Сохранить или обновить сессию."""
        conn = self._ensure_connection()
        conn.execute(
            "INSERT OR REPLACE INTO sessions (id, contact_id, ratchet_state, last_activity) "
            "VALUES (?, ?, ?, ?)",
            (session_id, contact_id, ratchet_state, time.time()),
        )
        conn.commit()

    def get_session(self, contact_id: str) -> tuple[str, bytes] | None:
        """Получить активную сессию для контакта."""
        conn = self._ensure_connection()
        row = conn.execute(
            "SELECT id, ratchet_state FROM sessions WHERE contact_id = ? "
            "ORDER BY last_activity DESC LIMIT 1",
            (contact_id,),
        ).fetchone()
        return row

    def delete_session(self, session_id: str) -> None:
        """Удалить сессию."""
        conn = self._ensure_connection()
        conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
        conn.commit()

    # ── Очистка ──────────────────────────────────────

    def wipe_all(self) -> None:
        """
        Полное удаление всех данных.

        ВНИМАНИЕ: Необратимая операция. Удаляет все контакты,
        сообщения и сессии. Файл БД перезаписывается.
        """
        conn = self._ensure_connection()
        conn.execute("DELETE FROM sessions")
        conn.execute("DELETE FROM messages")
        conn.execute("DELETE FROM contacts")
        conn.execute("VACUUM")
        conn.commit()
        logger.warning("Все данные БД удалены (WIPE)")
