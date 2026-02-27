"""
Зашифрованное хранилище ключей.

Приватные ключи идентичности хранятся зашифрованными на мастер-ключе,
который деривируется из пароля пользователя через Argon2id.

Структура файла keystore:
- salt (16 bytes): Соль для Argon2id
- encrypted_bundle: AES-256-GCM(master_key, serialized IdentityKeyBundle)
"""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

from pqc_messenger.common.constants import DEFAULT_DATA_DIR, KEYSTORE_FILENAME
from pqc_messenger.common.exceptions import CryptoError, StorageError
from pqc_messenger.common.logging import get_logger
from pqc_messenger.crypto.aead import AEAD
from pqc_messenger.crypto.kdf import PasswordKDF
from pqc_messenger.crypto.keys import IdentityKeyBundle

logger = get_logger("storage.keystore")


class KeyStore:
    """
    Зашифрованное хранилище приватных ключей.

    Все ключи шифруются мастер-ключом, который деривируется
    из пароля пользователя через Argon2id (RFC 9106).

    Использование:
        ks = KeyStore(data_dir="/path/to/data")
        ks.initialize("user_password")
        ks.store_identity(bundle)
        bundle = ks.load_identity()
    """

    def __init__(self, data_dir: str | None = None) -> None:
        if data_dir is None:
            data_dir = os.path.join(os.path.expanduser("~"), DEFAULT_DATA_DIR)
        self._data_dir = data_dir
        self._ks_path = os.path.join(data_dir, KEYSTORE_FILENAME)
        self._master_key: bytes | None = None
        self._conn: sqlite3.Connection | None = None

    def initialize(self, password: str) -> bool:
        """
        Инициализировать хранилище ключей.

        Если хранилище уже существует, проверяет пароль.
        Если нет — создаёт новое.

        Args:
            password: Пароль пользователя.

        Returns:
            True, если хранилище создано заново.
            False, если хранилище уже существовало.

        Raises:
            CryptoError: При неверном пароле.
        """
        os.makedirs(self._data_dir, exist_ok=True)

        is_new = not os.path.exists(self._ks_path)

        self._conn = sqlite3.connect(self._ks_path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS keystore (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );
        """)
        self._conn.commit()

        if is_new:
            # Создаём новое хранилище
            master_key, salt = PasswordKDF.derive(password)
            self._master_key = master_key

            # Сохраняем соль и контрольную запись
            self._put("argon2_salt", salt)
            verification = AEAD.encrypt(master_key, b"PQC_KEYSTORE_OK")
            self._put("verification", verification)
            self._conn.commit()

            logger.info("Новое хранилище ключей создано")
            return True
        else:
            # Проверяем пароль
            salt = self._get("argon2_salt")
            if salt is None:
                raise StorageError("Повреждённое хранилище: отсутствует соль")

            master_key, _ = PasswordKDF.derive(password, salt)

            verification = self._get("verification")
            if verification is None:
                raise StorageError("Повреждённое хранилище: отсутствует контрольная запись")

            try:
                result = AEAD.decrypt(master_key, verification)
                if result != b"PQC_KEYSTORE_OK":
                    raise CryptoError("Неверный пароль")
            except Exception:
                raise CryptoError(
                    "Неверный пароль. Невозможно разблокировать хранилище ключей."
                )

            self._master_key = master_key
            logger.info("Хранилище ключей разблокировано")
            return False

    def store_identity(self, bundle: IdentityKeyBundle) -> None:
        """
        Сохранить набор ключей идентичности (зашифрованно).

        Args:
            bundle: IdentityKeyBundle для сохранения.
        """
        if self._master_key is None:
            raise StorageError("Хранилище не инициализировано")

        serialized = bundle.serialize()
        # Конвертируем bytes-значения в hex для JSON-сериализации
        json_data = {k: v.hex() for k, v in serialized.items()}
        plaintext = json.dumps(json_data).encode("utf-8")

        encrypted = AEAD.encrypt(self._master_key, plaintext)
        self._put("identity_bundle", encrypted)
        self._conn.commit()  # type: ignore[union-attr]

        logger.info(f"Identity сохранён: {bundle.fingerprint()[:16]}...")

    def load_identity(self) -> IdentityKeyBundle | None:
        """
        Загрузить набор ключей идентичности.

        Returns:
            IdentityKeyBundle или None, если ещё не создан.
        """
        if self._master_key is None:
            raise StorageError("Хранилище не инициализировано")

        encrypted = self._get("identity_bundle")
        if encrypted is None:
            return None

        try:
            plaintext = AEAD.decrypt(self._master_key, encrypted)
            json_data = json.loads(plaintext)
            # Конвертируем hex обратно в bytes
            serialized = {k: bytes.fromhex(v) for k, v in json_data.items()}
            return IdentityKeyBundle.deserialize(serialized)
        except Exception as e:
            raise StorageError(f"Ошибка загрузки identity: {e}") from e

    def store_session_state(
        self,
        session_id: str,
        state: bytes,
    ) -> None:
        """Сохранить зашифрованное состояние сессии."""
        if self._master_key is None:
            raise StorageError("Хранилище не инициализировано")

        encrypted = AEAD.encrypt(self._master_key, state)
        self._put(f"session:{session_id}", encrypted)
        self._conn.commit()  # type: ignore[union-attr]

    def load_session_state(self, session_id: str) -> bytes | None:
        """Загрузить состояние сессии."""
        if self._master_key is None:
            raise StorageError("Хранилище не инициализировано")

        encrypted = self._get(f"session:{session_id}")
        if encrypted is None:
            return None

        return AEAD.decrypt(self._master_key, encrypted)

    def wipe(self) -> None:
        """
        Полное удаление всех ключей.

        ВНИМАНИЕ: Необратимая операция.
        """
        if self._conn:
            self._conn.execute("DELETE FROM keystore")
            self._conn.execute("VACUUM")
            self._conn.commit()

        self._master_key = None
        logger.warning("Все ключи удалены (WIPE)")

    def close(self) -> None:
        """Закрыть хранилище и обнулить мастер-ключ."""
        if self._master_key:
            # Пытаемся обнулить мастер-ключ (ограничения Python)
            self._master_key = b"\x00" * len(self._master_key)
            self._master_key = None

        if self._conn:
            self._conn.close()
            self._conn = None

    def _put(self, key: str, value: bytes) -> None:
        """Записать значение в keystore."""
        conn = self._conn
        if conn is None:
            raise StorageError("Хранилище не инициализировано")
        conn.execute(
            "INSERT OR REPLACE INTO keystore (key, value) VALUES (?, ?)",
            (key, value),
        )

    def _get(self, key: str) -> bytes | None:
        """Прочитать значение из keystore."""
        conn = self._conn
        if conn is None:
            raise StorageError("Хранилище не инициализировано")
        row = conn.execute(
            "SELECT value FROM keystore WHERE key = ?",
            (key,),
        ).fetchone()
        return row[0] if row else None
