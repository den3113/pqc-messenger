"""
Зашифрованное хранилище ключей.

При инициализации устанавливается wal_autocheckpoint=100,
        при закрытии выполняется PRAGMA wal_checkpoint(TRUNCATE),
        чтобы WAL-файл не хранил данные дольше необходимого.
"""

from __future__ import annotations

import json
import os
import sqlite3

from pqc_messenger.common.constants import (
    DEFAULT_DATA_DIR,
    KEYSTORE_FILENAME,
    KEYSTORE_WAL_AUTOCHECKPOINT,
)
from pqc_messenger.common.exceptions import CryptoError, StorageError
from pqc_messenger.common.logging import get_logger
from pqc_messenger.crypto.aead import AEAD
from pqc_messenger.crypto.kdf import PasswordKDF
from pqc_messenger.crypto.keys import IdentityKeyBundle

logger = get_logger("storage.keystore")


class KeyStore:
    """
    Зашифрованное хранилище приватных ключей.

    Публичный API не раскрывает мастер-ключ напрямую.
    """

    def __init__(self, data_dir: str | None = None) -> None:
        if data_dir is None:
            data_dir = os.path.join(os.path.expanduser("~"), DEFAULT_DATA_DIR)
        self._data_dir  = data_dir
        self._ks_path   = os.path.join(data_dir, KEYSTORE_FILENAME)
        self.__master_key: bytes | None = None
        self._conn: sqlite3.Connection | None = None



    def initialize(self, password: str) -> bool:
        """
        Инициализировать хранилище.

        Устанавливает wal_autocheckpoint=100, чтобы WAL-файл
                усекался чаще и не хранил лишние зашифрованные блоки.

        Returns:
            True — создано новое хранилище.
            False — существующее разблокировано.

        Raises:
            CryptoError: Неверный пароль.
            StorageError: Повреждённое хранилище.
        """
        os.makedirs(self._data_dir, exist_ok=True)
        is_new = not os.path.exists(self._ks_path)

        self._conn = sqlite3.connect(self._ks_path)
        self._conn.execute("PRAGMA journal_mode=WAL")

        self._conn.execute(
            f"PRAGMA wal_autocheckpoint={KEYSTORE_WAL_AUTOCHECKPOINT}"
        )
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS keystore (
                key   TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );
        """)
        self._conn.commit()

        if is_new:
            master_key, salt = PasswordKDF.derive(password)
            self.__master_key = master_key
            self._put("argon2_salt", salt)
            self._put("verification", AEAD.encrypt(master_key, b"PQC_KEYSTORE_OK"))
            self._conn.commit()
            logger.info("Новое хранилище ключей создано")
            return True

        salt = self._get("argon2_salt")
        if salt is None:
            raise StorageError("Повреждённое хранилище: отсутствует соль")

        master_key, _ = PasswordKDF.derive(password, salt)

        verification = self._get("verification")
        if verification is None:
            raise StorageError("Повреждённое хранилище: отсутствует контрольная запись")

        try:
            result = AEAD.decrypt(master_key, verification)
        except Exception:
            raise CryptoError("Неверный пароль. Проверьте правильность ввода.")

        if result != b"PQC_KEYSTORE_OK":
            raise StorageError(
                "Хранилище повреждено: контрольная запись не совпадает."
            )

        self.__master_key = master_key
        logger.info("Хранилище ключей разблокировано")
        return False

    @property
    def is_unlocked(self) -> bool:
        return self.__master_key is not None

    # ── Публичный API шифрования ──────────────────────────────────────────────

    def encrypt_for_storage(self, plaintext: bytes) -> bytes:
        """Зашифровать данные на мастер-ключе."""
        if self.__master_key is None:
            raise StorageError("Хранилище не разблокировано")
        return AEAD.encrypt(self.__master_key, plaintext)

    def decrypt_from_storage(self, ciphertext: bytes) -> bytes:
        """Расшифровать данные, зашифрованные на мастер-ключе."""
        if self.__master_key is None:
            raise StorageError("Хранилище не разблокировано")
        return AEAD.decrypt(self.__master_key, ciphertext)



    def store_identity(self, bundle: IdentityKeyBundle) -> None:
        if self.__master_key is None:
            raise StorageError("Хранилище не инициализировано")
        serialized = bundle.serialize()
        json_data  = {k: v.hex() for k, v in serialized.items()}
        plaintext  = json.dumps(json_data).encode("utf-8")
        self._put("identity_bundle", AEAD.encrypt(self.__master_key, plaintext))
        self._conn.commit()  # type: ignore[union-attr]
        logger.info("Identity сохранён: %s...", bundle.fingerprint()[:16])

    def load_identity(self) -> IdentityKeyBundle | None:
        if self.__master_key is None:
            raise StorageError("Хранилище не инициализировано")
        encrypted = self._get("identity_bundle")
        if encrypted is None:
            return None
        try:
            plaintext  = AEAD.decrypt(self.__master_key, encrypted)
            json_data  = json.loads(plaintext)
            serialized = {k: bytes.fromhex(v) for k, v in json_data.items()}
            return IdentityKeyBundle.deserialize(serialized)
        except Exception as e:
            raise StorageError(f"Ошибка загрузки identity: {e}") from e



    def store_session_state(self, session_id: str, state: bytes) -> None:
        if self.__master_key is None:
            raise StorageError("Хранилище не инициализировано")
        self._put(f"session:{session_id}", AEAD.encrypt(self.__master_key, state))
        self._conn.commit()  # type: ignore[union-attr]

    def load_session_state(self, session_id: str) -> bytes | None:
        if self.__master_key is None:
            raise StorageError("Хранилище не инициализировано")
        encrypted = self._get(f"session:{session_id}")
        if encrypted is None:
            return None
        return AEAD.decrypt(self.__master_key, encrypted)



    def wipe(self) -> None:
        """
        Полное удаление всех ключей и самого файла хранилища.
        """
        self.close()
        for suffix in ["", "-wal", "-shm"]:
            path = self._ks_path + suffix
            if os.path.exists(path):
                try:
                    os.remove(path)
                except Exception as e:
                    logger.error("Не удалось удалить файл %s: %s", path, e)
        self.__master_key = None
        logger.warning("Хранилище ключей полностью уничтожено (WIPE)")

    def close(self) -> None:
        """
        Перед закрытием выполняем TRUNCATE-чекпойнт,
                чтобы WAL-файл усекался и не хранил лишних данных на диске.
        """
        if self.__master_key:
            self.__master_key = b"\x00" * len(self.__master_key)
            self.__master_key = None
        if self._conn:
            try:

                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except Exception as e:
                logger.warning("Не удалось выполнить WAL checkpoint: %s", e)
            self._conn.close()
            self._conn = None

    def _put(self, key: str, value: bytes) -> None:
        conn = self._conn
        if conn is None:
            raise StorageError("Хранилище не инициализировано")
        conn.execute(
            "INSERT OR REPLACE INTO keystore (key, value) VALUES (?, ?)",
            (key, value),
        )

    def _get(self, key: str) -> bytes | None:
        conn = self._conn
        if conn is None:
            raise StorageError("Хранилище не инициализировано")
        row = conn.execute(
            "SELECT value FROM keystore WHERE key = ?", (key,)
        ).fetchone()
        return row[0] if row else None
