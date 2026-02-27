"""
Функции деривации ключей (KDF).

- HKDF-SHA256: деривация сессионных и message ключей из shared_secret
- Argon2id (RFC 9106): деривация мастер-ключа из пароля пользователя
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF as CryptoHKDF

from pqc_messenger.common.constants import (
    AES_KEY_SIZE,
    ARGON2_HASH_LEN,
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    ARGON2_SALT_LEN,
    ARGON2_TIME_COST,
)
from pqc_messenger.common.exceptions import CryptoError
from pqc_messenger.common.logging import get_logger

logger = get_logger("crypto.kdf")


class KDF:
    """
    HKDF-SHA256 для деривации криптографических ключей.

    Используется для:
    - Деривации сессионных ключей из shared_secret
    - Генерации message key из chain key (ratchet)
    - Разделения одного секрета на несколько ключей
    """

    @staticmethod
    def derive(
        input_key: bytes,
        info: bytes,
        length: int = AES_KEY_SIZE,
        salt: bytes | None = None,
    ) -> bytes:
        """
        Деривировать ключ через HKDF-SHA256.

        Args:
            input_key: Входной ключевой материал (IKM).
            info: Контекстная строка (разделение доменов).
            length: Длина выходного ключа (по умолчанию 32 байта).
            salt: Опциональная соль.

        Returns:
            Деривированный ключ заданной длины.
        """
        hkdf = CryptoHKDF(
            algorithm=SHA256(),
            length=length,
            salt=salt,
            info=info,
        )
        return hkdf.derive(input_key)

    @staticmethod
    def derive_pair(
        input_key: bytes,
        info: bytes,
    ) -> tuple[bytes, bytes]:
        """
        Деривировать пару ключей из одного секрета.

        Используется для одновременной генерации chain_key и message_key
        в ratchet-механизме.

        Args:
            input_key: Входной ключевой материал.
            info: Контекстная строка.

        Returns:
            (key_1, key_2) — два 32-байтных ключа.
        """
        # Деривируем 64 байта и разделяем на два ключа
        combined = KDF.derive(input_key, info, length=64)
        return combined[:32], combined[32:]


class PasswordKDF:
    """
    Argon2id (RFC 9106) для деривации мастер-ключа из пароля.

    Argon2id — гибрид Argon2i (устойчивость к side-channel) и
    Argon2d (устойчивость к GPU/ASIC). Рекомендован для хеширования паролей.

    Параметры подобраны для баланса между безопасностью и UX:
    - time_cost=3: 3 итерации
    - memory_cost=64 MiB: достаточно для защиты от GPU
    - parallelism=4: использование 4 потоков
    """

    @staticmethod
    def derive(
        password: str,
        salt: bytes | None = None,
    ) -> tuple[bytes, bytes]:
        """
        Деривировать ключ из пароля через Argon2id.

        Args:
            password: Пароль пользователя.
            salt: Случайная соль (генерируется, если не указана).

        Returns:
            (derived_key, salt) — 32-байтный ключ и соль.
        """
        try:
            from argon2.low_level import Type, hash_secret_raw
        except ImportError as e:
            raise CryptoError(
                "Библиотека argon2-cffi не установлена. "
                "Установите: pip install argon2-cffi"
            ) from e

        if salt is None:
            salt = os.urandom(ARGON2_SALT_LEN)

        derived = hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=salt,
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST,
            parallelism=ARGON2_PARALLELISM,
            hash_len=ARGON2_HASH_LEN,
            type=Type.ID,  # Argon2id
        )

        logger.debug("Ключ деривирован из пароля через Argon2id")
        return derived, salt

    @staticmethod
    def verify(
        password: str,
        salt: bytes,
        expected: bytes,
    ) -> bool:
        """
        Проверить пароль по сохранённому хешу.

        Args:
            password: Введённый пароль.
            salt: Соль, использованная при деривации.
            expected: Ожидаемый результат деривации.

        Returns:
            True, если пароль верный.
        """
        derived, _ = PasswordKDF.derive(password, salt)
        # Сравнение в постоянном времени для защиты от timing attacks
        import hmac
        return hmac.compare_digest(derived, expected)
