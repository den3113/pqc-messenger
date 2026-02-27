"""
Генерация идентификаторов пользователей на основе публичных ключей.

ID пользователя = SHA-256(x25519_pub || kyber_pub)
Это обеспечивает:
- Уникальность: вероятность коллизии SHA-256 пренебрежимо мала
- Анонимность: невозможно восстановить ключи из ID
- Верифицируемость: собеседник может сравнить fingerprint
"""

from __future__ import annotations

import hashlib

from pqc_messenger.common.logging import get_logger

logger = get_logger("crypto.identity")


class Identity:
    """Генерация и форматирование идентификаторов."""

    @staticmethod
    def compute_id(x25519_pub: bytes, kyber_pub: bytes) -> str:
        """
        Вычислить идентификатор пользователя.

        Args:
            x25519_pub: Публичный ключ X25519 (32 байта).
            kyber_pub: Публичный ключ Kyber.

        Returns:
            64-символьная hex-строка (SHA-256).
        """
        combined = x25519_pub + kyber_pub
        return hashlib.sha256(combined).hexdigest()

    @staticmethod
    def compute_hash(x25519_pub: bytes, kyber_pub: bytes) -> bytes:
        """
        Вычислить хеш для маршрутизации на relay.

        Используется как recipient_hash в пакетах для «слепой» маршрутизации.

        Args:
            x25519_pub: Публичный ключ X25519 (32 байта).
            kyber_pub: Публичный ключ Kyber.

        Returns:
            32 байта SHA-256.
        """
        combined = x25519_pub + kyber_pub
        return hashlib.sha256(combined).digest()

    @staticmethod
    def format_fingerprint(identity_id: str) -> str:
        """
        Отформатировать fingerprint для удобного отображения.

        Формат: XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX

        Args:
            identity_id: 64-символьная hex-строка.

        Returns:
            Форматированный fingerprint.
        """
        # Берём первые 32 символа (128 бит) для отображения
        short = identity_id[:32].upper()
        groups = [short[i:i + 4] for i in range(0, 32, 4)]
        return "-".join(groups)

    @staticmethod
    def verify_fingerprint(
        claimed_id: str,
        x25519_pub: bytes,
        kyber_pub: bytes,
    ) -> bool:
        """
        Верифицировать, что fingerprint соответствует ключам.

        Args:
            claimed_id: Заявленный ID.
            x25519_pub: Публичный ключ X25519.
            kyber_pub: Публичный ключ Kyber.

        Returns:
            True, если ID соответствует ключам.
        """
        computed = Identity.compute_id(x25519_pub, kyber_pub)
        return claimed_id == computed
