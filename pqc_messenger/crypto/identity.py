"""
Генерация идентификаторов пользователей на основе публичных ключей.

ID пользователя = SHA-256(x25519_pub || mode_byte || kyber_pub)
где mode_byte:
  \x01 — реальный ML-KEM/Kyber-768 (kyber_pub == 1184 байта)
  \x00 — эмуляция через X25519 (kyber_pub == 32 байта)

Нормализация по mode_byte гарантирует, что identity_hash одного
пользователя совпадает у всех peers независимо от того,
установлен ли liboqs на конкретном узле: вычисляющий хэш узел
смотрит только на длину kyber_pub и добавляет нужный байт.

Без нормализации SHA-256 от 32-байтного и 1184-байтного kyber_pub
давал бы разные хэши для одного пользователя, и relay не находил
получателя ("пользователь офлайн").
"""

from __future__ import annotations

import hashlib

from pqc_messenger.common.logging import get_logger

logger = get_logger("crypto.identity")

# Размер публичного ключа настоящего Kyber-768 (FIPS 203 / liboqs)
_KYBER768_PUB_SIZE = 1184

# Байт-префикс, кодирующий режим Kyber в хэше идентификатора
KYBER_MODE_REAL: bytes = b"\x01"   # настоящий ML-KEM
KYBER_MODE_EMUL: bytes = b"\x00"   # X25519-эмуляция


def _kyber_mode_byte(kyber_pub: bytes) -> bytes:
    """
    Вернуть однобайтовый префикс, однозначно идентифицирующий режим Kyber.

    Определение основано исключительно на длине ключа:
    - 1184 байта -> реальный Kyber-768
    - 32 байта   -> X25519-эмуляция
    - иное       -> ValueError (битый ключ или неизвестная версия протокола)
    """
    n = len(kyber_pub)
    if n == _KYBER768_PUB_SIZE:
        return KYBER_MODE_REAL
    if n == 32:
        return KYBER_MODE_EMUL
    raise ValueError(
        f"Неизвестный размер kyber_pub: {n} байт "
        f"(ожидается {_KYBER768_PUB_SIZE} для ML-KEM или 32 для эмуляции)"
    )


class Identity:
    """Генерация и форматирование идентификаторов."""

    @staticmethod
    def compute_id(x25519_pub: bytes, kyber_pub: bytes) -> str:
        """
        Вычислить идентификатор пользователя.

        Формула: SHA-256(x25519_pub || mode_byte || kyber_pub)
        mode_byte нормализует идентификатор так, что он не зависит
        от наличия liboqs на вычисляющем узле — только от того,
        какой ключ пользователь реально опубликовал.

        Args:
            x25519_pub: Публичный ключ X25519 (32 байта).
            kyber_pub:  Публичный ключ Kyber (1184 б — реальный, 32 б — эмуляция).

        Returns:
            64-символьная hex-строка (SHA-256).

        Raises:
            ValueError: Если kyber_pub имеет неизвестный размер.
        """
        mode = _kyber_mode_byte(kyber_pub)
        combined = x25519_pub + mode + kyber_pub
        return hashlib.sha256(combined).hexdigest()

    @staticmethod
    def compute_hash(x25519_pub: bytes, kyber_pub: bytes) -> bytes:
        """
        Вычислить хеш для маршрутизации на relay.

        Используется как recipient_hash в пакетах для "слепой" маршрутизации.
        Применяет ту же нормализацию, что и compute_id.

        Args:
            x25519_pub: Публичный ключ X25519 (32 байта).
            kyber_pub:  Публичный ключ Kyber.

        Returns:
            32 байта SHA-256.

        Raises:
            ValueError: Если kyber_pub имеет неизвестный размер.
        """
        mode = _kyber_mode_byte(kyber_pub)
        combined = x25519_pub + mode + kyber_pub
        return hashlib.sha256(combined).digest()

    @staticmethod
    def kyber_is_real(kyber_pub: bytes) -> bool:
        """Вернуть True, если kyber_pub соответствует настоящему Kyber-768."""
        return len(kyber_pub) == _KYBER768_PUB_SIZE

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
            kyber_pub:  Публичный ключ Kyber.

        Returns:
            True, если ID соответствует ключам.
        """
        try:
            computed = Identity.compute_id(x25519_pub, kyber_pub)
        except ValueError:
            return False
        return claimed_id == computed
