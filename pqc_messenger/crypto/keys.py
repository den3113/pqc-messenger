"""
Генерация и управление криптографическими ключами.

Поддерживаемые алгоритмы:
- X25519  — классический обмен ключами на эллиптических кривых (RFC 7748)
- ML-KEM (Kyber-768) — постквантовая инкапсуляция ключей (FIPS 203)

ВАЖНО: В данной реализации Kyber-768 эмулируется через X25519 + HKDF,
поскольку библиотека liboqs-python может быть недоступна.
При наличии liboqs модуль автоматически переключится на реальный Kyber.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from pqc_messenger.common.exceptions import CryptoError, KeyError_
from pqc_messenger.common.logging import get_logger

logger = get_logger("crypto.keys")

# Попытка импорта liboqs для реального Kyber
_HAS_LIBOQS = False

# Автоматический поиск liboqs.so в lib/ директории проекта
_PROJECT_LIB_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "lib",
)
if os.path.isdir(_PROJECT_LIB_DIR):
    # Добавляем lib/ в путь поиска разделяемых библиотек
    _current_ld = os.environ.get("LD_LIBRARY_PATH", "")
    if _PROJECT_LIB_DIR not in _current_ld:
        os.environ["LD_LIBRARY_PATH"] = (
            f"{_PROJECT_LIB_DIR}:{_current_ld}" if _current_ld else _PROJECT_LIB_DIR
        )
    # Предзагрузка через ctypes для текущего процесса
    import ctypes
    import ctypes.util
    _liboqs_path = os.path.join(_PROJECT_LIB_DIR, "liboqs.so")
    if os.path.exists(_liboqs_path):
        try:
            ctypes.cdll.LoadLibrary(_liboqs_path)
            logger.debug("liboqs.so загружена из %s", _liboqs_path)
        except OSError as _e:
            logger.warning("Не удалось загрузить liboqs.so: %s", _e)

try:
    import warnings
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message="liboqs version.*differs", category=UserWarning)
        import oqs  # type: ignore[import-untyped]
    _HAS_LIBOQS = True
    logger.info("liboqs доступен — используется реальный ML-KEM (Kyber-768)")
except ImportError:
    logger.warning(
        "liboqs не найден — Kyber-768 эмулируется через X25519 + HKDF. "
        "Для полной постквантовой защиты установите liboqs-python."
    )


# ─── X25519 ──────────────────────────────────────────────────────────────────


@dataclass
class X25519KeyPair:
    """
    Пара ключей на эллиптической кривой X25519 (RFC 7748).

    Используется для классического обмена ключами Диффи-Хеллмана.
    """

    private_key: X25519PrivateKey
    public_key: X25519PublicKey

    @classmethod
    def generate(cls) -> X25519KeyPair:
        """Сгенерировать новую пару ключей X25519."""
        private = X25519PrivateKey.generate()
        return cls(private_key=private, public_key=private.public_key())

    def shared_secret(self, peer_public: X25519PublicKey) -> bytes:
        """
        Вычислить общий секрет ECDH.

        Args:
            peer_public: Публичный ключ другой стороны.

        Returns:
            32 байта общего секрета.
        """
        return self.private_key.exchange(peer_public)

    def serialize_public(self) -> bytes:
        """Сериализовать публичный ключ в 32 байта (Raw)."""
        return self.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    def serialize_private(self) -> bytes:
        """Сериализовать приватный ключ в 32 байта (Raw)."""
        return self.private_key.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        )

    @classmethod
    def from_private_bytes(cls, data: bytes) -> X25519KeyPair:
        """Восстановить пару ключей из сериализованного приватного ключа."""
        if len(data) != 32:
            raise KeyError_(f"X25519 private key must be 32 bytes, got {len(data)}")
        private = X25519PrivateKey.from_private_bytes(data)
        return cls(private_key=private, public_key=private.public_key())

    @classmethod
    def public_from_bytes(cls, data: bytes) -> X25519PublicKey:
        """Восстановить публичный ключ из 32 байт."""
        if len(data) != 32:
            raise KeyError_(f"X25519 public key must be 32 bytes, got {len(data)}")
        return X25519PublicKey.from_public_bytes(data)


# ─── ML-KEM (Kyber-768) ─────────────────────────────────────────────────────


@dataclass
class KyberKeyPair:
    """
    Пара ключей ML-KEM (Kyber-768) — постквантовый KEM на решётках (FIPS 203).

    При отсутствии liboqs используется эмуляция через X25519.
    Эмуляция сохраняет интерфейс, но НЕ обеспечивает постквантовую стойкость.
    """

    private_key: bytes
    public_key: bytes
    _is_real_kyber: bool = False

    @classmethod
    def generate(cls) -> KyberKeyPair:
        """Сгенерировать новую пару ключей Kyber-768."""
        if _HAS_LIBOQS:
            kem = oqs.KeyEncapsulation("Kyber768")
            public_key = kem.generate_keypair()
            private_key = kem.export_secret_key()
            return cls(
                private_key=private_key,
                public_key=public_key,
                _is_real_kyber=True,
            )
        else:
            # Эмуляция: используем X25519 как замену
            kp = X25519KeyPair.generate()
            return cls(
                private_key=kp.serialize_private(),
                public_key=kp.serialize_public(),
                _is_real_kyber=False,
            )

    # Размер реального Kyber-768 публичного ключа (FIPS 203)
    KYBER768_PUB_SIZE = 1184
    # Размер реального Kyber-768 шифротекста
    KYBER768_CT_SIZE = 1088
    # Размер эмулированного ключа / шифротекста (X25519)
    EMULATED_SIZE = 32
    # Null-секрет для случая несовместимости Kyber-режимов.
    # Обе стороны используют этот секрет, когда Kyber-инкапсуляция
    # невозможна (разные liboqs). Безопасность обеспечивается X25519-частью.
    KYBER_NULL_SECRET = b"\x00" * 32

    @staticmethod
    def _is_real_kyber_data(data: bytes) -> bool:
        """Определить, является ли ключ/шифротекст реальным Kyber-768."""
        return len(data) > 32

    def encapsulate(self, peer_public: bytes) -> tuple[bytes, bytes]:
        """
        Инкапсуляция: создать общий секрет и шифротекст для получателя.

        Автоматически определяет режим по размеру публичного ключа пира.
        При несовместимости (нет liboqs, но пир использует реальный Kyber)
        возвращает null-секрет — обе стороны получат одинаковый результат.

        Args:
            peer_public: Публичный ключ получателя.

        Returns:
            (shared_secret, ciphertext) — общий секрет и шифротекст.
        """
        peer_is_real = self._is_real_kyber_data(peer_public)

        if _HAS_LIBOQS and peer_is_real:
            # Оба устройства поддерживают реальный Kyber
            kem = oqs.KeyEncapsulation("Kyber768")
            ciphertext, shared_secret = kem.encap_secret(peer_public)
            return shared_secret, ciphertext

        if not peer_is_real:
            # Пир использует эмуляцию (32-байтовый X25519 ключ) —
            # используем эмуляцию и мы, независимо от нашего liboqs
            ephemeral = X25519KeyPair.generate()
            peer_pub_key = X25519KeyPair.public_from_bytes(peer_public)
            raw_secret = ephemeral.shared_secret(peer_pub_key)
            shared_secret = hashlib.sha256(
                raw_secret + b"kyber-768-emulation"
            ).digest()
            ciphertext = ephemeral.serialize_public()  # 32 bytes
            return shared_secret, ciphertext

        # peer_is_real=True, но _HAS_LIBOQS=False:
        # Пир использует реальный Kyber, а у нас нет liboqs.
        # Возвращаем null-секрет и пустой маркер-шифротекст.
        logger.warning(
            "Пир использует реальный Kyber, но liboqs недоступен. "
            "Kyber-часть используется с null-секретом."
        )
        return self.KYBER_NULL_SECRET, b""

    def decapsulate(self, ciphertext: bytes) -> bytes:
        """
        Декапсуляция: извлечь общий секрет из шифротекста.

        При несовместимости (получен реальный Kyber-шифротекст, но нет liboqs,
        или наоборот) возвращает null-секрет для согласованного фоллбэка.

        Args:
            ciphertext: Полученный шифротекст от отправителя.

        Returns:
            32 байта общего секрета.
        """
        if len(ciphertext) == 0:
            # Пустой шифротекст = маркер null-секрета от стороны без liboqs
            logger.warning(
                "Получен пустой Kyber шифротекст (пир без liboqs). "
                "Используется null-секрет."
            )
            return self.KYBER_NULL_SECRET

        ct_is_real = self._is_real_kyber_data(ciphertext)

        if self._is_real_kyber and ct_is_real and _HAS_LIBOQS:
            # Реальный Kyber шифротекст + реальный ключ
            kem = oqs.KeyEncapsulation("Kyber768", self.private_key)
            return kem.decap_secret(ciphertext)

        if not ct_is_real and not self._is_real_kyber:
            # Оба используют эмуляцию: ciphertext = ephemeral X25519 pub
            own_kp = X25519KeyPair.from_private_bytes(self.private_key)
            peer_ephemeral = X25519KeyPair.public_from_bytes(ciphertext)
            raw_secret = own_kp.shared_secret(peer_ephemeral)
            return hashlib.sha256(
                raw_secret + b"kyber-768-emulation"
            ).digest()

        # Несовместимость: один реальный, другой эмулированный
        logger.warning(
            f"Несовместимость Kyber-режимов "
            f"(ciphertext={len(ciphertext)} байт, "
            f"own_real={self._is_real_kyber}). "
            "Используется null-секрет."
        )
        return self.KYBER_NULL_SECRET


# ─── Identity Key Bundle ─────────────────────────────────────────────────────


@dataclass
class IdentityKeyBundle:
    """
    Полный набор ключей идентичности пользователя.

    Включает:
    - x25519: Классическая пара ключей для ECDH
    - kyber: Постквантовая пара ключей для ML-KEM
    """

    x25519: X25519KeyPair
    kyber: KyberKeyPair

    @classmethod
    def generate(cls) -> IdentityKeyBundle:
        """Сгенерировать полный набор ключей идентичности."""
        logger.info("Генерация нового набора ключей идентичности...")
        return cls(
            x25519=X25519KeyPair.generate(),
            kyber=KyberKeyPair.generate(),
        )

    def fingerprint(self) -> str:
        """
        Вычислить отпечаток (fingerprint) идентичности.

        Формула: SHA-256(x25519_pub || kyber_pub), представленный как hex.
        Используется для отображения и верификации собеседника.

        Returns:
            64-символьная hex-строка.
        """
        combined = self.x25519.serialize_public() + self.kyber.public_key
        return hashlib.sha256(combined).hexdigest()

    def public_bundle(self) -> dict[str, bytes]:
        """
        Получить только публичные ключи для передачи собеседнику.

        Returns:
            Словарь с ключами 'x25519' и 'kyber'.
        """
        return {
            "x25519": self.x25519.serialize_public(),
            "kyber": self.kyber.public_key,
        }

    def serialize(self) -> dict[str, bytes]:
        """Сериализовать полный бандл (вкл. приватные ключи) для хранения."""
        return {
            "x25519_private": self.x25519.serialize_private(),
            "x25519_public": self.x25519.serialize_public(),
            "kyber_private": self.kyber.private_key,
            "kyber_public": self.kyber.public_key,
        }

    @classmethod
    def deserialize(cls, data: dict[str, bytes]) -> IdentityKeyBundle:
        """Восстановить бандл из сериализованных данных."""
        try:
            x25519 = X25519KeyPair.from_private_bytes(data["x25519_private"])
            # Определяем, реальный ли Kyber по размеру ключей и доступности liboqs.
            # Эмуляция использует 32-байтовые X25519 ключи,
            # реальный Kyber-768 — 1184-byte pub / 2400-byte priv.
            kyber_pub = data["kyber_public"]
            is_real = _HAS_LIBOQS and len(kyber_pub) > 32
            kyber = KyberKeyPair(
                private_key=data["kyber_private"],
                public_key=kyber_pub,
                _is_real_kyber=is_real,
            )
            return cls(x25519=x25519, kyber=kyber)
        except Exception as e:
            raise KeyError_(f"Не удалось десериализовать IdentityKeyBundle: {e}") from e
