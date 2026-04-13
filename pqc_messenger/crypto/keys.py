"""
Генерация и управление криптографическими ключами.

Поддерживаемые алгоритмы:
- X25519  — классический обмен ключами на эллиптических кривых (RFC 7748)
- ML-KEM (Kyber-768) — постквантовая инкапсуляция ключей (FIPS 203)

ВАЖНО: В данной реализации Kyber-768 эмулируется через X25519 + HKDF,
если библиотека liboqs-python недоступна.
При наличии liboqs модуль автоматически переключится на реальный Kyber.

При несовместимости Kyber-режимов (реальный Kyber ↔ эмуляция)
encapsulate/decapsulate выбрасывают HandshakeError.
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

from pqc_messenger.common.exceptions import CryptoError, HandshakeError, KeyError_
from pqc_messenger.common.logging import get_logger

logger = get_logger("crypto.keys")

_HAS_LIBOQS = False

# ─── Определение пути к локальной liboqs ────────────────────────────────────
# Корень проекта = на два уровня выше этого файла (pqc_messenger/crypto/keys.py)
_PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
_PROJECT_LIB_DIR = os.path.join(_PROJECT_ROOT, "lib")

def _ensure_liboqs_python() -> bool:
    """
    Убедиться, что пакет liboqs-python установлен.
    Если нет — установить автоматически через pip.
    Возвращает True, если пакет доступен после проверки/установки.
    """
    import importlib
    import warnings
    try:
        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore",
                message=r"liboqs version.*differs",
                category=UserWarning,
            )
            importlib.import_module("oqs")
        return True
    except ImportError:
        pass

    import subprocess
    import sys
    logger.info("liboqs-python не найден. Автоматическая установка...")
    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "liboqs-python", "--quiet"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        logger.info("liboqs-python успешно установлен.")
        return True
    except subprocess.CalledProcessError as _e:
        logger.warning("Не удалось установить liboqs-python: %s", _e)
        return False


# ─── Настройка путей к liboqs ДО любого импорта oqs ────────────────────────
# ВАЖНО: OQS_INSTALL_PATH и LD_LIBRARY_PATH должны быть выставлены до первого
# импорта пакета oqs, потому что oqs.py вызывает _load_liboqs() на уровне
# модуля при импорте. Кэш sys.modules гарантирует, что повторный импорт
# не перезапускает _load_liboqs() — поэтому первый импорт должен уже видеть
# правильные переменные окружения.
_local_liboqs = os.path.join(_PROJECT_LIB_DIR, "liboqs.so")
if os.path.exists(_local_liboqs):
    # OQS_INSTALL_PATH — стандартный механизм oqs: ищет OQS_INSTALL_PATH/lib/liboqs.so.
    # Используем setdefault чтобы не перезаписывать явно заданный пользователем путь.
    os.environ.setdefault("OQS_INSTALL_PATH", _PROJECT_ROOT)

    # LD_LIBRARY_PATH нужен по двум причинам:
    # 1. ctypes.util.find_library() использует ldconfig/ldd — без записи в
    #    LD_LIBRARY_PATH или ldcache системная утилита не найдёт нашу liboqs.so.
    # 2. liboqs.so сама может динамически подгружать зависимости (libssl и др.)
    #    из той же папки — без LD_LIBRARY_PATH dlopen не найдёт их.
    ld_path = os.environ.get("LD_LIBRARY_PATH", "")
    lib_dir_abs = os.path.abspath(_PROJECT_LIB_DIR)
    if lib_dir_abs not in ld_path.split(os.pathsep):
        os.environ["LD_LIBRARY_PATH"] = (
            lib_dir_abs + (os.pathsep + ld_path if ld_path else "")
        )

    logger.debug(
        "OQS_INSTALL_PATH=%s, LD_LIBRARY_PATH включает %s",
        _PROJECT_ROOT,
        lib_dir_abs,
    )
else:
    logger.warning(
        "liboqs.so не найден в %s — будет использована системная библиотека (если есть).",
        _PROJECT_LIB_DIR,
    )

# ─── Автоустановка liboqs-python и импорт oqs ───────────────────────────────
if _ensure_liboqs_python():
    try:
        import warnings
        # Подавляем предупреждение о несовпадении версий liboqs / liboqs-python.
        # lib/liboqs.so.0.15.0 новее пакета 0.14.x, но API совместим.
        warnings.filterwarnings(
            "ignore",
            message=r"liboqs version.*differs",
            category=UserWarning,
        )
        import oqs  # type: ignore[import-untyped]
        _HAS_LIBOQS = True
        logger.info("liboqs доступен — используется реальный ML-KEM (Kyber-768)")
    except (ImportError, RuntimeError, SystemExit) as _oqs_err:
        logger.warning(
            "Не удалось инициализировать oqs (%s: %s) — "
            "Kyber-768 эмулируется через X25519 + HKDF. "
            "Проверьте: OQS_INSTALL_PATH=%s, LD_LIBRARY_PATH=%s",
            type(_oqs_err).__name__,
            _oqs_err,
            os.environ.get("OQS_INSTALL_PATH", "<не задан>"),
            os.environ.get("LD_LIBRARY_PATH", "<не задан>"),
        )
else:
    logger.warning(
        "liboqs-python недоступен — Kyber-768 эмулируется через X25519 + HKDF. "
        "Для полной постквантовой защиты убедитесь в наличии pip и интернета."
    )




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
        """Вычислить общий секрет ECDH."""
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

    encapsulate / decapsulate выбрасывают HandshakeError при
    несовместимости режимов (реальный Kyber ↔ эмуляция).
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
            kp = X25519KeyPair.generate()
            return cls(
                private_key=kp.serialize_private(),
                public_key=kp.serialize_public(),
                _is_real_kyber=False,
            )

    KYBER768_PUB_SIZE = 1184
    KYBER768_CT_SIZE = 1088
    EMULATED_SIZE = 32

    @staticmethod
    def _is_real_kyber_data(data: bytes) -> bool:
        """Определить, является ли ключ/шифротекст реальным Kyber-768."""
        return len(data) > 32

    def encapsulate(self, peer_public: bytes) -> tuple[bytes, bytes]:
        """
        Инкапсуляция: создать общий секрет и шифротекст для получателя.

        Режим (реальный Kyber или эмуляция X25519) определяется исключительно
        по размеру публичного ключа получателя — это позволяет корректно работать
        в смешанных сценариях (у нас liboqs есть, у пира — нет, или наоборот).

        Совместимость:
        - peer_public > 32 байт → реальный Kyber-768 (требует liboqs у нас)
        - peer_public == 32 байт → эмуляция X25519 (работает всегда)

        Args:
            peer_public: Публичный ключ получателя.

        Returns:
            (shared_secret, ciphertext) — общий секрет и шифротекст.

        Raises:
            HandshakeError: Если пир использует реальный Kyber, а у нас нет liboqs.
        """
        peer_is_real = self._is_real_kyber_data(peer_public)

        if peer_is_real:
            # Пир использует настоящий ML-KEM — нам тоже нужен liboqs
            if not _HAS_LIBOQS:
                raise HandshakeError(
                    "Пир использует реальный ML-KEM (Kyber-768), "
                    "но liboqs недоступен на этом узле. "
                    "Установите liboqs для подключения к этому контакту."
                )
            kem = oqs.KeyEncapsulation("Kyber768")
            ciphertext, shared_secret = kem.encap_secret(peer_public)
            return shared_secret, ciphertext
        else:
            # Пир использует эмуляцию (32-байтный X25519 ключ).
            # Используем эмуляцию независимо от того, есть ли у нас liboqs.
            ephemeral = X25519KeyPair.generate()
            peer_pub_key = X25519KeyPair.public_from_bytes(peer_public)
            raw_secret = ephemeral.shared_secret(peer_pub_key)
            shared_secret = hashlib.sha256(
                raw_secret + b"kyber-768-emulation"
            ).digest()
            ciphertext = ephemeral.serialize_public()  # 32 bytes
            if _HAS_LIBOQS:
                logger.debug(
                    "Пир использует X25519-эмуляцию Kyber — "
                    "деградация до эмуляции для совместимости."
                )
            return shared_secret, ciphertext

    def decapsulate(self, ciphertext: bytes) -> bytes:
        """
        Декапсуляция: извлечь общий секрет из шифротекста.

        Режим определяется по размеру шифротекста, а не по флагу _is_real_kyber,
        чтобы корректно обрабатывать контакты, чьи ключи менялись (например,
        контакт установил liboqs после первого обмена ключами).

        Совместимость:
        - ciphertext > 32 байт → реальный Kyber-768 (требует liboqs и реальный ключ)
        - ciphertext == 32 байт → эмуляция X25519 (работает всегда при наличии
          приватного ключа нужного типа)

        Args:
            ciphertext: Полученный шифротекст от отправителя.

        Returns:
            32 байта общего секрета.

        Raises:
            HandshakeError: Если шифротекст несовместим с нашим ключом.
        """
        if len(ciphertext) == 0:
            raise HandshakeError(
                "Получен пустой Kyber-шифротекст. Handshake отклонён."
            )

        ct_is_real = self._is_real_kyber_data(ciphertext)

        if ct_is_real:
            # Отправитель использует настоящий ML-KEM
            if not _HAS_LIBOQS:
                raise HandshakeError(
                    "Получен реальный Kyber-шифротекст, "
                    "но liboqs недоступен на этом узле."
                )
            if not self._is_real_kyber:
                raise HandshakeError(
                    "Получен реальный Kyber-шифротекст, "
                    "но наш ключ был создан в режиме эмуляции. "
                    "Сбросьте identity и зарегистрируйтесь заново."
                )
            kem = oqs.KeyEncapsulation("Kyber768", self.private_key)
            return kem.decap_secret(ciphertext)
        else:
            # Отправитель использует эмуляцию (ciphertext = ephemeral X25519 pub).
            # Декапсулируем через X25519 независимо от нашего режима.
            if self._is_real_kyber:
                # Наш приватный ключ — настоящий Kyber, но шифротекст — X25519.
                # Такое возможно если контакт добавил нас до установки liboqs.
                # Для совместимости пробуем использовать приватный ключ как X25519.
                # Это корректно только если private_key был сохранён как X25519 (32 байта),
                # что невозможно для настоящего Kyber (2400 байт). Бросаем ошибку.
                raise HandshakeError(
                    f"Получен X25519-эмуляция шифротекст ({len(ciphertext)} байт), "
                    "но наш ключ — настоящий Kyber-768. "
                    "Контакт должен обновить ваш публичный ключ в своей адресной книге."
                )
            own_kp = X25519KeyPair.from_private_bytes(self.private_key)
            peer_ephemeral = X25519KeyPair.public_from_bytes(ciphertext)
            raw_secret = own_kp.shared_secret(peer_ephemeral)
            return hashlib.sha256(
                raw_secret + b"kyber-768-emulation"
            ).digest()


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
        """
        combined = self.x25519.serialize_public() + self.kyber.public_key
        return hashlib.sha256(combined).hexdigest()

    def public_bundle(self) -> dict[str, bytes]:
        """Получить только публичные ключи для передачи собеседнику."""
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
