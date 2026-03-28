"""
Гибридный KEM: X25519 + ML-KEM (Kyber-768).

Комбинирует классический ECDH и постквантовую инкапсуляцию ключей.
Финальный общий секрет вычисляется как:
    shared_secret = HKDF-SHA256(x25519_secret || kyber_secret, info="kem-combine")

Такая гибридная схема гарантирует безопасность, даже если один из
алгоритмов окажется скомпрометированным.

Fix #1: если Kyber-режимы несовместимы (один пир использует реальный Kyber,
        другой — эмуляцию), HandshakeError поднимается немедленно вместо
        тихой подстановки нулевого секрета.

Fix #7: для комбинирования KEM-секретов используется отдельный info-тег
        HKDF_INFO_KEM_COMBINE, отличный от HKDF_INFO_HANDSHAKE.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from pqc_messenger.common.constants import (
    AES_KEY_SIZE,
    HKDF_INFO_KEM_COMBINE,   # Fix #7
)
from pqc_messenger.common.exceptions import CryptoError, HandshakeError
from pqc_messenger.common.logging import get_logger
from pqc_messenger.crypto.keys import KyberKeyPair, X25519KeyPair

logger = get_logger("crypto.kem")


@dataclass
class HybridEncapsulation:
    """Результат гибридной инкапсуляции."""

    shared_secret: bytes         # Финальный общий секрет (32 байта)
    x25519_ephemeral_pub: bytes  # Эфемерный X25519 публичный ключ (32 байта)
    kyber_ciphertext: bytes      # Шифротекст Kyber KEM


class HybridKEM:
    """
    Гибридный KEM: X25519 + ML-KEM (Kyber-768).

    Обеспечивает устойчивость как к классическим, так и к квантовым атакам.
    Если один из алгоритмов сломан, второй продолжает защищать канал.
    """

    @staticmethod
    def _combine_secrets(
        x25519_secret: bytes,
        kyber_secret: bytes,
        info: bytes = HKDF_INFO_KEM_COMBINE,  # Fix #7: собственный info-тег
    ) -> bytes:
        """
        Объединить два секрета через HKDF-SHA256.

        Args:
            x25519_secret: Секрет от X25519 ECDH.
            kyber_secret: Секрет от ML-KEM.
            info: Контекстная строка для HKDF.

        Returns:
            32 байта финального ключа.
        """
        combined = x25519_secret + kyber_secret
        hkdf = HKDF(
            algorithm=SHA256(),
            length=AES_KEY_SIZE,
            salt=None,
            info=info,
        )
        return hkdf.derive(combined)

    @staticmethod
    def encapsulate(
        sender_x25519: X25519KeyPair,
        recipient_x25519_pub: bytes,
        recipient_kyber_pub: bytes,
    ) -> HybridEncapsulation:
        """
        Выполнить гибридную инкапсуляцию (сторона отправителя).

        Fix #1: если режимы Kyber несовместимы, выбрасывает HandshakeError.

        Шаги:
        1. Сгенерировать эфемерную пару X25519
        2. Вычислить x25519_secret = ECDH(ephemeral, recipient_pub)
        3. Инкапсулировать kyber_secret через ML-KEM
        4. shared_secret = HKDF(x25519_secret || kyber_secret, info=kem-combine)

        Args:
            sender_x25519: Ключи отправителя.
            recipient_x25519_pub: X25519 публичный ключ получателя (32 байта).
            recipient_kyber_pub: Kyber публичный ключ получателя.

        Returns:
            HybridEncapsulation с общим секретом и данными для передачи.

        Raises:
            HandshakeError: Если Kyber-режимы несовместимы (Fix #1).
        """
        try:
            # 1. Эфемерный X25519 DH
            ephemeral = X25519KeyPair.generate()
            peer_pub = X25519KeyPair.public_from_bytes(recipient_x25519_pub)
            x25519_secret = ephemeral.shared_secret(peer_pub)

            # 2. ML-KEM (Kyber) инкапсуляция
            kyber_kp = KyberKeyPair.generate()

            # Fix #1: encapsulate теперь выбрасывает HandshakeError
            # вместо возврата нулевого секрета при несовместимости режимов.
            kyber_secret, kyber_ct = kyber_kp.encapsulate(recipient_kyber_pub)

            # 3. Комбинирование секретов через HKDF (Fix #7: отдельный info)
            shared_secret = HybridKEM._combine_secrets(x25519_secret, kyber_secret)

            logger.debug("Гибридная инкапсуляция выполнена успешно")

            return HybridEncapsulation(
                shared_secret=shared_secret,
                x25519_ephemeral_pub=ephemeral.serialize_public(),
                kyber_ciphertext=kyber_ct,
            )

        except HandshakeError:
            raise
        except Exception as e:
            raise CryptoError(f"Ошибка гибридной инкапсуляции: {e}") from e

    @staticmethod
    def decapsulate(
        recipient_x25519: X25519KeyPair,
        recipient_kyber: KyberKeyPair,
        sender_x25519_ephemeral_pub: bytes,
        kyber_ciphertext: bytes,
    ) -> bytes:
        """
        Выполнить гибридную декапсуляцию (сторона получателя).

        Fix #1: если Kyber-режимы несовместимы, выбрасывает HandshakeError.

        Шаги:
        1. Вычислить x25519_secret = ECDH(own_private, sender_ephemeral_pub)
        2. Декапсулировать kyber_secret из шифротекста
        3. shared_secret = HKDF(x25519_secret || kyber_secret, info=kem-combine)

        Args:
            recipient_x25519: Своя пара ключей X25519.
            recipient_kyber: Своя пара ключей Kyber.
            sender_x25519_ephemeral_pub: Эфемерный X25519 публичный ключ отправителя.
            kyber_ciphertext: Шифротекст ML-KEM от отправителя.

        Returns:
            32 байта общего секрета.

        Raises:
            HandshakeError: Если Kyber-режимы несовместимы (Fix #1).
        """
        try:
            # 1. X25519 ECDH
            peer_pub = X25519KeyPair.public_from_bytes(sender_x25519_ephemeral_pub)
            x25519_secret = recipient_x25519.shared_secret(peer_pub)

            # 2. Kyber декапсуляция (Fix #1: выбрасывает при несовместимости)
            kyber_secret = recipient_kyber.decapsulate(kyber_ciphertext)

            # 3. Комбинирование (Fix #7: отдельный info)
            shared_secret = HybridKEM._combine_secrets(x25519_secret, kyber_secret)

            logger.debug("Гибридная декапсуляция выполнена успешно")
            return shared_secret

        except HandshakeError:
            raise
        except Exception as e:
            raise CryptoError(f"Ошибка гибридной декапсуляции: {e}") from e
