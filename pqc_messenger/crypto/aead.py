"""
AES-256-GCM аутентифицированное шифрование (AEAD).

NIST SP 800-38D — Galois/Counter Mode.
Обеспечивает одновременно конфиденциальность и целостность данных.

Формат зашифрованного блока:
    [nonce (12 bytes)] [ciphertext (variable)] [tag (16 bytes)]
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pqc_messenger.common.constants import AES_KEY_SIZE, GCM_NONCE_SIZE, GCM_TAG_SIZE
from pqc_messenger.common.exceptions import DecryptionError, IntegrityError
from pqc_messenger.common.logging import get_logger

logger = get_logger("crypto.aead")


class AEAD:
    """
    AES-256-GCM AEAD шифрование.

    Гарантии:
    - Конфиденциальность: данные зашифрованы AES-256
    - Целостность: GCM tag подтверждает отсутствие модификаций
    - Аутентичность: Additional Authenticated Data (AAD) защищены от подмены
    """

    @staticmethod
    def encrypt(
        key: bytes,
        plaintext: bytes,
        aad: bytes = b"",
    ) -> bytes:
        """
        Зашифровать данные с аутентификацией.

        Args:
            key: 32-байтный ключ AES-256.
            plaintext: Открытый текст.
            aad: Дополнительные аутентифицируемые данные (заголовок пакета и т.д.).

        Returns:
            nonce || ciphertext || tag (nonce 12 байт, tag 16 байт).

        Raises:
            CryptoError: При некорректном размере ключа.
        """
        if len(key) != AES_KEY_SIZE:
            raise DecryptionError(
                f"Ключ AES-256 должен быть {AES_KEY_SIZE} байт, получено {len(key)}"
            )

        nonce = os.urandom(GCM_NONCE_SIZE)

        aesgcm = AESGCM(key)
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, aad if aad else None)

        return nonce + ciphertext_with_tag

    @staticmethod
    def decrypt(
        key: bytes,
        data: bytes,
        aad: bytes = b"",
    ) -> bytes:
        """
        Расшифровать и проверить целостность данных.

        Args:
            key: 32-байтный ключ AES-256.
            data: Зашифрованные данные в формате nonce || ciphertext || tag.
            aad: Дополнительные аутентифицируемые данные (должны совпадать с encrypt).

        Returns:
            Расшифрованный открытый текст.

        Raises:
            IntegrityError: Если данные были модифицированы (tag mismatch).
            DecryptionError: При других ошибках расшифрования.
        """
        if len(key) != AES_KEY_SIZE:
            raise DecryptionError(
                f"Ключ AES-256 должен быть {AES_KEY_SIZE} байт, получено {len(key)}"
            )

        min_size = GCM_NONCE_SIZE + GCM_TAG_SIZE
        if len(data) < min_size:
            raise DecryptionError(
                f"Данные слишком короткие: минимум {min_size} байт, получено {len(data)}"
            )

        nonce = data[:GCM_NONCE_SIZE]
        ciphertext_with_tag = data[GCM_NONCE_SIZE:]

        from cryptography.exceptions import InvalidTag

        aesgcm = AESGCM(key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, aad if aad else None)
        except InvalidTag as e:
            raise IntegrityError(
                "Нарушение целостности данных: GCM authentication tag не совпадает. "
                "Данные были модифицированы при передаче."
            ) from e
        except Exception as e:
            raise DecryptionError(f"Ошибка расшифрования: {e}") from e

        return plaintext

    @staticmethod
    def generate_key() -> bytes:
        """Сгенерировать случайный 256-битный ключ для AES-256-GCM."""
        return AESGCM.generate_key(bit_length=256)
