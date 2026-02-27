"""Тесты AES-256-GCM AEAD шифрования."""

import os
import pytest

from pqc_messenger.crypto.aead import AEAD
from pqc_messenger.common.exceptions import IntegrityError, DecryptionError


class TestAEAD:
    """Тесты для AES-256-GCM."""

    def test_encrypt_decrypt(self):
        """Базовый encrypt/decrypt roundtrip."""
        key = AEAD.generate_key()
        plaintext = b"Hello, PQC-Messenger!"

        encrypted = AEAD.encrypt(key, plaintext)
        decrypted = AEAD.decrypt(key, encrypted)

        assert decrypted == plaintext

    def test_with_aad(self):
        """Шифрование с Additional Authenticated Data."""
        key = AEAD.generate_key()
        plaintext = b"Secret message"
        aad = b"packet-header-data"

        encrypted = AEAD.encrypt(key, plaintext, aad)
        decrypted = AEAD.decrypt(key, encrypted, aad)

        assert decrypted == plaintext

    def test_wrong_aad_fails(self):
        """Неверный AAD вызывает IntegrityError."""
        key = AEAD.generate_key()
        plaintext = b"Secret"
        aad = b"correct-header"

        encrypted = AEAD.encrypt(key, plaintext, aad)

        with pytest.raises(IntegrityError):
            AEAD.decrypt(key, encrypted, b"wrong-header")

    def test_wrong_key_fails(self):
        """Неверный ключ вызывает ошибку."""
        key1 = AEAD.generate_key()
        key2 = AEAD.generate_key()
        plaintext = b"Secret"

        encrypted = AEAD.encrypt(key1, plaintext)

        with pytest.raises((IntegrityError, DecryptionError)):
            AEAD.decrypt(key2, encrypted)

    def test_bit_modification_detected(self):
        """
        КРИТИЧЕСКИЙ ТЕСТ (ТЗ п.7):
        Изменение хотя бы одного бита вызывает ошибку аутентификации.
        """
        key = AEAD.generate_key()
        plaintext = b"This message integrity must be verified"

        encrypted = AEAD.encrypt(key, plaintext)

        # Модифицируем один бит в середине зашифрованных данных
        modified = bytearray(encrypted)
        mid = len(modified) // 2
        modified[mid] ^= 0x01  # Инвертируем 1 бит

        with pytest.raises(IntegrityError):
            AEAD.decrypt(key, bytes(modified))

    def test_nonce_uniqueness(self):
        """Два шифрования одного текста дают разные результаты (разные nonce)."""
        key = AEAD.generate_key()
        plaintext = b"Same text"

        enc1 = AEAD.encrypt(key, plaintext)
        enc2 = AEAD.encrypt(key, plaintext)

        assert enc1 != enc2  # Разные nonce → разный шифротекст

    def test_encrypted_size(self):
        """Проверка размера зашифрованных данных: nonce(12) + ct + tag(16)."""
        key = AEAD.generate_key()
        plaintext = b"Test"

        encrypted = AEAD.encrypt(key, plaintext)
        # nonce(12) + ciphertext(len(plaintext)) + tag(16)
        expected_size = 12 + len(plaintext) + 16
        assert len(encrypted) == expected_size

    def test_empty_plaintext(self):
        """Шифрование пустого текста."""
        key = AEAD.generate_key()
        encrypted = AEAD.encrypt(key, b"")
        decrypted = AEAD.decrypt(key, encrypted)
        assert decrypted == b""

    def test_large_plaintext(self):
        """Шифрование большого объёма данных (1 MiB)."""
        key = AEAD.generate_key()
        plaintext = os.urandom(1024 * 1024)  # 1 MiB

        encrypted = AEAD.encrypt(key, plaintext)
        decrypted = AEAD.decrypt(key, encrypted)

        assert decrypted == plaintext

    def test_generate_key_size(self):
        """Сгенерированный ключ = 32 байта."""
        key = AEAD.generate_key()
        assert len(key) == 32

    def test_invalid_key_size(self):
        """Ключ неправильного размера вызывает ошибку."""
        with pytest.raises(DecryptionError):
            AEAD.encrypt(b"short_key", b"data")
