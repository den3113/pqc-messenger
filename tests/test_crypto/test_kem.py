"""Тесты гибридного KEM и KDF."""

from pqc_messenger.crypto.kem import HybridKEM
from pqc_messenger.crypto.keys import X25519KeyPair, KyberKeyPair, IdentityKeyBundle
from pqc_messenger.crypto.kdf import KDF, PasswordKDF


class TestHybridKEM:
    """Тесты для гибридного KEM (X25519 + Kyber)."""

    def test_encapsulate_decapsulate(self):
        """Encapsulate/Decapsulate дают одинаковый shared secret."""
        alice = IdentityKeyBundle.generate()
        bob = IdentityKeyBundle.generate()

        bob_pub = bob.public_bundle()

        encap = HybridKEM.encapsulate(
            sender_x25519=alice.x25519,
            recipient_x25519_pub=bob_pub["x25519"],
            recipient_kyber_pub=bob_pub["kyber"],
        )

        decap_secret = HybridKEM.decapsulate(
            recipient_x25519=bob.x25519,
            recipient_kyber=bob.kyber,
            sender_x25519_ephemeral_pub=encap.x25519_ephemeral_pub,
            kyber_ciphertext=encap.kyber_ciphertext,
        )

        assert encap.shared_secret == decap_secret
        assert len(encap.shared_secret) == 32

    def test_different_recipients(self):
        """Разные получатели дают разные shared secrets."""
        alice = IdentityKeyBundle.generate()
        bob = IdentityKeyBundle.generate()
        charlie = IdentityKeyBundle.generate()

        bob_pub = bob.public_bundle()
        charlie_pub = charlie.public_bundle()

        encap_bob = HybridKEM.encapsulate(
            sender_x25519=alice.x25519,
            recipient_x25519_pub=bob_pub["x25519"],
            recipient_kyber_pub=bob_pub["kyber"],
        )

        encap_charlie = HybridKEM.encapsulate(
            sender_x25519=alice.x25519,
            recipient_x25519_pub=charlie_pub["x25519"],
            recipient_kyber_pub=charlie_pub["kyber"],
        )

        assert encap_bob.shared_secret != encap_charlie.shared_secret


class TestKDF:
    """Тесты для HKDF."""

    def test_derive_deterministic(self):
        """HKDF детерминистичен: одинаковые входы → одинаковый выход."""
        key = b"input_key_material_32_bytes!!!"
        info = b"test-context"

        result1 = KDF.derive(key, info)
        result2 = KDF.derive(key, info)

        assert result1 == result2
        assert len(result1) == 32

    def test_different_info_different_output(self):
        """Разные контексты (info) дают разные ключи."""
        key = b"same_input_key_material_32_!!!!!"
        result1 = KDF.derive(key, b"context-a")
        result2 = KDF.derive(key, b"context-b")
        assert result1 != result2

    def test_derive_pair(self):
        """derive_pair возвращает два разных 32-байтных ключа."""
        key = b"some_input_key_material_32_bytes"
        k1, k2 = KDF.derive_pair(key, b"ratchet")
        assert len(k1) == 32
        assert len(k2) == 32
        assert k1 != k2


class TestPasswordKDF:
    """Тесты для Argon2id."""

    def test_derive(self):
        """Базовая деривация из пароля."""
        key, salt = PasswordKDF.derive("test_password")
        assert len(key) == 32
        assert len(salt) == 16

    def test_derive_with_salt(self):
        """Деривация с явной солью детерминистична."""
        key1, salt1 = PasswordKDF.derive("password123")
        key2, _ = PasswordKDF.derive("password123", salt1)
        assert key1 == key2

    def test_different_passwords(self):
        """Разные пароли дают разные ключи (при одной соли)."""
        _, salt = PasswordKDF.derive("password1")
        key1, _ = PasswordKDF.derive("password1", salt)
        key2, _ = PasswordKDF.derive("password2", salt)
        assert key1 != key2

    def test_verify_correct(self):
        """Верификация правильного пароля."""
        key, salt = PasswordKDF.derive("correct_password")
        assert PasswordKDF.verify("correct_password", salt, key)

    def test_verify_incorrect(self):
        """Верификация неправильного пароля."""
        key, salt = PasswordKDF.derive("correct_password")
        assert not PasswordKDF.verify("wrong_password", salt, key)
