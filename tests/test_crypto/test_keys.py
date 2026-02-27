"""Тесты генерации ключей X25519 и Kyber-768."""

from pqc_messenger.crypto.keys import X25519KeyPair, KyberKeyPair, IdentityKeyBundle


class TestX25519KeyPair:
    """Тесты для X25519."""

    def test_generate(self):
        """Генерация ключей X25519."""
        kp = X25519KeyPair.generate()
        assert kp.private_key is not None
        assert kp.public_key is not None

    def test_serialize_public(self):
        """Сериализация публичного ключа = 32 байта."""
        kp = X25519KeyPair.generate()
        pub_bytes = kp.serialize_public()
        assert len(pub_bytes) == 32

    def test_serialize_private(self):
        """Сериализация приватного ключа = 32 байта."""
        kp = X25519KeyPair.generate()
        priv_bytes = kp.serialize_private()
        assert len(priv_bytes) == 32

    def test_from_private_bytes(self):
        """Восстановление ключей из сериализованного приватного ключа."""
        kp1 = X25519KeyPair.generate()
        priv_bytes = kp1.serialize_private()
        kp2 = X25519KeyPair.from_private_bytes(priv_bytes)
        assert kp1.serialize_public() == kp2.serialize_public()

    def test_shared_secret(self):
        """ECDH: обе стороны получают одинаковый shared secret."""
        alice = X25519KeyPair.generate()
        bob = X25519KeyPair.generate()

        secret_a = alice.shared_secret(bob.public_key)
        secret_b = bob.shared_secret(alice.public_key)

        assert secret_a == secret_b
        assert len(secret_a) == 32

    def test_unique_keys(self):
        """Два вызова generate() дают разные ключи."""
        kp1 = X25519KeyPair.generate()
        kp2 = X25519KeyPair.generate()
        assert kp1.serialize_public() != kp2.serialize_public()


class TestKyberKeyPair:
    """Тесты для ML-KEM (Kyber-768)."""

    def test_generate(self):
        """Генерация ключей Kyber."""
        kp = KyberKeyPair.generate()
        assert len(kp.private_key) > 0
        assert len(kp.public_key) > 0

    def test_encapsulate_decapsulate(self):
        """Encapsulate/Decapsulate дают одинаковый shared secret."""
        recipient = KyberKeyPair.generate()
        sender = KyberKeyPair.generate()

        shared_secret, ciphertext = sender.encapsulate(recipient.public_key)
        decapsulated = recipient.decapsulate(ciphertext)

        assert shared_secret == decapsulated
        assert len(shared_secret) == 32


class TestIdentityKeyBundle:
    """Тесты для IdentityKeyBundle."""

    def test_generate(self):
        """Генерация полного набора ключей."""
        bundle = IdentityKeyBundle.generate()
        assert bundle.x25519 is not None
        assert bundle.kyber is not None

    def test_fingerprint(self):
        """Fingerprint — 64-символьная hex-строка."""
        bundle = IdentityKeyBundle.generate()
        fp = bundle.fingerprint()
        assert len(fp) == 64
        # Проверяем, что это hex
        int(fp, 16)

    def test_fingerprint_deterministic(self):
        """Один и тот же бандл даёт одинаковый fingerprint."""
        bundle = IdentityKeyBundle.generate()
        assert bundle.fingerprint() == bundle.fingerprint()

    def test_unique_fingerprints(self):
        """Разные бандлы дают разные fingerprints."""
        b1 = IdentityKeyBundle.generate()
        b2 = IdentityKeyBundle.generate()
        assert b1.fingerprint() != b2.fingerprint()

    def test_serialize_deserialize(self):
        """Roundtrip сериализации/десериализации."""
        bundle = IdentityKeyBundle.generate()
        serialized = bundle.serialize()
        restored = IdentityKeyBundle.deserialize(serialized)

        assert bundle.fingerprint() == restored.fingerprint()

    def test_public_bundle(self):
        """Публичный бандл содержит только публичные ключи."""
        bundle = IdentityKeyBundle.generate()
        pub = bundle.public_bundle()
        assert "x25519" in pub
        assert "kyber" in pub
        assert len(pub["x25519"]) == 32
