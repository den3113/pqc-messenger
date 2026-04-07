# test_integration.py — запускать: python test_integration.py

from pqc_messenger.crypto.keys import IdentityKeyBundle
from pqc_messenger.protocol.handshake import Handshake
from pqc_messenger.protocol.ratchet import SessionRatchet
from pqc_messenger.crypto.aead import AEAD

# === ТЕСТ 1: Полный Handshake между Алисой и Бобом ===
print("=== ТЕСТ 1: Handshake ===")
alice = IdentityKeyBundle.generate()
bob   = IdentityKeyBundle.generate()
bob_pub = bob.public_bundle()

init_msg, alice_secret = Handshake.create_init(
    initiator=alice,
    responder_x25519_pub=bob_pub["x25519"],
    responder_kyber_pub=bob_pub["kyber"],
)

# Вычислить fingerprint Алисы и передать Бобу как доверенный
alice_fingerprint = alice.fingerprint()
trusted = {alice_fingerprint}

resp_msg, bob_secret = Handshake.process_init(bob, init_msg, trusted)  # <-- добавлено

final_alice = Handshake.complete_handshake(alice, alice_secret, resp_msg)
assert final_alice == bob_secret, "FAIL: секреты не совпали!"
print(f"  shared_secret совпал: {final_alice.hex()[:16]}...  OK")

# === ТЕСТ 2: Double Ratchet — шифрование/расшифровка ===
print("=== ТЕСТ 2: Double Ratchet ===")
alice_ratchet = SessionRatchet.initialize_as_initiator(
    shared_secret=final_alice,
    own_dh_keypair=alice.x25519,
    remote_dh_public=bob.x25519.serialize_public(),
)
bob_ratchet = SessionRatchet.initialize_as_responder(
    shared_secret=bob_secret,
    own_dh_keypair=bob.x25519,
    remote_dh_public=alice.x25519.serialize_public(),
)

messages = ["Привет!", "Это защищённый канал.", "PFS работает?", "Да, каждый ключ уникален."]
for text in messages:
    encrypted = alice_ratchet.encrypt(text.encode())
    decrypted = bob_ratchet.decrypt(encrypted).decode()
    assert decrypted == text, f"FAIL: '{text}' != '{decrypted}'"
    print(f"  '{text}' -> зашифровано -> расшифровано  OK")

# === ТЕСТ 3: Разные nonce — разные шифротексты ===
print("=== ТЕСТ 3: Уникальность nonce ===")
key = AEAD.generate_key()
ct1 = AEAD.encrypt(key, b"same message")
ct2 = AEAD.encrypt(key, b"same message")
assert ct1 != ct2, "FAIL: одинаковые nonce!"
print(f"  nonce1: {ct1[:12].hex()}")
print(f"  nonce2: {ct2[:12].hex()}  (разные)  OK")

# === ТЕСТ 4: KeyStore ===
print("=== ТЕСТ 4: KeyStore ===")
import tempfile, os
from pqc_messenger.storage.keystore import KeyStore
from pqc_messenger.common.exceptions import CryptoError

with tempfile.TemporaryDirectory() as tmpdir:
    ks = KeyStore(tmpdir)
    ks.initialize("правильный_пароль")
    bundle = IdentityKeyBundle.generate()
    ks.store_identity(bundle)
    ks.close()

    # Открыть с правильным паролем
    ks2 = KeyStore(tmpdir)
    ks2.initialize("правильный_пароль")
    loaded = ks2.load_identity()
    assert loaded.fingerprint() == bundle.fingerprint(), "FAIL: fingerprint не совпал!"
    print(f"  Identity сохранён и загружен: {bundle.fingerprint()[:16]}...  OK")
    ks2.close()

    # Открыть с неверным паролем
    ks3 = KeyStore(tmpdir)
    try:
        ks3.initialize("неверный_пароль")
        print("  FAIL: должна была быть ошибка!")
    except CryptoError:
        print("  Неверный пароль — CryptoError  OK")
    ks3.close()

print("\nВсе интеграционные тесты пройдены!")
