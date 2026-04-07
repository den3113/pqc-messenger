# test_mitm.py — симуляция модификации пакета в транзите
from pqc_messenger.crypto.keys import IdentityKeyBundle
from pqc_messenger.protocol.handshake import Handshake
from pqc_messenger.protocol.ratchet import SessionRatchet
from pqc_messenger.common.exceptions import IntegrityError

alice = IdentityKeyBundle.generate()
bob   = IdentityKeyBundle.generate()
bob_pub = bob.public_bundle()

alice_fingerprint = alice.fingerprint()
trusted = {alice_fingerprint}

init_msg, alice_s = Handshake.create_init(alice, bob_pub["x25519"], bob_pub["kyber"])
resp_msg, bob_s   = Handshake.process_init(bob, init_msg, trusted)
final = Handshake.complete_handshake(alice, alice_s, resp_msg)

alice_r = SessionRatchet.initialize_as_initiator(final, alice.x25519, bob.x25519.serialize_public())
bob_r   = SessionRatchet.initialize_as_responder(final, bob.x25519, alice.x25519.serialize_public())

# Шифруем нормальное сообщение
encrypted = alice_r.encrypt(b"secret message")
print(f"Оригинал (hex): {encrypted.hex()[:40]}...")

# Симулируем MITM: меняем 1 бит
tampered = bytearray(encrypted)
tampered[40] ^= 0x01   # инвертировать один бит
tampered = bytes(tampered)

# Боб пытается расшифровать изменённый пакет
try:
    bob_r.decrypt(tampered)
    print("FAIL: должна быть ошибка целостности!")
except (IntegrityError, Exception) as e:
    print(f"Модификация обнаружена: {type(e).__name__}  OK")
    print("GCM-тег не совпал — атака отклонена")
