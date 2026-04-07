# test_pfs.py
from pqc_messenger.crypto.keys import IdentityKeyBundle, X25519KeyPair
from pqc_messenger.protocol.handshake import Handshake
from pqc_messenger.protocol.ratchet import SessionRatchet
import copy

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

# Отправляем сообщение №1
enc1 = alice_r.encrypt(b"message 1")
bob_r.decrypt(enc1)

# Снимок состояния через __dict__ + ручная сериализация X25519KeyPair
def snapshot_ratchet(r):
    state = r.__dict__.copy()
    kp = state["dh_keypair"]
    state["dh_keypair"] = {
        "_serialized_private": kp.serialize_private(),
    }
    return copy.deepcopy(state)

def restore_ratchet(cls, state):
    obj = object.__new__(cls)
    s = state.copy()
    kp_data = s.pop("dh_keypair")
    s["dh_keypair"] = X25519KeyPair.from_private_bytes(kp_data["_serialized_private"])
    obj.__dict__.update(s)
    return obj

snapshot = snapshot_ratchet(bob_r)

# Отправляем ещё 5 сообщений
for i in range(2, 7):
    enc = alice_r.encrypt(f"message {i}".encode())
    bob_r.decrypt(enc)

# Восстанавливаем старый снимок
old_bob_r = restore_ratchet(SessionRatchet, snapshot)
enc_new = alice_r.encrypt(b"future message")

try:
    old_bob_r.decrypt(enc_new)
    print("FAIL: старый ключ не должен расшифровывать новые сообщения!")
except Exception as e:
    print(f"PFS работает: {type(e).__name__}  OK")
    print("Старое состояние ratchet не расшифровывает новые сообщения")
