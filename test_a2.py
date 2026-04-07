# test_argon2.py — замерить время деривации
import time
from pqc_messenger.crypto.kdf import PasswordKDF

start = time.time()
key, salt = PasswordKDF.derive("тестовый_пароль")
elapsed = time.time() - start

print(f"Время деривации Argon2id: {elapsed:.2f} сек")
print(f"Ключ: {key.hex()}")
# Ожидаемо: 0.5–2 сек (защита от GPU-перебора)

# Верификация
assert PasswordKDF.verify("тестовый_пароль", salt, key)
assert not PasswordKDF.verify("неверный_пароль", salt, key)
print("Верификация пароля: OK")
