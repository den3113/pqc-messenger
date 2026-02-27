"""
Константы и конфигурация PQC-Messenger.

Централизованное хранение всех параметров криптографии, сети и приложения.
"""

# ──────────────────────────────────────────────
# Криптографические параметры
# ──────────────────────────────────────────────

# Алгоритм постквантовой инкапсуляции ключей (ML-KEM / Kyber)
KEM_ALGORITHM = "Kyber768"

# AES-256-GCM
AES_KEY_SIZE = 32          # 256 бит
GCM_NONCE_SIZE = 12        # 96 бит  (рекомендация NIST SP 800-38D)
GCM_TAG_SIZE = 16          # 128 бит

# HKDF
HKDF_HASH = "SHA256"
HKDF_INFO_HANDSHAKE = b"pqc-messenger-handshake-v1"
HKDF_INFO_MESSAGE = b"pqc-messenger-message-v1"
HKDF_INFO_RATCHET = b"pqc-messenger-ratchet-v1"

# Argon2id (RFC 9106) — параметры для деривации ключа из пароля
ARGON2_TIME_COST = 3           # Число итераций
ARGON2_MEMORY_COST = 65536     # 64 MiB
ARGON2_PARALLELISM = 4         # Потоки
ARGON2_HASH_LEN = 32           # Длина выходного ключа (256 бит)
ARGON2_SALT_LEN = 16           # Длина соли

# ──────────────────────────────────────────────
# Параметры протокола
# ──────────────────────────────────────────────

PROTOCOL_VERSION = 1

# Максимальное число пропущенных ключей в ratchet-цепочке
MAX_SKIP = 256

# Время жизни сессии (в секундах): 7 дней
SESSION_TTL = 7 * 24 * 60 * 60

# ──────────────────────────────────────────────
# Сетевые параметры
# ──────────────────────────────────────────────

DEFAULT_RELAY_HOST = "0.0.0.0"
DEFAULT_RELAY_PORT = 8765
DEFAULT_RELAY_URL = f"ws://localhost:{DEFAULT_RELAY_PORT}"

# WebSocket
WS_PING_INTERVAL = 30          # Интервал пинга (сек)
WS_PING_TIMEOUT = 10           # Таймаут пинга (сек)
WS_MAX_MESSAGE_SIZE = 1_048_576  # 1 MiB

# Размер очереди mailbox на relay
MAILBOX_MAX_SIZE = 1000

# ──────────────────────────────────────────────
# Хранилище
# ──────────────────────────────────────────────

DEFAULT_DATA_DIR = ".pqc_messenger"
DB_FILENAME = "messenger.db"
KEYSTORE_FILENAME = "keystore.db"
