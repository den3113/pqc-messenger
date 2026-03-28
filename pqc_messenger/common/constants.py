"""
Константы и конфигурация PQC-Messenger.

Централизованное хранение всех параметров криптографии, сети и приложения.
"""

# ──────────────────────────────────────────────
# Криптографические параметры
# ──────────────────────────────────────────────

KEM_ALGORITHM = "Kyber768"

AES_KEY_SIZE   = 32   # 256 бит
GCM_NONCE_SIZE = 12   # 96 бит  (NIST SP 800-38D)
GCM_TAG_SIZE   = 16   # 128 бит

HKDF_HASH           = "SHA256"
HKDF_INFO_HANDSHAKE = b"pqc-messenger-handshake-v1"
HKDF_INFO_MESSAGE   = b"pqc-messenger-message-v1"
HKDF_INFO_RATCHET   = b"pqc-messenger-ratchet-v1"
# Fix #7: отдельный info-тег для комбинирования секретов KEM,
# чтобы не пересекаться с HKDF_INFO_HANDSHAKE в handshake.py
HKDF_INFO_KEM_COMBINE = b"pqc-messenger-kem-combine-v1"

# Argon2id (RFC 9106)
ARGON2_TIME_COST   = 3
ARGON2_MEMORY_COST = 65536   # 64 MiB
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN    = 32
ARGON2_SALT_LEN    = 16

# ──────────────────────────────────────────────
# Параметры протокола
# ──────────────────────────────────────────────

PROTOCOL_VERSION = 1
MAX_SKIP         = 256
SESSION_TTL      = 7 * 24 * 60 * 60   # 7 дней

# Fix #2: максимальный суммарный размер кэша пропущенных ключей
# (защита от unbounded growth при частой ротации DH-ключей пиром)
MAX_SKIPPED_KEYS_TOTAL = 1000

# Fix #4: допустимое отклонение временной метки пакета от локальных часов
PACKET_TIMESTAMP_TOLERANCE_SEC = 120   # ±120 секунд

# ──────────────────────────────────────────────
# Сетевые параметры
# ──────────────────────────────────────────────

DEFAULT_RELAY_HOST = "0.0.0.0"
DEFAULT_RELAY_PORT = 8765
DEFAULT_RELAY_URL  = f"ws://localhost:{DEFAULT_RELAY_PORT}"

WS_PING_INTERVAL    = 30
WS_PING_TIMEOUT     = 10
WS_MAX_MESSAGE_SIZE = 1_048_576   # 1 MiB

MAILBOX_MAX_SIZE = 1000
# Fix #12: максимальное число записей в mailbox от одного отправителя
MAILBOX_PER_SENDER_MAX = 100

# Переподключение к relay
RECONNECT_DELAY_MIN = 2    # сек — начальная задержка
RECONNECT_DELAY_MAX = 60   # сек — максимальная задержка
RECONNECT_ATTEMPTS  = 0    # 0 = бесконечно

# Rate limiting на relay
RATE_LIMIT_WINDOW   = 60   # секунд
RATE_LIMIT_MAX_MSGS = 120  # сообщений в окне на одного клиента

# ──────────────────────────────────────────────
# Хранилище
# ──────────────────────────────────────────────

DEFAULT_DATA_DIR   = ".pqc_messenger"
DB_FILENAME        = "messenger.db"
KEYSTORE_FILENAME  = "keystore.db"

# Fix #6: порог автоматического WAL-чекпойнта (в страницах)
KEYSTORE_WAL_AUTOCHECKPOINT = 100

# Лимиты базы данных (пункт 3)
DB_MAX_MESSAGES_PER_CONTACT = 10_000   # макс. сообщений на контакт
DB_MAX_TOTAL_MESSAGES       = 100_000  # макс. всего сообщений
DB_PRUNE_KEEP               = 8_000    # оставить при очистке
