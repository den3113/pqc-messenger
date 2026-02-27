"""
Иерархия исключений PQC-Messenger.

Все пользовательские исключения наследуются от PQCError,
что позволяет перехватывать их на верхнем уровне единообразно.
"""


class PQCError(Exception):
    """Базовое исключение PQC-Messenger."""


# ── Криптографические ошибки ──────────────────

class CryptoError(PQCError):
    """Общая ошибка криптографического модуля."""


class DecryptionError(CryptoError):
    """Ошибка при расшифровке данных."""


class IntegrityError(CryptoError):
    """Нарушение целостности данных (AES-GCM tag mismatch)."""


class KeyError_(CryptoError):
    """Ошибка, связанная с ключами (не найден, истёк, повреждён)."""


class KeyExpiredError(KeyError_):
    """Сессионный ключ истёк."""


# ── Ошибки протокола ────────────────────────

class ProtocolError(PQCError):
    """Общая ошибка протокола."""


class HandshakeError(ProtocolError):
    """Ошибка при выполнении Handshake."""


class PacketError(ProtocolError):
    """Ошибка при разборе или валидации пакета."""


class SessionError(ProtocolError):
    """Ошибка управления сессией."""


# ── Ошибки хранилища ────────────────────────

class StorageError(PQCError):
    """Общая ошибка хранилища."""


class DatabaseError(StorageError):
    """Ошибка при работе с базой данных."""


# ── Сетевые ошибки ──────────────────────────

class NetworkError(PQCError):
    """Общая сетевая ошибка."""


class ConnectionError_(NetworkError):
    """Ошибка подключения к relay-серверу."""


class RelayError(NetworkError):
    """Ошибка на стороне relay-сервера."""
