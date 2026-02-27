"""
Структура пакета PQC-Messenger.

Формат бинарного пакета:
┌────────────────────────────────────────────────┐
│ Header (plaintext, 42 bytes)                   │
│  ├─ version: u8           (1 byte)             │
│  ├─ type: u8              (1 byte)             │
│  ├─ recipient_hash: bytes (32 bytes, SHA-256)  │
│  └─ timestamp: u64        (8 bytes, big-endian)│
├────────────────────────────────────────────────┤
│ Payload length: u32       (4 bytes, big-endian)│
├────────────────────────────────────────────────┤
│ Payload (encrypted)       (variable)           │
│  └─ nonce (12) + ciphertext + tag (16)         │
└────────────────────────────────────────────────┘

Заголовок НЕ зашифрован, но используется как AAD при шифровании payload,
что гарантирует его целостность.
"""

from __future__ import annotations

import struct
import time
from enum import IntEnum
from dataclasses import dataclass, field

from pqc_messenger.common.constants import PROTOCOL_VERSION
from pqc_messenger.common.exceptions import PacketError
from pqc_messenger.common.logging import get_logger

logger = get_logger("protocol.packet")

# Формат заголовка: version(1) + type(1) + recipient_hash(32) + timestamp(8) = 42 байта
HEADER_FORMAT = "!BB32sQ"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # 42

# Формат длины payload
PAYLOAD_LEN_FORMAT = "!I"
PAYLOAD_LEN_SIZE = struct.calcsize(PAYLOAD_LEN_FORMAT)  # 4


class PacketType(IntEnum):
    """Типы пакетов протокола."""

    HANDSHAKE_INIT = 0x01   # Инициация Handshake
    HANDSHAKE_RESP = 0x02   # Ответ на Handshake
    MESSAGE = 0x10          # Зашифрованное сообщение
    ACK = 0x20              # Подтверждение доставки
    CONTROL = 0x30          # Управляющие команды (удаление, уведомления)
    KEY_ROTATION = 0x40     # Ротация DH ключа (ratchet step)


@dataclass
class Packet:
    """
    Сетевой пакет PQC-Messenger.

    Атрибуты:
        version: Версия протокола.
        packet_type: Тип пакета.
        recipient_hash: SHA-256 хеш публичного ключа получателя (32 байта).
                         Используется relay-сервером для «слепой» маршрутизации.
        timestamp: Unix-время создания пакета.
        payload: Зашифрованная нагрузка (nonce + ciphertext + tag).
    """

    packet_type: PacketType
    recipient_hash: bytes
    payload: bytes
    version: int = PROTOCOL_VERSION
    timestamp: int = field(default_factory=lambda: int(time.time()))

    def __post_init__(self) -> None:
        """Валидация полей после инициализации."""
        if len(self.recipient_hash) != 32:
            raise PacketError(
                f"recipient_hash должен быть 32 байта, получено {len(self.recipient_hash)}"
            )
        if not isinstance(self.packet_type, PacketType):
            try:
                self.packet_type = PacketType(self.packet_type)
            except ValueError as e:
                raise PacketError(f"Неизвестный тип пакета: {self.packet_type}") from e

    def header_bytes(self) -> bytes:
        """
        Сериализовать заголовок пакета.

        Используется как AAD при шифровании/расшифровании payload.
        """
        return struct.pack(
            HEADER_FORMAT,
            self.version,
            self.packet_type.value,
            self.recipient_hash,
            self.timestamp,
        )

    def serialize(self) -> bytes:
        """
        Сериализовать весь пакет в байты для передачи по сети.

        Returns:
            Байтовое представление пакета.
        """
        header = self.header_bytes()
        payload_len = struct.pack(PAYLOAD_LEN_FORMAT, len(self.payload))
        return header + payload_len + self.payload

    @classmethod
    def deserialize(cls, data: bytes) -> Packet:
        """
        Десериализовать пакет из байтовой последовательности.

        Args:
            data: Сырые байты пакета.

        Returns:
            Объект Packet.

        Raises:
            PacketError: При ошибке разбора.
        """
        min_size = HEADER_SIZE + PAYLOAD_LEN_SIZE
        if len(data) < min_size:
            raise PacketError(
                f"Пакет слишком короткий: минимум {min_size} байт, получено {len(data)}"
            )

        try:
            # Разбор заголовка
            version, ptype, recipient_hash, timestamp = struct.unpack(
                HEADER_FORMAT, data[:HEADER_SIZE]
            )

            # Разбор длины payload
            payload_len_data = data[HEADER_SIZE:HEADER_SIZE + PAYLOAD_LEN_SIZE]
            (payload_len,) = struct.unpack(PAYLOAD_LEN_FORMAT, payload_len_data)

            # Извлечение payload
            payload_start = HEADER_SIZE + PAYLOAD_LEN_SIZE
            payload = data[payload_start:payload_start + payload_len]

            if len(payload) != payload_len:
                raise PacketError(
                    f"Несоответствие длины payload: ожидалось {payload_len}, "
                    f"получено {len(payload)}"
                )

            return cls(
                version=version,
                packet_type=PacketType(ptype),
                recipient_hash=recipient_hash,
                timestamp=timestamp,
                payload=payload,
            )

        except PacketError:
            raise
        except Exception as e:
            raise PacketError(f"Ошибка десериализации пакета: {e}") from e

    def __repr__(self) -> str:
        return (
            f"Packet(type={self.packet_type.name}, "
            f"recipient={self.recipient_hash[:8].hex()}..., "
            f"payload_size={len(self.payload)})"
        )
