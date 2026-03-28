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

Fix #4: validate_timestamp() проверяет свежесть пакета.
Fix #13: version_check() отклоняет неизвестные версии протокола.
"""

from __future__ import annotations

import struct
import time
from enum import IntEnum
from dataclasses import dataclass, field

from pqc_messenger.common.constants import (
    PACKET_TIMESTAMP_TOLERANCE_SEC,   # Fix #4
    PROTOCOL_VERSION,
)
from pqc_messenger.common.exceptions import PacketError, PacketReplayError
from pqc_messenger.common.logging import get_logger

logger = get_logger("protocol.packet")

HEADER_FORMAT = "!BB32sQ"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # 42

PAYLOAD_LEN_FORMAT = "!I"
PAYLOAD_LEN_SIZE = struct.calcsize(PAYLOAD_LEN_FORMAT)  # 4


class PacketType(IntEnum):
    """Типы пакетов протокола."""

    HANDSHAKE_INIT = 0x01
    HANDSHAKE_RESP = 0x02
    MESSAGE        = 0x10
    ACK            = 0x20
    CONTROL        = 0x30
    KEY_ROTATION   = 0x40


@dataclass
class Packet:
    """
    Сетевой пакет PQC-Messenger.

    Fix #4: метод validate_timestamp() проверяет, что временная метка
            пакета не слишком далеко отстоит от текущего времени.
    Fix #13: deserialize() отклоняет пакеты с неизвестной версией протокола.
    """

    packet_type: PacketType
    recipient_hash: bytes
    payload: bytes
    version: int = PROTOCOL_VERSION
    timestamp: int = field(default_factory=lambda: int(time.time()))

    def __post_init__(self) -> None:
        if len(self.recipient_hash) != 32:
            raise PacketError(
                f"recipient_hash должен быть 32 байта, получено {len(self.recipient_hash)}"
            )
        if not isinstance(self.packet_type, PacketType):
            try:
                self.packet_type = PacketType(self.packet_type)
            except ValueError as e:
                raise PacketError(f"Неизвестный тип пакета: {self.packet_type}") from e

    def validate_timestamp(
        self,
        tolerance: int = PACKET_TIMESTAMP_TOLERANCE_SEC,
    ) -> None:
        """
        Fix #4: проверить свежесть временной метки пакета.

        Отклоняет пакеты, временная метка которых отличается от текущего
        времени более чем на ±tolerance секунд.  Это защищает от replay-атак
        (злоумышленник не может переотправить захваченный пакет спустя время).

        Args:
            tolerance: Максимально допустимое отклонение в секундах.

        Raises:
            PacketReplayError: Если метка слишком старая или из будущего.
        """
        now  = int(time.time())
        diff = abs(now - self.timestamp)
        if diff > tolerance:
            raise PacketReplayError(
                f"Пакет отклонён: временная метка {self.timestamp} "
                f"отличается от текущего времени {now} на {diff}с "
                f"(максимум {tolerance}с). Возможен replay-attack."
            )

    def header_bytes(self) -> bytes:
        """Сериализовать заголовок пакета (используется как AAD)."""
        return struct.pack(
            HEADER_FORMAT,
            self.version,
            self.packet_type.value,
            self.recipient_hash,
            self.timestamp,
        )

    def serialize(self) -> bytes:
        """Сериализовать весь пакет в байты для передачи по сети."""
        header      = self.header_bytes()
        payload_len = struct.pack(PAYLOAD_LEN_FORMAT, len(self.payload))
        return header + payload_len + self.payload

    @classmethod
    def deserialize(cls, data: bytes) -> Packet:
        """
        Десериализовать пакет из байтовой последовательности.

        Fix #13: отклоняет пакеты с версией, отличной от PROTOCOL_VERSION,
                 и возвращает осмысленный код ошибки.

        Args:
            data: Сырые байты пакета.

        Returns:
            Объект Packet.

        Raises:
            PacketError: При ошибке разбора или неизвестной версии.
        """
        min_size = HEADER_SIZE + PAYLOAD_LEN_SIZE
        if len(data) < min_size:
            raise PacketError(
                f"Пакет слишком короткий: минимум {min_size} байт, получено {len(data)}"
            )

        try:
            version, ptype, recipient_hash, timestamp = struct.unpack(
                HEADER_FORMAT, data[:HEADER_SIZE]
            )

            # Fix #13: явная проверка версии с понятным сообщением
            if version != PROTOCOL_VERSION:
                raise PacketError(
                    f"Неподдерживаемая версия протокола: {version}. "
                    f"Ожидается: {PROTOCOL_VERSION}. "
                    "Обновите клиент или сервер до совместимой версии."
                )

            payload_len_data = data[HEADER_SIZE:HEADER_SIZE + PAYLOAD_LEN_SIZE]
            (payload_len,) = struct.unpack(PAYLOAD_LEN_FORMAT, payload_len_data)

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
