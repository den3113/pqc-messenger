"""
Типы сетевых сообщений для WebSocket-транспорта.

Определяет формат JSON-сообщений между клиентом и relay-сервером.
Relay оперирует только этими сообщениями, не имея доступа к содержимому пакетов.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import StrEnum

from pqc_messenger.common.exceptions import NetworkError
from pqc_messenger.common.logging import get_logger

logger = get_logger("network.messages")


class MessageType(StrEnum):
    """Типы WebSocket-сообщений между клиентом и relay."""

    REGISTER = "register"         # Регистрация клиента на relay
    UNREGISTER = "unregister"     # Отключение от relay
    SEND = "send"                 # Отправка зашифрованного пакета
    DELIVER = "deliver"           # Доставка пакета от relay к получателю
    ACK = "ack"                   # Подтверждение получения
    ERROR = "error"               # Ошибка
    PING = "ping"                 # Keepalive
    PONG = "pong"                 # Ответ на keepalive


@dataclass
class RelayMessage:
    """
    JSON-сообщение для WebSocket-транспорта.

    Атрибуты:
        type: Тип сообщения.
        recipient_hash: Хеш публичного ключа получателя (hex).
        payload: Base64-encoded зашифрованный пакет.
        sender_hash: Хеш отправителя (для регистрации). Relay использует
                      его только для маршрутизации, но не для идентификации.
        timestamp: Unix-время.
        error: Описание ошибки (для типа ERROR).
        message_id: Уникальный ID сообщения для подтверждений.
    """

    type: MessageType
    recipient_hash: str = ""
    payload: str = ""
    sender_hash: str = ""
    timestamp: float = field(default_factory=time.time)
    error: str = ""
    message_id: str = ""

    def to_json(self) -> str:
        """Сериализовать в JSON-строку для передачи по WebSocket."""
        data: dict = {"type": self.type.value}

        # Включаем только непустые поля (экономия трафика)
        if self.recipient_hash:
            data["recipient_hash"] = self.recipient_hash
        if self.payload:
            data["payload"] = self.payload
        if self.sender_hash:
            data["sender_hash"] = self.sender_hash
        if self.error:
            data["error"] = self.error
        if self.message_id:
            data["message_id"] = self.message_id

        data["timestamp"] = self.timestamp
        return json.dumps(data, separators=(",", ":"))

    @classmethod
    def from_json(cls, raw: str) -> RelayMessage:
        """
        Десериализовать из JSON-строки.

        Args:
            raw: JSON-закодированное сообщение.

        Returns:
            RelayMessage.

        Raises:
            NetworkError: При ошибке разбора.
        """
        try:
            data = json.loads(raw)
            return cls(
                type=MessageType(data["type"]),
                recipient_hash=data.get("recipient_hash", ""),
                payload=data.get("payload", ""),
                sender_hash=data.get("sender_hash", ""),
                timestamp=data.get("timestamp", time.time()),
                error=data.get("error", ""),
                message_id=data.get("message_id", ""),
            )
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            raise NetworkError(f"Ошибка разбора RelayMessage: {e}") from e

    @classmethod
    def register(cls, identity_hash: str) -> RelayMessage:
        """Создать сообщение REGISTER."""
        return cls(type=MessageType.REGISTER, sender_hash=identity_hash)

    @classmethod
    def send(
        cls,
        recipient_hash: str,
        payload: str,
        message_id: str = "",
    ) -> RelayMessage:
        """Создать сообщение SEND."""
        return cls(
            type=MessageType.SEND,
            recipient_hash=recipient_hash,
            payload=payload,
            message_id=message_id,
        )

    @classmethod
    def deliver(
        cls,
        recipient_hash: str,
        payload: str,
        message_id: str = "",
    ) -> RelayMessage:
        """Создать сообщение DELIVER (relay → client)."""
        return cls(
            type=MessageType.DELIVER,
            recipient_hash=recipient_hash,
            payload=payload,
            message_id=message_id,
        )

    @classmethod
    def ack(cls, message_id: str) -> RelayMessage:
        """Создать сообщение ACK."""
        return cls(type=MessageType.ACK, message_id=message_id)

    @classmethod
    def error(cls, error_msg: str) -> RelayMessage:
        """Создать сообщение ERROR."""
        return cls(type=MessageType.ERROR, error=error_msg)
