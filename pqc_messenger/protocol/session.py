"""
Управление криптографическими сессиями.

Сессия инкапсулирует весь криптографический контекст общения
с конкретным контактом: ratchet-состояние, ключи, метаданные.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime

from pqc_messenger.common.constants import PROTOCOL_VERSION, SESSION_TTL
from pqc_messenger.common.exceptions import SessionError
from pqc_messenger.common.logging import get_logger
from pqc_messenger.crypto.aead import AEAD
from pqc_messenger.crypto.identity import Identity
from pqc_messenger.protocol.packet import Packet, PacketType
from pqc_messenger.protocol.ratchet import SessionRatchet

logger = get_logger("protocol.session")


@dataclass
class Session:
    """
    Криптографическая сессия с контактом.

    Атрибуты:
        session_id: Уникальный идентификатор сессии.
        contact_id: ID контакта (SHA-256 fingerprint).
        contact_x25519_pub: X25519 публичный ключ контакта.
        contact_kyber_pub: Kyber публичный ключ контакта.
        ratchet: Double Ratchet для Forward Secrecy.
        created_at: Время создания сессии.
        last_activity: Время последней активности.
    """

    session_id: str
    contact_id: str
    contact_x25519_pub: bytes
    contact_kyber_pub: bytes
    ratchet: SessionRatchet
    created_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)

    @classmethod
    def create(
        cls,
        contact_id: str,
        contact_x25519_pub: bytes,
        contact_kyber_pub: bytes,
        ratchet: SessionRatchet,
    ) -> Session:
        """
        Создать новую сессию после успешного Handshake.

        Args:
            contact_id: ID контакта.
            contact_x25519_pub: X25519 публичный ключ контакта.
            contact_kyber_pub: Kyber публичный ключ контакта.
            ratchet: Инициализированный ratchet.

        Returns:
            Новая Session.
        """
        return cls(
            session_id=str(uuid.uuid4()),
            contact_id=contact_id,
            contact_x25519_pub=contact_x25519_pub,
            contact_kyber_pub=contact_kyber_pub,
            ratchet=ratchet,
        )

    def send_message(self, plaintext: str) -> Packet:
        """
        Зашифровать и упаковать сообщение для отправки.

        Args:
            plaintext: Текст сообщения.

        Returns:
            Packet, готовый к передаче через relay.
        """
        try:
            # Шифруем через ratchet
            encrypted_payload = self.ratchet.encrypt(
                plaintext.encode("utf-8")
            )

            # Хеш получателя для «слепой» маршрутизации
            recipient_hash = Identity.compute_hash(
                self.contact_x25519_pub,
                self.contact_kyber_pub,
            )

            # Создаём пакет
            packet = Packet(
                packet_type=PacketType.MESSAGE,
                recipient_hash=recipient_hash,
                payload=encrypted_payload,
            )

            self.last_activity = time.time()
            logger.debug(f"Сообщение зашифровано для сессии {self.session_id[:8]}")
            return packet

        except Exception as e:
            raise SessionError(f"Ошибка шифрования сообщения: {e}") from e

    def receive_message(self, packet: Packet) -> str:
        """
        Расшифровать входящее сообщение.

        Args:
            packet: Полученный Packet с типом MESSAGE.

        Returns:
            Расшифрованный текст сообщения.
        """
        if packet.packet_type != PacketType.MESSAGE:
            raise SessionError(
                f"Ожидался пакет MESSAGE, получен {packet.packet_type.name}"
            )

        try:
            plaintext_bytes = self.ratchet.decrypt(packet.payload)
            self.last_activity = time.time()
            logger.debug(f"Сообщение расшифровано в сессии {self.session_id[:8]}")
            return plaintext_bytes.decode("utf-8")

        except Exception as e:
            raise SessionError(f"Ошибка расшифрования сообщения: {e}") from e

    def is_expired(self) -> bool:
        """
        Проверить, истекла ли сессия.

        Returns:
            True, если сессия неактивна дольше SESSION_TTL.
        """
        return (time.time() - self.last_activity) > SESSION_TTL

    def destroy(self) -> None:
        """
        Безопасно уничтожить сессию.

        Обнуляет все криптографические ключи в памяти.
        Полноценное удаление из памяти невозможно в Python,
        но обнуление переменных минимизирует окно уязвимости.
        """
        logger.info(f"Уничтожение сессии {self.session_id[:8]}")

        # Обнуление ключей
        self.ratchet.root_key = b"\x00" * len(self.ratchet.root_key)
        if self.ratchet.sending_chain:
            self.ratchet.sending_chain.chain_key = b"\x00" * 32
        if self.ratchet.receiving_chain:
            self.ratchet.receiving_chain.chain_key = b"\x00" * 32
        self.ratchet.skipped_keys.clear()

    def serialize(self) -> dict:
        """Сериализовать сессию для хранения."""
        return {
            "session_id": self.session_id,
            "contact_id": self.contact_id,
            "contact_x25519_pub": self.contact_x25519_pub.hex(),
            "contact_kyber_pub": self.contact_kyber_pub.hex(),
            "ratchet_state": self.ratchet.serialize().hex(),
            "created_at": self.created_at,
            "last_activity": self.last_activity,
        }

    @classmethod
    def deserialize(cls, data: dict) -> Session:
        """Восстановить сессию из сериализованных данных."""
        try:
            ratchet = SessionRatchet.deserialize(
                bytes.fromhex(data["ratchet_state"])
            )
            return cls(
                session_id=data["session_id"],
                contact_id=data["contact_id"],
                contact_x25519_pub=bytes.fromhex(data["contact_x25519_pub"]),
                contact_kyber_pub=bytes.fromhex(data["contact_kyber_pub"]),
                ratchet=ratchet,
                created_at=data["created_at"],
                last_activity=data["last_activity"],
            )
        except Exception as e:
            raise SessionError(f"Ошибка десериализации сессии: {e}") from e
