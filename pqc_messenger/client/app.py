"""
Главная логика клиентского приложения PQC-Messenger.

Координирует работу всех модулей: криптографию, протокол, сеть, хранилище.
"""

from __future__ import annotations

import asyncio
import base64
import os
from pathlib import Path

from pqc_messenger.common.constants import DEFAULT_DATA_DIR, DEFAULT_RELAY_URL
from pqc_messenger.common.exceptions import (
    CryptoError,
    PQCError,
    SessionError,
    StorageError,
)
from pqc_messenger.common.logging import get_logger
from pqc_messenger.crypto.aead import AEAD
from pqc_messenger.crypto.identity import Identity
from pqc_messenger.crypto.keys import IdentityKeyBundle
from pqc_messenger.network.transport import Transport
from pqc_messenger.protocol.handshake import Handshake
from pqc_messenger.protocol.packet import Packet, PacketType
from pqc_messenger.protocol.ratchet import SessionRatchet
from pqc_messenger.protocol.session import Session
from pqc_messenger.storage.database import Contact, Database, Message
from pqc_messenger.storage.keystore import KeyStore

logger = get_logger("client.app")


class PQCMessengerApp:
    """
    Главная точка входа приложения PQC-Messenger.

    Управляет жизненным циклом: инициализация, подключение,
    обмен сообщениями, очистка данных.
    """

    def __init__(self, data_dir: str | None = None) -> None:
        if data_dir is None:
            data_dir = os.path.join(os.path.expanduser("~"), DEFAULT_DATA_DIR)

        self._data_dir = data_dir
        self._db = Database(data_dir)
        self._keystore = KeyStore(data_dir)
        self._transport = Transport()
        self._identity: IdentityKeyBundle | None = None
        self._sessions: dict[str, Session] = {}  # contact_id → Session
        self._pending_handshakes: dict[str, tuple[bytes, bytes, bytes]] = {}
        # contact_id → (init_secret, contact_x25519_pub, contact_kyber_pub)
        self._master_key: bytes | None = None
        self._message_callback = None

    @property
    def identity(self) -> IdentityKeyBundle | None:
        """Текущая идентичность пользователя."""
        return self._identity

    @property
    def identity_id(self) -> str | None:
        """ID текущей идентичности."""
        if self._identity:
            return self._identity.fingerprint()
        return None

    @property
    def identity_hash(self) -> str | None:
        """Хеш идентичности для маршрутизации."""
        if self._identity:
            return Identity.compute_id(
                self._identity.x25519.serialize_public(),
                self._identity.kyber.public_key,
            )
        return None

    @property
    def is_initialized(self) -> bool:
        """Инициализировано ли приложение."""
        return self._identity is not None

    @property
    def is_connected(self) -> bool:
        """Подключено ли приложение к relay."""
        return self._transport.is_connected

    def initialize(self, password: str) -> bool:
        """
        Инициализировать приложение.

        Создаёт или разблокирует хранилище ключей,
        загружает или генерирует идентичность.

        Args:
            password: Пароль пользователя.

        Returns:
            True, если создана новая идентичность.
        """
        # Инициализируем базу данных
        self._db.initialize()

        # Инициализируем keystore
        is_new = self._keystore.initialize(password)

        if is_new:
            # Генерируем новую идентичность
            self._identity = IdentityKeyBundle.generate()
            self._keystore.store_identity(self._identity)
            logger.info(
                f"Новая идентичность создана: "
                f"{Identity.format_fingerprint(self._identity.fingerprint())}"
            )
            return True
        else:
            # Загружаем существующую идентичность
            self._identity = self._keystore.load_identity()
            if self._identity is None:
                # Хранилище существует, но идентичность отсутствует
                self._identity = IdentityKeyBundle.generate()
                self._keystore.store_identity(self._identity)
                return True

            logger.info(
                f"Идентичность загружена: "
                f"{Identity.format_fingerprint(self._identity.fingerprint())}"
            )
            return False

    async def connect(self, relay_url: str = DEFAULT_RELAY_URL) -> None:
        """
        Подключиться к Relay Server.

        Args:
            relay_url: URL relay-сервера.
        """
        if not self.is_initialized:
            raise PQCError("Приложение не инициализировано")

        await self._transport.connect(relay_url)
        await self._transport.register(self.identity_hash)  # type: ignore[arg-type]

        # Запускаем обработку входящих сообщений
        asyncio.create_task(self._process_incoming())

        logger.info(f"Подключено к relay: {relay_url}")

    def add_contact(
        self,
        x25519_pub_hex: str,
        kyber_pub_hex: str,
        display_name: str = "",
    ) -> Contact:
        """
        Добавить контакт по публичным ключам.

        Args:
            x25519_pub_hex: X25519 публичный ключ (hex).
            kyber_pub_hex: Kyber публичный ключ (hex).
            display_name: Отображаемое имя.

        Returns:
            Добавленный Contact.
        """
        x25519_pub = bytes.fromhex(x25519_pub_hex)
        kyber_pub = bytes.fromhex(kyber_pub_hex)

        contact_id = Identity.compute_id(x25519_pub, kyber_pub)

        return self._db.add_contact(
            contact_id=contact_id,
            x25519_pub=x25519_pub,
            kyber_pub=kyber_pub,
            display_name=display_name,
        )

    def get_contacts(self) -> list[Contact]:
        """Получить список контактов."""
        return self._db.get_all_contacts()

    async def start_session(self, contact_id: str) -> None:
        """
        Начать сессию с контактом (отправить Handshake INIT).

        Сессия будет создана после получения HANDSHAKE_RESP.

        Args:
            contact_id: ID контакта.
        """
        if not self.is_initialized:
            raise PQCError("Приложение не инициализировано")

        contact = self._db.get_contact(contact_id)
        if contact is None:
            raise SessionError(f"Контакт {contact_id[:16]}... не найден")

        # Создаём HANDSHAKE_INIT
        init_msg, init_secret = Handshake.create_init(
            initiator=self._identity,  # type: ignore[arg-type]
            responder_x25519_pub=contact.x25519_public_key,
            responder_kyber_pub=contact.kyber_public_key,
        )

        # Отправляем через relay
        recipient_hash = Identity.compute_hash(
            contact.x25519_public_key,
            contact.kyber_public_key,
        )

        packet = Packet(
            packet_type=PacketType.HANDSHAKE_INIT,
            recipient_hash=recipient_hash,
            payload=init_msg.serialize(),
        )

        await self._transport.send_packet(packet)
        logger.info(f"HANDSHAKE_INIT отправлен контакту {contact_id[:16]}...")

        # Сохраняем состояние ожидания; сессия будет создана в _handle_handshake_resp
        self._pending_handshakes[contact_id] = (
            init_secret,
            contact.x25519_public_key,
            contact.kyber_public_key,
        )

    async def send_message(self, contact_id: str, text: str) -> None:
        """
        Отправить сообщение контакту.

        Args:
            contact_id: ID контакта.
            text: Текст сообщения.
        """
        session = self._sessions.get(contact_id)
        if session is None:
            # Инициируем handshake, если ещё не начат
            if contact_id not in self._pending_handshakes:
                await self.start_session(contact_id)

            # Ожидаем завершения handshake (до ~5 секунд)
            for _ in range(50):
                await asyncio.sleep(0.1)
                session = self._sessions.get(contact_id)
                if session is not None:
                    break

            if session is None:
                raise SessionError(
                    "Таймаут ожидания завершения Handshake. "
                    "Убедитесь, что собеседник онлайн."
                )

        # Шифруем и отправляем
        packet = session.send_message(text)
        await self._transport.send_packet(packet)

        # Сохраняем в БД (зашифровано на мастер-ключе)
        encrypted_for_storage = AEAD.encrypt(
            self._keystore._master_key,  # type: ignore[arg-type]
            text.encode("utf-8"),
        )
        self._db.store_message(contact_id, "sent", encrypted_for_storage)

        # Сохраняем состояние ratchet
        self._persist_session(session)

        logger.info(f"Сообщение отправлено → {contact_id[:16]}...")

    def get_messages(self, contact_id: str, limit: int = 100) -> list[Message]:
        """
        Получить историю сообщений с контактом.

        Args:
            contact_id: ID контакта.
            limit: Максимальное количество сообщений.

        Returns:
            Список расшифрованных Message.
        """
        if self._keystore._master_key is None:
            raise StorageError("Хранилище не разблокировано")

        raw_messages = self._db.get_messages(contact_id, limit)
        messages = []

        for msg_id, direction, encrypted_content, timestamp in raw_messages:
            try:
                content = AEAD.decrypt(
                    self._keystore._master_key,
                    encrypted_content,
                ).decode("utf-8")

                messages.append(Message(
                    id=msg_id,
                    contact_id=contact_id,
                    direction=direction,
                    content=content,
                    timestamp=timestamp,
                ))
            except Exception as e:
                logger.error(f"Ошибка расшифрования сообщения {msg_id}: {e}")

        return messages

    async def _process_incoming(self) -> None:
        """Фоновая обработка входящих пакетов."""
        try:
            async for packet in self._transport.receive_packets():
                await self._handle_packet(packet)
        except Exception as e:
            logger.error(f"Ошибка обработки входящих: {e}")

    async def _handle_packet(self, packet: Packet) -> None:
        """Обработать входящий пакет."""
        if packet.packet_type == PacketType.HANDSHAKE_INIT:
            await self._handle_handshake_init(packet)
        elif packet.packet_type == PacketType.HANDSHAKE_RESP:
            await self._handle_handshake_resp(packet)
        elif packet.packet_type == PacketType.MESSAGE:
            await self._handle_message(packet)
        else:
            logger.warning(f"Неизвестный тип пакета: {packet.packet_type}")

    async def _handle_handshake_init(self, packet: Packet) -> None:
        """Обработать входящий HANDSHAKE_INIT."""
        from pqc_messenger.protocol.handshake import HandshakeInitMessage

        try:
            init_msg = HandshakeInitMessage.deserialize(packet.payload)
            resp_msg, shared_secret = Handshake.process_init(
                responder=self._identity,  # type: ignore[arg-type]
                init_msg=init_msg,
            )

            # Определяем contact_id
            contact_id = Identity.compute_id(
                init_msg.initiator_x25519_pub,
                init_msg.initiator_kyber_pub,
            )

            # Создаём сессию как респондент
            # Используем identity X25519 как начальный DH ключ (initiator знает его)
            ratchet = SessionRatchet.initialize_as_responder(
                shared_secret=shared_secret,
                own_dh_keypair=self._identity.x25519,  # type: ignore[union-attr]
                remote_dh_public=init_msg.initiator_x25519_pub,
            )

            session = Session.create(
                contact_id=contact_id,
                contact_x25519_pub=init_msg.initiator_x25519_pub,
                contact_kyber_pub=init_msg.initiator_kyber_pub,
                ratchet=ratchet,
            )
            self._sessions[contact_id] = session

            # Отправляем HANDSHAKE_RESP
            recipient_hash = Identity.compute_hash(
                init_msg.initiator_x25519_pub,
                init_msg.initiator_kyber_pub,
            )
            resp_packet = Packet(
                packet_type=PacketType.HANDSHAKE_RESP,
                recipient_hash=recipient_hash,
                payload=resp_msg.serialize(),
            )
            await self._transport.send_packet(resp_packet)

            logger.info(f"Handshake принят от {contact_id[:16]}...")

            # Уведомляем callback
            if self._message_callback:
                self._message_callback("system", f"Новая сессия с {contact_id[:16]}...")

        except Exception as e:
            logger.error(f"Ошибка обработки HANDSHAKE_INIT: {e}")

    async def _handle_handshake_resp(self, packet: Packet) -> None:
        """Обработать входящий HANDSHAKE_RESP (сторона инициатора)."""
        from pqc_messenger.protocol.handshake import HandshakeRespMessage

        try:
            resp_msg = HandshakeRespMessage.deserialize(packet.payload)

            # Определяем contact_id по публичным ключам респондента
            contact_id = Identity.compute_id(
                resp_msg.responder_x25519_pub,
                resp_msg.responder_kyber_pub,
            )

            # Ищем ожидающий handshake
            pending = self._pending_handshakes.pop(contact_id, None)
            if pending is None:
                logger.warning(
                    f"Получен HANDSHAKE_RESP для неизвестного handshake: "
                    f"{contact_id[:16]}..."
                )
                return

            init_secret, contact_x25519_pub, contact_kyber_pub = pending

            # Завершаем handshake → получаем финальный секрет
            final_secret = Handshake.complete_handshake(
                initiator=self._identity,  # type: ignore[arg-type]
                init_shared_secret=init_secret,
                resp_msg=resp_msg,
            )

            # Создаём сессию с правильным финальным секретом
            ratchet = SessionRatchet.initialize_as_initiator(
                shared_secret=final_secret,
                own_dh_keypair=self._identity.x25519,  # type: ignore[union-attr]
                remote_dh_public=contact_x25519_pub,
            )

            session = Session.create(
                contact_id=contact_id,
                contact_x25519_pub=contact_x25519_pub,
                contact_kyber_pub=contact_kyber_pub,
                ratchet=ratchet,
            )
            self._sessions[contact_id] = session
            self._persist_session(session)

            logger.info(f"Handshake завершён с {contact_id[:16]}...")

            # Уведомляем callback
            if self._message_callback:
                self._message_callback(
                    "system", f"Сессия установлена с {contact_id[:16]}..."
                )

        except Exception as e:
            logger.error(f"Ошибка обработки HANDSHAKE_RESP: {e}")

    async def _handle_message(self, packet: Packet) -> None:
        """Обработать входящее сообщение."""
        # Первые 32 байта payload в формате ratchet — DH public key отправителя.
        # Используем его для точного поиска сессии, не допуская
        # «порчи» чужого ratchet при неудачной попытке расшифровки.
        if len(packet.payload) < 36:
            logger.warning("Слишком короткий payload MESSAGE пакета")
            return

        sender_dh_pub = packet.payload[:32]

        # Сначала ищем по точному совпадению remote_dh_public или identity pub контакта
        target_contact_id = None
        for contact_id, session in self._sessions.items():
            r = session.ratchet
            if (r.remote_dh_public == sender_dh_pub or
                    session.contact_x25519_pub == sender_dh_pub):
                target_contact_id = contact_id
                break

        if target_contact_id is None:
            logger.warning("Не удалось найти сессию для входящего сообщения")
            return

        session = self._sessions[target_contact_id]
        try:
            text = session.receive_message(packet)

            # Сохраняем в БД
            encrypted_for_storage = AEAD.encrypt(
                self._keystore._master_key,  # type: ignore[arg-type]
                text.encode("utf-8"),
            )
            self._db.store_message(target_contact_id, "received", encrypted_for_storage)

            self._persist_session(session)

            logger.info(f"Сообщение получено от {target_contact_id[:16]}...")

            if self._message_callback:
                self._message_callback(target_contact_id, text)

        except Exception as e:
            logger.error(
                f"Ошибка расшифрования сообщения от {target_contact_id[:16]}...: {e}"
            )

    def _persist_session(self, session: Session) -> None:
        """Сохранить состояние сессии в хранилище."""
        try:
            ratchet_state = session.ratchet.serialize()
            self._keystore.store_session_state(session.session_id, ratchet_state)
            self._db.store_session(
                session.session_id,
                session.contact_id,
                ratchet_state,
            )
        except Exception as e:
            logger.error(f"Ошибка сохранения сессии: {e}")

    def set_message_callback(self, callback) -> None:
        """Установить callback для обработки входящих сообщений."""
        self._message_callback = callback

    async def wipe_all(self) -> None:
        """
        Полное удаление всех данных.

        Удаляет: ключи, сообщения, контакты, сессии.
        """
        # Уничтожаем активные сессии
        for session in self._sessions.values():
            session.destroy()
        self._sessions.clear()

        # Отключаемся от relay
        if self._transport.is_connected:
            await self._transport.disconnect()

        # Очищаем хранилища
        self._db.wipe_all()
        self._keystore.wipe()
        self._identity = None

        logger.warning("Все данные полностью уничтожены (WIPE)")

    def shutdown(self) -> None:
        """Корректное завершение работы."""
        for session in self._sessions.values():
            self._persist_session(session)

        self._db.close()
        self._keystore.close()
        logger.info("Приложение завершено")
