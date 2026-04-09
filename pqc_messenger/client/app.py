"""
Главная логика клиентского приложения PQC-Messenger.

Координирует работу всех модулей: криптографию, протокол, сеть, хранилище.
"""

from __future__ import annotations

import asyncio
import os

from pqc_messenger.common.constants import (
    DEFAULT_DATA_DIR,
    DEFAULT_RELAY_URL,
    SESSION_TTL,
)
from pqc_messenger.common.exceptions import (
    CryptoError,
    PQCError,
    SessionError,
    StorageError,
)
from pqc_messenger.common.logging import get_logger
from pqc_messenger.crypto.identity import Identity
from pqc_messenger.crypto.keys import IdentityKeyBundle, _HAS_LIBOQS  # noqa: PLC2701
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
        self._db       = Database(data_dir)
        self._keystore = KeyStore(data_dir)
        self._transport = Transport()
        self._identity: IdentityKeyBundle | None = None
        self._sessions: dict[str, Session] = {}
        self._pending_handshakes: dict[str, tuple[bytes, bytes, bytes]] = {}
        # Сообщения, ожидающие завершения handshake (получатель был офлайн)
        self._pending_messages: dict[str, list[str]] = {}
        self._message_callback = None
        # Пункт 8: предупреждение о Kyber-эмуляции выводится один раз
        self._kyber_warning_shown = False

    # ── Свойства ──────────────────────────────────────────────────────────────

    @property
    def identity(self) -> IdentityKeyBundle | None:
        return self._identity

    @property
    def identity_id(self) -> str | None:
        if self._identity:
            return self._identity.fingerprint()
        return None

    @property
    def identity_hash(self) -> str | None:
        if self._identity:
            return Identity.compute_id(
                self._identity.x25519.serialize_public(),
                self._identity.kyber.public_key,
            )
        return None

    @property
    def is_initialized(self) -> bool:
        return self._identity is not None

    @property
    def is_connected(self) -> bool:
        return self._transport.is_connected

    @property
    def kyber_is_real(self) -> bool:
        """True если используется настоящий Kyber-768 (liboqs), False = эмуляция."""
        return bool(_HAS_LIBOQS)

    # ── Инициализация ─────────────────────────────────────────────────────────

    def initialize(self, password: str) -> bool:
        """
        Инициализировать приложение.

        Returns:
            True — создана новая идентичность.

        Raises:
            CryptoError: Неверный пароль.
            StorageError: Повреждённое хранилище.
        """
        self._db.initialize()
        is_new = self._keystore.initialize(password)  # raises CryptoError / StorageError

        if is_new:
            self._identity = IdentityKeyBundle.generate()
            self._keystore.store_identity(self._identity)
            logger.info(
                "Новая идентичность создана: %s",
                Identity.format_fingerprint(self._identity.fingerprint()),
            )
        else:
            self._identity = self._keystore.load_identity()
            if self._identity is None:
                self._identity = IdentityKeyBundle.generate()
                self._keystore.store_identity(self._identity)
                is_new = True
            else:
                logger.info(
                    "Идентичность загружена: %s",
                    Identity.format_fingerprint(self._identity.fingerprint()),
                )
                # Восстанавливаем сохранённые сессии из БД
                self._restore_sessions()

        # Пункт 4: удаляем истёкшие сессии
        expired = self._db.delete_expired_sessions(SESSION_TTL)
        if expired:
            logger.info("Удалено %d истёкших сессий при запуске", expired)

        # Пункт 8: предупреждение об эмуляции Kyber
        if not _HAS_LIBOQS and not self._kyber_warning_shown:
            self._kyber_warning_shown = True
            msg = (
                "ВНИМАНИЕ: liboqs не найден — Kyber-768 работает в режиме ЭМУЛЯЦИИ "
                "через X25519+HKDF. Постквантовая защита НЕ активна. "
                "Для полной защиты установите liboqs-python."
            )
            logger.warning(msg)
            if self._message_callback:
                self._message_callback("system", "⚠ " + msg)

        return is_new

    def _restore_sessions(self) -> None:
        """Восстановить активные сессии из БД при запуске."""
        if not self._keystore.is_unlocked:
            return
        try:
            rows = self._db.get_all_sessions()
            for session_id, contact_id, ratchet_state_raw, last_activity in rows:
                try:
                    # ratchet_state в БД хранится незашифрованным (keystore хранит отдельно)
                    # Пробуем загрузить из keystore (зашифровано)
                    state_bytes = self._keystore.load_session_state(session_id)
                    if state_bytes is None:
                        # Fallback: используем данные из БД напрямую
                        state_bytes = ratchet_state_raw

                    ratchet = SessionRatchet.deserialize(state_bytes)
                    contact = self._db.get_contact(contact_id)
                    if contact is None:
                        continue

                    session = Session(
                        session_id=session_id,
                        contact_id=contact_id,
                        contact_x25519_pub=contact.x25519_public_key,
                        contact_kyber_pub=contact.kyber_public_key,
                        ratchet=ratchet,
                        last_activity=last_activity,
                    )
                    self._sessions[contact_id] = session
                    logger.debug("Сессия восстановлена для %s...", contact_id[:16])
                except Exception as e:
                    logger.warning(
                        "Не удалось восстановить сессию %s: %s", session_id[:8], e
                    )
            if self._sessions:
                logger.info("Восстановлено %d сессий из хранилища", len(self._sessions))
        except Exception as e:
            logger.error("Ошибка восстановления сессий: %s", e)

    # ── Подключение ───────────────────────────────────────────────────────────

    async def connect(self, relay_url: str = DEFAULT_RELAY_URL) -> None:
        if not self.is_initialized:
            raise PQCError("Приложение не инициализировано")

        # Пункт 1: регистрируем callback переподключения
        self._transport.set_reconnect_callback(self._on_reconnected)

        await self._transport.connect(relay_url)
        await self._transport.register(self.identity_hash)  # type: ignore[arg-type]

        asyncio.create_task(self._process_incoming())
        logger.info("Подключено к relay: %s", relay_url)

    async def _on_reconnected(self) -> None:
        """
        Пункт 1: вызывается транспортом после успешного переподключения.
        Уведомляем пользователя.
        """
        logger.info("Переподключение к relay выполнено успешно")
        if self._message_callback:
            self._message_callback("system", "Связь с relay восстановлена")

    # ── Контакты ──────────────────────────────────────────────────────────────

    def add_contact(
        self,
        x25519_pub_hex: str,
        kyber_pub_hex: str,
        display_name: str = "",
    ) -> Contact:
        x25519_pub = bytes.fromhex(x25519_pub_hex)
        kyber_pub  = bytes.fromhex(kyber_pub_hex)
        contact_id = Identity.compute_id(x25519_pub, kyber_pub)
        return self._db.add_contact(
            contact_id=contact_id,
            x25519_pub=x25519_pub,
            kyber_pub=kyber_pub,
            display_name=display_name,
        )

    def delete_contact(self, contact_id: str) -> None:
        """
        Пункт 7: удалить контакт, все сообщения и сессию с ним.
        """
        # Уничтожаем активную сессию если есть
        session = self._sessions.pop(contact_id, None)
        if session:
            session.destroy()

        self._db.delete_contact(contact_id)
        logger.info("Контакт %s... удалён", contact_id[:16])

    def get_contacts(self) -> list[Contact]:
        return self._db.get_all_contacts()

    # ── Сессии ────────────────────────────────────────────────────────────────

    async def start_session(self, contact_id: str) -> None:
        if not self.is_initialized:
            raise PQCError("Приложение не инициализировано")

        contact = self._db.get_contact(contact_id)
        if contact is None:
            raise SessionError(f"Контакт {contact_id[:16]}... не найден")

        init_msg, init_secret = Handshake.create_init(
            initiator=self._identity,  # type: ignore[arg-type]
            responder_x25519_pub=contact.x25519_public_key,
            responder_kyber_pub=contact.kyber_public_key,
        )

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
        logger.info("HANDSHAKE_INIT отправлен контакту %s...", contact_id[:16])

        self._pending_handshakes[contact_id] = (
            init_secret,
            contact.x25519_public_key,
            contact.kyber_public_key,
        )

    # ── Сообщения ─────────────────────────────────────────────────────────────

    async def send_message(self, contact_id: str, text: str) -> None:
        session = self._sessions.get(contact_id)
        if session is None:
            # Инициируем handshake если ещё не начат.
            # HANDSHAKE_INIT уйдёт в mailbox получателя даже если он офлайн.
            if contact_id not in self._pending_handshakes:
                await self.start_session(contact_id)

            # Ждём до 2 сек: если получатель онлайн, handshake завершится быстро
            for _ in range(20):
                await asyncio.sleep(0.1)
                session = self._sessions.get(contact_id)
                if session is not None:
                    break

            if session is None:
                # Получатель офлайн — откладываем сообщение.
                # Оно будет автоматически отправлено в _handle_handshake_resp,
                # когда получатель подключится и завершит handshake.
                self._pending_messages.setdefault(contact_id, []).append(text)
                logger.info(
                    "Получатель офлайн — сообщение отложено для %s...",
                    contact_id[:16],
                )
                if self._message_callback:
                    self._message_callback(
                        "system",
                        "Собеседник офлайн. Сообщение будет доставлено при его подключении.",
                    )
                return

        await self._send_packet_and_store(session, contact_id, text)

    async def _send_packet_and_store(
        self, session: "Session", contact_id: str, text: str
    ) -> None:
        """Зашифровать, отправить пакет и сохранить в БД."""
        packet = session.send_message(text)
        await self._transport.send_packet(packet)
        encrypted_for_storage = self._keystore.encrypt_for_storage(
            text.encode("utf-8")
        )
        self._db.store_message(contact_id, "sent", encrypted_for_storage)
        self._persist_session(session)
        logger.info("Сообщение отправлено → %s...", contact_id[:16])

    def get_messages(self, contact_id: str, limit: int = 100) -> list[Message]:
        if not self._keystore.is_unlocked:
            raise StorageError("Хранилище не разблокировано")

        raw_messages = self._db.get_messages(contact_id, limit)
        messages = []
        for msg_id, direction, encrypted_content, timestamp in raw_messages:
            try:
                # Пункт 6: decrypt_from_storage вместо _master_key
                content = self._keystore.decrypt_from_storage(
                    encrypted_content
                ).decode("utf-8")
                messages.append(Message(
                    id=msg_id,
                    contact_id=contact_id,
                    direction=direction,
                    content=content,
                    timestamp=timestamp,
                ))
            except Exception as e:
                logger.error("Ошибка расшифрования сообщения %d: %s", msg_id, e)

        return messages

    # ── Обработка входящих ────────────────────────────────────────────────────

    async def _process_incoming(self) -> None:
        try:
            async for packet in self._transport.receive_packets():
                await self._handle_packet(packet)
        except Exception as e:
            logger.error("Ошибка обработки входящих: %s", e)

    async def _handle_packet(self, packet: Packet) -> None:
        if packet.packet_type == PacketType.HANDSHAKE_INIT:
            await self._handle_handshake_init(packet)
        elif packet.packet_type == PacketType.HANDSHAKE_RESP:
            await self._handle_handshake_resp(packet)
        elif packet.packet_type == PacketType.MESSAGE:
            await self._handle_message(packet)
        else:
            logger.warning("Неизвестный тип пакета: %s", packet.packet_type)

    async def _handle_handshake_init(self, packet: Packet) -> None:
        from pqc_messenger.protocol.handshake import HandshakeInitMessage
        try:
            init_msg = HandshakeInitMessage.deserialize(packet.payload)
            resp_msg, shared_secret = Handshake.process_init(
                responder=self._identity,  # type: ignore[arg-type]
                init_msg=init_msg,
            )
            contact_id = Identity.compute_id(
                init_msg.initiator_x25519_pub,
                init_msg.initiator_kyber_pub,
            )

            if contact_id in self._sessions:
                logger.info(
                    "Сессия с %s... уже существует, HANDSHAKE_INIT проигнорирован",
                    contact_id[:16],
                )
                recipient_hash = Identity.compute_hash(
                    init_msg.initiator_x25519_pub,
                    init_msg.initiator_kyber_pub,
                )
                await self._transport.send_packet(Packet(
                    packet_type=PacketType.HANDSHAKE_RESP,
                    recipient_hash=recipient_hash,
                    payload=resp_msg.serialize(),
                ))
                return

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

            recipient_hash = Identity.compute_hash(
                init_msg.initiator_x25519_pub,
                init_msg.initiator_kyber_pub,
            )
            await self._transport.send_packet(Packet(
                packet_type=PacketType.HANDSHAKE_RESP,
                recipient_hash=recipient_hash,
                payload=resp_msg.serialize(),
            ))
            logger.info("Handshake принят от %s...", contact_id[:16])
            if self._message_callback:
                self._message_callback("system", f"Новая сессия с {contact_id[:16]}...")

        except Exception as e:
            logger.error("Ошибка обработки HANDSHAKE_INIT: %s", e)

    async def _handle_handshake_resp(self, packet: Packet) -> None:
        from pqc_messenger.protocol.handshake import HandshakeRespMessage
        try:
            resp_msg   = HandshakeRespMessage.deserialize(packet.payload)
            contact_id = Identity.compute_id(
                resp_msg.responder_x25519_pub,
                resp_msg.responder_kyber_pub,
            )
            pending = self._pending_handshakes.pop(contact_id, None)
            if pending is None:
                logger.warning(
                    "Получен HANDSHAKE_RESP для неизвестного handshake: %s...",
                    contact_id[:16],
                )
                return

            init_secret, contact_x25519_pub, contact_kyber_pub = pending
            final_secret = Handshake.complete_handshake(
                initiator=self._identity,  # type: ignore[arg-type]
                init_shared_secret=init_secret,
                resp_msg=resp_msg,
            )
            ratchet = SessionRatchet.initialize_as_initiator(
                shared_secret=final_secret,
                own_dh_keypair=self._identity.x25519,  # type: ignore[union-attr]
                remote_dh_public=contact_x25519_pub,
            )
            if contact_id not in self._sessions:
                session = Session.create(
                    contact_id=contact_id,
                    contact_x25519_pub=contact_x25519_pub,
                    contact_kyber_pub=contact_kyber_pub,
                    ratchet=ratchet,
                )
                self._sessions[contact_id] = session
                self._persist_session(session)

            logger.info("Handshake завершён с %s...", contact_id[:16])
            if self._message_callback:
                self._message_callback("system", f"Сессия установлена с {contact_id[:16]}...")

            # Отправляем сообщения, накопленные пока получатель был офлайн
            queued = self._pending_messages.pop(contact_id, [])
            if queued:
                logger.info(
                    "Отправка %d отложенных сообщений → %s...",
                    len(queued), contact_id[:16],
                )
                session = self._sessions[contact_id]
                for queued_text in queued:
                    try:
                        await self._send_packet_and_store(session, contact_id, queued_text)
                    except Exception as e:
                        logger.error("Ошибка доставки отложенного сообщения: %s", e)
                if self._message_callback:
                    self._message_callback(
                        "system",
                        f"Доставлено {len(queued)} отложенных сообщений.",
                    )

        except Exception as e:
            logger.error("Ошибка обработки HANDSHAKE_RESP: %s", e)

    async def _handle_message(self, packet: Packet) -> None:
        if len(packet.payload) < 36:
            logger.warning("Слишком короткий payload MESSAGE пакета")
            return

        sender_dh_pub     = packet.payload[:32]
        target_contact_id = None

        for contact_id, session in self._sessions.items():
            r = session.ratchet
            if (r.remote_dh_public == sender_dh_pub
                    or session.contact_x25519_pub == sender_dh_pub):
                target_contact_id = contact_id
                break

        if target_contact_id is None:
            if len(self._sessions) == 1:
                target_contact_id = next(iter(self._sessions))
            else:
                logger.warning(
                    "Не удалось найти сессию для входящего сообщения "
                    "(несколько активных сессий, DH pub не совпал ни с одной)"
                )
                return

        session = self._sessions[target_contact_id]
        try:
            text = session.receive_message(packet)

            # Пункт 6: encrypt_for_storage вместо _master_key
            encrypted_for_storage = self._keystore.encrypt_for_storage(
                text.encode("utf-8")
            )
            self._db.store_message(target_contact_id, "received", encrypted_for_storage)
            self._persist_session(session)
            logger.info("Сообщение получено от %s...", target_contact_id[:16])

            if self._message_callback:
                self._message_callback(target_contact_id, text)

        except Exception as e:
            logger.error(
                "Ошибка расшифрования сообщения от %s...: %s",
                target_contact_id[:16], e,
            )

    def _persist_session(self, session: Session) -> None:
        try:
            ratchet_state = session.ratchet.serialize()
            self._keystore.store_session_state(session.session_id, ratchet_state)
            self._db.store_session(
                session.session_id,
                session.contact_id,
                ratchet_state,
            )
        except Exception as e:
            logger.error("Ошибка сохранения сессии: %s", e)

    def set_message_callback(self, callback) -> None:
        self._message_callback = callback

    # ── Очистка ───────────────────────────────────────────────────────────────

    async def wipe_all(self) -> None:
        """
        Полное уничтожение всех данных приложения.
        """
        for session in self._sessions.values():
            session.destroy()
        self._sessions.clear()
        if self._transport.is_connected:
            await self._transport.disconnect()
        self._db.wipe_all()
        self._keystore.wipe()
        self._identity = None

        # Попытка удалить директорию данных, если она пуста
        if os.path.exists(self._data_dir) and not os.listdir(self._data_dir):
            try:
                os.rmdir(self._data_dir)
                logger.info("Директория данных удалена: %s", self._data_dir)
            except Exception as e:
                logger.error("Не удалось удалить директорию данных: %s", e)

        logger.warning("Все данные полностью уничтожены (WIPE)")

    def shutdown(self) -> None:
        # Пункт 4: удаляем истёкшие сессии при завершении
        self._db.delete_expired_sessions(SESSION_TTL)
        for session in self._sessions.values():
            self._persist_session(session)
        self._db.close()
        self._keystore.close()
        logger.info("Приложение завершено")
