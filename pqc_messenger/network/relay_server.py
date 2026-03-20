"""
Relay Server — «слепой» ретранслятор сообщений.

Принцип работы (Mailbox):
- Клиенты подключаются по WebSocket и регистрируются по хешу своего ID
- Relay маршрутизирует пакеты по recipient_hash, не зная реальных ID
- Если получатель офлайн, пакеты сохраняются в очереди (mailbox)
- Relay не имеет доступа к ключам шифрования и не может расшифровать данные

Безопасность:
- Сервер видит только хеши и зашифрованные blob-ы
- Нет логирования метаданных отправителя
- Временные данные удаляются при отключении клиента
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from collections import defaultdict

from pqc_messenger.common.constants import (
    DEFAULT_RELAY_HOST,
    DEFAULT_RELAY_PORT,
    MAILBOX_MAX_SIZE,
    WS_MAX_MESSAGE_SIZE,
    WS_PING_INTERVAL,
    WS_PING_TIMEOUT,
)
from pqc_messenger.common.logging import get_logger, setup_logging
from pqc_messenger.network.messages import MessageType, RelayMessage

logger = get_logger("network.relay")

try:
    import websockets
    from websockets.asyncio.server import serve, ServerConnection
except ImportError:
    websockets = None  # type: ignore[assignment]


class RelayServer:
    """
    «Слепой» Relay-сервер для маршрутизации зашифрованных пакетов.

    Атрибуты:
        host: Адрес для прослушивания.
        port: Порт для прослушивания.
        connections: Активные WebSocket-подключения (hash → connection).
        mailboxes: Очереди сообщений для офлайн-получателей.
    """

    def __init__(
        self,
        host: str = DEFAULT_RELAY_HOST,
        port: int = DEFAULT_RELAY_PORT,
    ) -> None:
        self.host = host
        self.port = port
        self.connections: dict[str, ServerConnection] = {}
        self.mailboxes: dict[str, asyncio.Queue] = defaultdict(
            lambda: asyncio.Queue(maxsize=MAILBOX_MAX_SIZE)
        )
        self._stats = {"total_messages": 0, "total_connections": 0}

    async def handle_connection(self, websocket: ServerConnection) -> None:
        """
        Обработать подключение клиента.

        Протокол:
        1. Клиент отправляет REGISTER с sender_hash
        2. Relay доставляет накопленные сообщения из mailbox
        3. Дальше relay пересылает SEND → DELIVER
        """
        client_hash: str | None = None

        try:
            async for raw_message in websocket:
                if isinstance(raw_message, bytes):
                    raw_message = raw_message.decode("utf-8")

                try:
                    msg = RelayMessage.from_json(raw_message)
                except Exception as e:
                    error_resp = RelayMessage.create_error(f"Ошибка формата: {e}")
                    await websocket.send(error_resp.to_json())
                    continue

                if msg.type == MessageType.REGISTER:
                    client_hash = await self._handle_register(
                        websocket, msg.sender_hash
                    )

                elif msg.type == MessageType.SEND:
                    await self._handle_send(msg)

                elif msg.type == MessageType.PING:
                    pong = RelayMessage(type=MessageType.PONG)
                    await websocket.send(pong.to_json())

                elif msg.type == MessageType.UNREGISTER:
                    break

        except websockets.exceptions.ConnectionClosed:  # type: ignore[union-attr]
            logger.debug(f"Клиент отключился: {client_hash or 'unknown'}")
        finally:
            if client_hash and client_hash in self.connections:
                del self.connections[client_hash]
                logger.info(f"Клиент удалён: {client_hash[:16]}...")

    async def _handle_register(
        self,
        websocket: ServerConnection,
        sender_hash: str,
    ) -> str:
        """Зарегистрировать клиента и доставить накопленные сообщения."""
        self.connections[sender_hash] = websocket
        self._stats["total_connections"] += 1
        logger.info(
            f"Клиент зарегистрирован: {sender_hash[:16]}... "
            f"(всего: {len(self.connections)})"
        )

        # Подтверждение регистрации — ОБЯЗАТЕЛЬНО до mailbox,
        # иначе клиент получит DELIVER раньше ACK и упадёт с ошибкой
        # в transport.register() при ожидании подтверждения.
        ack = RelayMessage.ack("register")
        await websocket.send(ack.to_json())

        # Доставить накопленные сообщения из mailbox
        if sender_hash in self.mailboxes:
            mailbox = self.mailboxes[sender_hash]
            delivered = 0
            while not mailbox.empty():
                queued_msg = await mailbox.get()
                try:
                    await websocket.send(queued_msg)
                    delivered += 1
                except Exception:
                    await mailbox.put(queued_msg)
                    break
            if delivered:
                logger.info(f"Доставлено {delivered} накопленных сообщений для {sender_hash[:16]}...")

        return sender_hash

    async def _handle_send(self, msg: RelayMessage) -> None:
        """Маршрутизировать пакет к получателю или в mailbox."""
        self._stats["total_messages"] += 1
        recipient_hash = msg.recipient_hash

        # Формируем DELIVER для получателя
        deliver_msg = RelayMessage.deliver(
            recipient_hash=recipient_hash,
            payload=msg.payload,
            message_id=msg.message_id,
        )
        deliver_json = deliver_msg.to_json()

        if recipient_hash in self.connections:
            # Получатель онлайн — доставляем напрямую
            try:
                await self.connections[recipient_hash].send(deliver_json)
                logger.debug(f"Пакет доставлен: → {recipient_hash[:16]}...")
            except Exception:
                # Подключение сломано, кладём в mailbox
                logger.warning(f"Ошибка доставки, кладём в mailbox: {recipient_hash[:16]}...")
                del self.connections[recipient_hash]
                await self._enqueue_to_mailbox(recipient_hash, deliver_json)
        else:
            # Получатель офлайн — сохраняем в mailbox
            await self._enqueue_to_mailbox(recipient_hash, deliver_json)
            logger.debug(f"Пакет в mailbox: → {recipient_hash[:16]}...")

    async def _enqueue_to_mailbox(
        self,
        recipient_hash: str,
        message: str,
    ) -> None:
        """Поставить сообщение в очередь mailbox."""
        mailbox = self.mailboxes[recipient_hash]
        try:
            mailbox.put_nowait(message)
        except asyncio.QueueFull:
            # Mailbox переполнен — удаляем самое старое сообщение
            logger.warning(f"Mailbox переполнен для {recipient_hash[:16]}..., удаляем старые")
            try:
                mailbox.get_nowait()
            except asyncio.QueueEmpty:
                pass
            mailbox.put_nowait(message)

    async def start(self) -> None:
        """Запустить Relay Server."""
        if websockets is None:
            logger.error(
                "Библиотека websockets не установлена. "
                "Установите: pip install websockets"
            )
            return

        logger.info(f"Relay Server запущен на ws://{self.host}:{self.port}")
        logger.info("Режим: «слепой» Mailbox (без доступа к содержимому)")

        async with serve(
            self.handle_connection,
            self.host,
            self.port,
            ping_interval=WS_PING_INTERVAL,
            ping_timeout=WS_PING_TIMEOUT,
            max_size=WS_MAX_MESSAGE_SIZE,
        ):
            await asyncio.get_event_loop().create_future()  # Работать бесконечно


def main() -> None:
    """Точка входа для запуска Relay Server из командной строки."""
    parser = argparse.ArgumentParser(
        description="PQC-Messenger Relay Server (Blind Mailbox)"
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_RELAY_HOST,
        help=f"Адрес для прослушивания (default: {DEFAULT_RELAY_HOST})",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_RELAY_PORT,
        help=f"Порт (default: {DEFAULT_RELAY_PORT})",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Включить отладочное логирование",
    )

    args = parser.parse_args()

    level = logging.DEBUG if args.debug else logging.INFO
    setup_logging(level)

    server = RelayServer(host=args.host, port=args.port)

    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        logger.info("Relay Server остановлен")
        sys.exit(0)


if __name__ == "__main__":
    main()
