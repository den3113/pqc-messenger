"""
Relay Server — «слепой» ретранслятор сообщений с rate limiting.

Пункт 5: каждый клиент ограничен RATE_LIMIT_MAX_MSGS сообщениями
за RATE_LIMIT_WINDOW секунд. При превышении — пакет отбрасывается
с ответом ERROR (без блокировки соединения).
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
import time
from collections import defaultdict, deque

from pqc_messenger.common.constants import (
    DEFAULT_RELAY_HOST,
    DEFAULT_RELAY_PORT,
    MAILBOX_MAX_SIZE,
    RATE_LIMIT_MAX_MSGS,
    RATE_LIMIT_WINDOW,
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


class RateLimiter:
    """
    Пункт 5: скользящее окно rate limiting на отправку SEND-пакетов.

    Хранит timestamp'ы последних сообщений для каждого hash-клиента.
    Старые записи вытесняются автоматически при проверке.
    """

    def __init__(
        self,
        window: float = RATE_LIMIT_WINDOW,
        max_msgs: int = RATE_LIMIT_MAX_MSGS,
    ) -> None:
        self._window   = window
        self._max_msgs = max_msgs
        # hash → deque of timestamps
        self._buckets: dict[str, deque[float]] = defaultdict(deque)

    def is_allowed(self, client_id: str) -> bool:
        """Вернуть True если клиент не превысил лимит, иначе False."""
        now    = time.monotonic()
        bucket = self._buckets[client_id]

        # Выбрасываем устаревшие записи
        cutoff = now - self._window
        while bucket and bucket[0] < cutoff:
            bucket.popleft()

        if len(bucket) >= self._max_msgs:
            return False

        bucket.append(now)
        return True

    def cleanup(self) -> None:
        """Удалить пустые корзины (вызывать периодически)."""
        empty = [k for k, v in self._buckets.items() if not v]
        for k in empty:
            del self._buckets[k]


class RelayServer:
    """«Слепой» Relay-сервер с Mailbox и rate limiting."""

    def __init__(
        self,
        host: str = DEFAULT_RELAY_HOST,
        port: int = DEFAULT_RELAY_PORT,
    ) -> None:
        self.host        = host
        self.port        = port
        self.connections: dict[str, ServerConnection] = {}
        self.mailboxes: dict[str, asyncio.Queue] = defaultdict(
            lambda: asyncio.Queue(maxsize=MAILBOX_MAX_SIZE)
        )
        self._rate_limiter = RateLimiter()
        self._stats = {"total_messages": 0, "total_connections": 0, "rate_limited": 0}

    async def handle_connection(self, websocket: ServerConnection) -> None:
        client_hash: str | None = None
        try:
            async for raw_message in websocket:
                if isinstance(raw_message, bytes):
                    raw_message = raw_message.decode("utf-8")
                try:
                    msg = RelayMessage.from_json(raw_message)
                except Exception as e:
                    await websocket.send(
                        RelayMessage.create_error(f"Ошибка формата: {e}").to_json()
                    )
                    continue

                if msg.type == MessageType.REGISTER:
                    client_hash = await self._handle_register(
                        websocket, msg.sender_hash
                    )
                elif msg.type == MessageType.SEND:
                    # Пункт 5: rate limit по hash отправителя
                    sender_id = client_hash or websocket.remote_address[0]
                    if not self._rate_limiter.is_allowed(sender_id):
                        self._stats["rate_limited"] += 1
                        logger.warning(
                            "Rate limit превышен для %s", sender_id[:16] if len(sender_id) > 16 else sender_id
                        )
                        await websocket.send(
                            RelayMessage.create_error(
                                "Слишком много сообщений. Подождите немного."
                            ).to_json()
                        )
                        continue
                    await self._handle_send(msg)
                elif msg.type == MessageType.PING:
                    await websocket.send(RelayMessage(type=MessageType.PONG).to_json())
                elif msg.type == MessageType.UNREGISTER:
                    break

        except websockets.exceptions.ConnectionClosed:  # type: ignore[union-attr]
            logger.debug("Клиент отключился: %s", client_hash or "unknown")
        finally:
            if client_hash and client_hash in self.connections:
                del self.connections[client_hash]
                logger.info("Клиент удалён: %s...", client_hash[:16])

    async def _handle_register(
        self,
        websocket: ServerConnection,
        sender_hash: str,
    ) -> str:
        self.connections[sender_hash] = websocket
        self._stats["total_connections"] += 1
        logger.info(
            "Клиент зарегистрирован: %s... (всего: %d)",
            sender_hash[:16], len(self.connections),
        )

        # ACK — ОБЯЗАТЕЛЬНО до mailbox (иначе клиент получит DELIVER раньше ACK)
        await websocket.send(RelayMessage.ack("register").to_json())

        # Доставить накопленные сообщения
        if sender_hash in self.mailboxes:
            mailbox   = self.mailboxes[sender_hash]
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
                logger.info(
                    "Доставлено %d накопленных сообщений для %s...",
                    delivered, sender_hash[:16],
                )

        return sender_hash

    async def _handle_send(self, msg: RelayMessage) -> None:
        self._stats["total_messages"] += 1
        recipient_hash = msg.recipient_hash

        deliver_msg  = RelayMessage.deliver(
            recipient_hash=recipient_hash,
            payload=msg.payload,
            message_id=msg.message_id,
        )
        deliver_json = deliver_msg.to_json()

        if recipient_hash in self.connections:
            try:
                await self.connections[recipient_hash].send(deliver_json)
                logger.debug("Пакет доставлен: → %s...", recipient_hash[:16])
            except Exception:
                logger.warning(
                    "Ошибка доставки, кладём в mailbox: %s...", recipient_hash[:16]
                )
                del self.connections[recipient_hash]
                await self._enqueue_to_mailbox(recipient_hash, deliver_json)
        else:
            await self._enqueue_to_mailbox(recipient_hash, deliver_json)
            logger.debug("Пакет в mailbox: → %s...", recipient_hash[:16])

    async def _enqueue_to_mailbox(self, recipient_hash: str, message: str) -> None:
        mailbox = self.mailboxes[recipient_hash]
        try:
            mailbox.put_nowait(message)
        except asyncio.QueueFull:
            logger.warning(
                "Mailbox переполнен для %s..., удаляем старые", recipient_hash[:16]
            )
            try:
                mailbox.get_nowait()
            except asyncio.QueueEmpty:
                pass
            mailbox.put_nowait(message)

    async def _cleanup_loop(self) -> None:
        """Периодически очищаем rate limiter от пустых корзин."""
        while True:
            await asyncio.sleep(300)
            self._rate_limiter.cleanup()

    async def start(self) -> None:
        if websockets is None:
            logger.error("Библиотека websockets не установлена")
            return

        logger.info("Relay Server запущен на ws://%s:%d", self.host, self.port)
        logger.info(
            "Rate limit: %d сообщений / %d сек на клиента",
            RATE_LIMIT_MAX_MSGS, RATE_LIMIT_WINDOW,
        )

        asyncio.create_task(self._cleanup_loop())

        async with serve(
            self.handle_connection,
            self.host,
            self.port,
            ping_interval=WS_PING_INTERVAL,
            ping_timeout=WS_PING_TIMEOUT,
            max_size=WS_MAX_MESSAGE_SIZE,
        ):
            await asyncio.get_event_loop().create_future()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="PQC-Messenger Relay Server (Blind Mailbox)"
    )
    parser.add_argument("--host", default=DEFAULT_RELAY_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_RELAY_PORT)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    setup_logging(logging.DEBUG if args.debug else logging.INFO)

    server = RelayServer(host=args.host, port=args.port)
    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        logger.info("Relay Server остановлен")
        sys.exit(0)


if __name__ == "__main__":
    main()
