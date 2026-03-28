"""
Relay Server — «слепой» ретранслятор сообщений с rate limiting.

Fix #5: rate limiting теперь привязан к IP-адресу TCP-соединения,
        а не к самосообщаемому sender_hash, который клиент мог подделать.

Fix #12: mailbox ограничен по числу записей от одного отправителя
         (MAILBOX_PER_SENDER_MAX), чтобы злоумышленник не мог вытеснить
         все легитимные сообщения жертвы до её подключения.
"""

from __future__ import annotations

import asyncio
import logging
import sys
import time
import argparse
from collections import defaultdict, deque
from typing import DefaultDict

from pqc_messenger.common.constants import (
    DEFAULT_RELAY_HOST,
    DEFAULT_RELAY_PORT,
    MAILBOX_MAX_SIZE,
    MAILBOX_PER_SENDER_MAX,   # Fix #12
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
    Скользящее окно rate limiting.

    Fix #5: bucket key — это IP-адрес клиента (remote_address[0]),
            а не self-reported sender_hash, который клиент мог сфабриковать.
    """

    def __init__(
        self,
        window: float = RATE_LIMIT_WINDOW,
        max_msgs: int = RATE_LIMIT_MAX_MSGS,
    ) -> None:
        self._window   = window
        self._max_msgs = max_msgs
        self._buckets: DefaultDict[str, deque[float]] = defaultdict(deque)

    def is_allowed(self, client_ip: str) -> bool:
        """
        Вернуть True если IP не превысил лимит, иначе False.

        Fix #5: принимает IP-адрес, а не sender_hash.
        """
        now    = time.monotonic()
        bucket = self._buckets[client_ip]

        cutoff = now - self._window
        while bucket and bucket[0] < cutoff:
            bucket.popleft()

        if len(bucket) >= self._max_msgs:
            return False

        bucket.append(now)
        return True

    def cleanup(self) -> None:
        empty = [k for k, v in self._buckets.items() if not v]
        for k in empty:
            del self._buckets[k]


class RelayServer:
    """«Слепой» Relay-сервер с Mailbox, rate limiting и per-sender mailbox limit."""

    def __init__(
        self,
        host: str = DEFAULT_RELAY_HOST,
        port: int = DEFAULT_RELAY_PORT,
    ) -> None:
        self.host        = host
        self.port        = port
        self.connections: dict[str, ServerConnection] = {}
        self.mailboxes: DefaultDict[str, asyncio.Queue] = defaultdict(
            lambda: asyncio.Queue(maxsize=MAILBOX_MAX_SIZE)
        )
        # Fix #12: счётчик записей от каждого отправителя в каждый mailbox
        # Структура: {recipient_hash: {sender_ip: count}}
        self._mailbox_sender_counts: DefaultDict[str, DefaultDict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )
        self._rate_limiter = RateLimiter()
        self._stats = {
            "total_messages": 0,
            "total_connections": 0,
            "rate_limited": 0,
            "mailbox_sender_dropped": 0,
        }

    async def handle_connection(self, websocket: ServerConnection) -> None:
        # Fix #5: получаем IP немедленно — он не изменится за время соединения
        client_ip: str = websocket.remote_address[0]
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
                    # Fix #5: rate limit по IP-адресу, не по sender_hash
                    if not self._rate_limiter.is_allowed(client_ip):
                        self._stats["rate_limited"] += 1
                        logger.warning("Rate limit превышен для IP %s", client_ip)
                        await websocket.send(
                            RelayMessage.create_error(
                                "Слишком много сообщений. Подождите немного."
                            ).to_json()
                        )
                        continue
                    await self._handle_send(msg, sender_ip=client_ip)
                elif msg.type == MessageType.PING:
                    await websocket.send(RelayMessage(type=MessageType.PONG).to_json())
                elif msg.type == MessageType.UNREGISTER:
                    break

        except websockets.exceptions.ConnectionClosed:  # type: ignore[union-attr]
            logger.debug("Клиент отключился: %s", client_hash or client_ip)
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

        await websocket.send(RelayMessage.ack("register").to_json())

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
                # Сбрасываем счётчики отправителей для этого mailbox
                self._mailbox_sender_counts.pop(sender_hash, None)
                logger.info(
                    "Доставлено %d накопленных сообщений для %s...",
                    delivered, sender_hash[:16],
                )

        return sender_hash

    async def _handle_send(self, msg: RelayMessage, sender_ip: str) -> None:
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
                await self._enqueue_to_mailbox(recipient_hash, deliver_json, sender_ip)
        else:
            await self._enqueue_to_mailbox(recipient_hash, deliver_json, sender_ip)
            logger.debug("Пакет в mailbox: → %s...", recipient_hash[:16])

    async def _enqueue_to_mailbox(
        self,
        recipient_hash: str,
        message: str,
        sender_ip: str,
    ) -> None:
        """
        Fix #12: перед добавлением проверяем лимит записей от одного отправителя.

        Если sender_ip уже достиг MAILBOX_PER_SENDER_MAX, новое сообщение
        отбрасывается вместо вытеснения сообщений других отправителей.
        Это не позволяет одному IP занять весь mailbox жертвы.
        """
        sender_counts = self._mailbox_sender_counts[recipient_hash]
        current_count = sender_counts.get(sender_ip, 0)

        if current_count >= MAILBOX_PER_SENDER_MAX:
            self._stats["mailbox_sender_dropped"] += 1
            logger.warning(
                "Mailbox для %s...: лимит от отправителя %s достигнут (%d), пакет отброшен",
                recipient_hash[:16], sender_ip, MAILBOX_PER_SENDER_MAX,
            )
            return

        mailbox = self.mailboxes[recipient_hash]
        try:
            mailbox.put_nowait(message)
            sender_counts[sender_ip] = current_count + 1
        except asyncio.QueueFull:
            # Глобальный лимит mailbox: вытесняем старейшее сообщение
            logger.warning(
                "Mailbox переполнен для %s..., удаляем старые", recipient_hash[:16]
            )
            try:
                mailbox.get_nowait()
                # При вытеснении не корректируем sender_counts точно —
                # это усложнило бы логику; небольшое приближение допустимо.
            except asyncio.QueueEmpty:
                pass
            mailbox.put_nowait(message)
            sender_counts[sender_ip] = current_count + 1

    async def _cleanup_loop(self) -> None:
        while True:
            await asyncio.sleep(300)
            self._rate_limiter.cleanup()

    async def start(self) -> None:
        if websockets is None:
            logger.error("Библиотека websockets не установлена")
            return

        logger.info("Relay Server запущен на ws://%s:%d", self.host, self.port)
        logger.info(
            "Rate limit: %d сообщений / %d сек на IP (Fix #5: по IP, не по hash)",
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
