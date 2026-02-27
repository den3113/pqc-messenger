"""
Клиентский WebSocket-транспорт.

Обеспечивает подключение к Relay Server, регистрацию,
отправку и получение зашифрованных пакетов.
"""

from __future__ import annotations

import asyncio
import base64
from collections.abc import AsyncIterator

from pqc_messenger.common.constants import (
    DEFAULT_RELAY_URL,
    WS_MAX_MESSAGE_SIZE,
    WS_PING_INTERVAL,
    WS_PING_TIMEOUT,
)
from pqc_messenger.common.exceptions import ConnectionError_, NetworkError
from pqc_messenger.common.logging import get_logger
from pqc_messenger.network.messages import MessageType, RelayMessage
from pqc_messenger.protocol.packet import Packet

logger = get_logger("network.transport")

try:
    import websockets
    from websockets.asyncio.client import connect, ClientConnection
except ImportError:
    websockets = None  # type: ignore[assignment]


class Transport:
    """
    Клиентский WebSocket-транспорт для связи с Relay Server.

    Использование:
        transport = Transport()
        await transport.connect("ws://localhost:8765")
        await transport.register(identity_hash)
        await transport.send_packet(packet)
        async for packet in transport.receive_packets():
            process(packet)
        await transport.disconnect()
    """

    def __init__(self) -> None:
        self._ws: ClientConnection | None = None
        self._identity_hash: str = ""
        self._receive_queue: asyncio.Queue[Packet] = asyncio.Queue()
        self._listener_task: asyncio.Task | None = None
        self._connected = False

    @property
    def is_connected(self) -> bool:
        """Подключён ли транспорт к relay."""
        return self._connected and self._ws is not None

    async def connect(self, relay_url: str = DEFAULT_RELAY_URL) -> None:
        """
        Подключиться к Relay Server.

        Args:
            relay_url: URL relay-сервера (например, ws://localhost:8765).

        Raises:
            ConnectionError_: При ошибке подключения.
        """
        if websockets is None:
            raise ConnectionError_(
                "Библиотека websockets не установлена. "
                "Установите: pip install websockets"
            )

        try:
            self._ws = await websockets.connect(  # type: ignore[attr-defined]
                relay_url,
                ping_interval=WS_PING_INTERVAL,
                ping_timeout=WS_PING_TIMEOUT,
                max_size=WS_MAX_MESSAGE_SIZE,
            )
            self._connected = True
            logger.info(f"Подключено к relay: {relay_url}")

        except Exception as e:
            raise ConnectionError_(f"Не удалось подключиться к relay: {e}") from e

    async def register(self, identity_hash: str) -> None:
        """
        Зарегистрироваться на relay по хешу идентичности.

        Args:
            identity_hash: SHA-256 хеш публичных ключей (hex).

        Raises:
            NetworkError: При ошибке регистрации.
        """
        if not self.is_connected:
            raise ConnectionError_("Нет подключения к relay")

        self._identity_hash = identity_hash

        # Отправляем REGISTER
        reg_msg = RelayMessage.register(identity_hash)
        await self._ws.send(reg_msg.to_json())  # type: ignore[union-attr]

        # Ждём ACK
        try:
            raw = await asyncio.wait_for(
                self._ws.recv(),  # type: ignore[union-attr]
                timeout=10.0,
            )
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8")

            response = RelayMessage.from_json(raw)
            if response.type == MessageType.ERROR:
                raise NetworkError(f"Relay отклонил регистрацию: {response.error}")

            logger.info(f"Зарегистрирован на relay как {identity_hash[:16]}...")

        except asyncio.TimeoutError:
            raise NetworkError("Таймаут при регистрации на relay")

        # Запускаем фоновый слушатель
        self._listener_task = asyncio.create_task(self._listen())

    async def send_packet(self, packet: Packet) -> None:
        """
        Отправить зашифрованный пакет через relay.

        Args:
            packet: Сериализованный Packet.

        Raises:
            NetworkError: При ошибке отправки.
        """
        if not self.is_connected:
            raise ConnectionError_("Нет подключения к relay")

        try:
            # Сериализуем пакет и кодируем в base64
            packet_bytes = packet.serialize()
            payload_b64 = base64.b64encode(packet_bytes).decode("ascii")

            # Формируем SEND сообщение
            send_msg = RelayMessage.send(
                recipient_hash=packet.recipient_hash.hex(),
                payload=payload_b64,
            )
            await self._ws.send(send_msg.to_json())  # type: ignore[union-attr]
            logger.debug(f"Пакет отправлен → {packet.recipient_hash[:8].hex()}...")

        except Exception as e:
            raise NetworkError(f"Ошибка отправки пакета: {e}") from e

    async def receive_packets(self) -> AsyncIterator[Packet]:
        """
        Асинхронный итератор по входящим пакетам.

        Yields:
            Packet — десериализованный входящий пакет.
        """
        while self.is_connected:
            try:
                packet = await asyncio.wait_for(
                    self._receive_queue.get(),
                    timeout=1.0,
                )
                yield packet
            except asyncio.TimeoutError:
                continue  # Проверяем is_connected и продолжаем ждать

    async def _listen(self) -> None:
        """Фоновый слушатель входящих сообщений от relay."""
        try:
            async for raw in self._ws:  # type: ignore[union-attr]
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8")

                try:
                    msg = RelayMessage.from_json(raw)
                except Exception:
                    continue

                if msg.type == MessageType.DELIVER:
                    # Decode payload и десериализуем пакет
                    try:
                        packet_bytes = base64.b64decode(msg.payload)
                        packet = Packet.deserialize(packet_bytes)
                        await self._receive_queue.put(packet)
                        logger.debug("Входящий пакет получен от relay")
                    except Exception as e:
                        logger.error(f"Ошибка разбора входящего пакета: {e}")

                elif msg.type == MessageType.ERROR:
                    logger.error(f"Ошибка от relay: {msg.error}")

        except Exception as e:
            logger.warning(f"Слушатель остановлен: {e}")
        finally:
            self._connected = False

    async def disconnect(self) -> None:
        """Отключиться от relay."""
        self._connected = False

        if self._listener_task:
            self._listener_task.cancel()
            try:
                await self._listener_task
            except asyncio.CancelledError:
                pass

        if self._ws:
            try:
                # Отправляем UNREGISTER перед отключением
                unreg = RelayMessage(type=MessageType.UNREGISTER)
                await self._ws.send(unreg.to_json())
            except Exception:
                pass
            await self._ws.close()
            self._ws = None

        logger.info("Отключено от relay")
