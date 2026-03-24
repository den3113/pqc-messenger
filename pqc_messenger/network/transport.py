"""
Клиентский WebSocket-транспорт с автопереподключением.

Пункт 1: при обрыве соединения транспорт автоматически пытается
переподключиться с экспоненциальной задержкой.
"""

from __future__ import annotations

import asyncio
import base64
import math
from collections.abc import AsyncIterator

from pqc_messenger.common.constants import (
    DEFAULT_RELAY_URL,
    RECONNECT_DELAY_MAX,
    RECONNECT_DELAY_MIN,
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

    Поддерживает автоматическое переподключение при обрыве связи.
    """

    def __init__(self) -> None:
        self._ws: ClientConnection | None = None
        self._relay_url: str = DEFAULT_RELAY_URL
        self._identity_hash: str = ""
        self._receive_queue: asyncio.Queue[Packet] = asyncio.Queue()
        self._listener_task: asyncio.Task | None = None
        self._reconnect_task: asyncio.Task | None = None
        self._connected = False
        self._reconnect_enabled = False
        # Callback вызывается при успешном переподключении
        self._on_reconnect: asyncio.coroutines | None = None

    @property
    def is_connected(self) -> bool:
        return self._connected and self._ws is not None

    # ── Подключение ───────────────────────────────────────────────────────────

    async def connect(self, relay_url: str = DEFAULT_RELAY_URL) -> None:
        if websockets is None:
            raise ConnectionError_("Библиотека websockets не установлена")
        self._relay_url = relay_url
        await self._do_connect()

    async def _do_connect(self) -> None:
        """Установить WebSocket-соединение (без повторных попыток)."""
        try:
            self._ws = await websockets.connect(  # type: ignore[attr-defined]
                self._relay_url,
                ping_interval=WS_PING_INTERVAL,
                ping_timeout=WS_PING_TIMEOUT,
                max_size=WS_MAX_MESSAGE_SIZE,
            )
            self._connected = True
            logger.info("Подключено к relay: %s", self._relay_url)
        except Exception as e:
            raise ConnectionError_(f"Не удалось подключиться к relay: {e}") from e

    async def register(self, identity_hash: str) -> None:
        if not self.is_connected:
            raise ConnectionError_("Нет подключения к relay")

        self._identity_hash = identity_hash
        self._reconnect_enabled = True

        reg_msg = RelayMessage.register(identity_hash)
        await self._ws.send(reg_msg.to_json())  # type: ignore[union-attr]

        # Ждём ACK (пропускаем DELIVER которые могут прийти раньше)
        try:
            deadline = asyncio.get_event_loop().time() + 10.0
            while True:
                remaining = deadline - asyncio.get_event_loop().time()
                if remaining <= 0:
                    raise asyncio.TimeoutError()
                raw = await asyncio.wait_for(
                    self._ws.recv(),  # type: ignore[union-attr]
                    timeout=remaining,
                )
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8")
                response = RelayMessage.from_json(raw)
                if response.type == MessageType.ERROR:
                    raise NetworkError(f"Relay отклонил регистрацию: {response.error}")
                if response.type == MessageType.ACK:
                    logger.info("Зарегистрирован на relay как %s...", identity_hash[:16])
                    break
                if response.type == MessageType.DELIVER:
                    try:
                        packet_bytes = base64.b64decode(response.payload)
                        from pqc_messenger.protocol.packet import Packet as _Packet
                        packet = _Packet.deserialize(packet_bytes)
                        await self._receive_queue.put(packet)
                    except Exception as _e:
                        logger.error("Ошибка разбора mailbox-пакета: %s", _e)
                    continue
                logger.debug("Неожиданный тип при регистрации: %s", response.type)
        except asyncio.TimeoutError:
            raise NetworkError("Таймаут при регистрации на relay")

        self._listener_task = asyncio.create_task(self._listen())

    def set_reconnect_callback(self, coro_fn) -> None:
        """Установить async-callback вызываемый после успешного переподключения."""
        self._on_reconnect = coro_fn

    # ── Отправка ─────────────────────────────────────────────────────────────

    async def send_packet(self, packet: Packet) -> None:
        if not self.is_connected:
            raise ConnectionError_("Нет подключения к relay")
        try:
            packet_bytes = packet.serialize()
            payload_b64  = base64.b64encode(packet_bytes).decode("ascii")
            send_msg = RelayMessage.send(
                recipient_hash=packet.recipient_hash.hex(),
                payload=payload_b64,
            )
            await self._ws.send(send_msg.to_json())  # type: ignore[union-attr]
            logger.debug("Пакет отправлен → %s...", packet.recipient_hash[:8].hex())
        except Exception as e:
            raise NetworkError(f"Ошибка отправки пакета: {e}") from e

    # ── Получение ─────────────────────────────────────────────────────────────

    async def receive_packets(self) -> AsyncIterator[Packet]:
        while self.is_connected or self._reconnect_enabled:
            try:
                packet = await asyncio.wait_for(
                    self._receive_queue.get(), timeout=1.0
                )
                yield packet
            except asyncio.TimeoutError:
                continue

    # ── Слушатель + автопереподключение ──────────────────────────────────────

    async def _listen(self) -> None:
        """Фоновый слушатель. При обрыве запускает цикл переподключения."""
        try:
            async for raw in self._ws:  # type: ignore[union-attr]
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8")
                try:
                    msg = RelayMessage.from_json(raw)
                except Exception:
                    continue
                if msg.type == MessageType.DELIVER:
                    try:
                        packet_bytes = base64.b64decode(msg.payload)
                        packet = Packet.deserialize(packet_bytes)
                        await self._receive_queue.put(packet)
                        logger.debug("Входящий пакет получен от relay")
                    except Exception as e:
                        logger.error("Ошибка разбора входящего пакета: %s", e)
                elif msg.type == MessageType.ERROR:
                    logger.error("Ошибка от relay: %s", msg.error)
        except Exception as e:
            logger.warning("Слушатель остановлен: %s", e)
        finally:
            self._connected = False
            self._ws = None
            # Запускаем автопереподключение если не было явного disconnect()
            if self._reconnect_enabled and self._identity_hash:
                logger.info("Соединение потеряно — запускаем автопереподключение")
                self._reconnect_task = asyncio.create_task(self._reconnect_loop())

    async def _reconnect_loop(self) -> None:
        """
        Пункт 1: Экспоненциальная задержка переподключения.
        RECONNECT_DELAY_MIN → ... → RECONNECT_DELAY_MAX, затем фиксированная пауза.
        """
        attempt = 0
        while self._reconnect_enabled:
            delay = min(
                RECONNECT_DELAY_MIN * (2 ** attempt),
                RECONNECT_DELAY_MAX,
            )
            logger.info(
                "Переподключение через %.0f сек (попытка %d)...", delay, attempt + 1
            )
            await asyncio.sleep(delay)

            try:
                await self._do_connect()
                # Повторная регистрация
                reg_msg = RelayMessage.register(self._identity_hash)
                await self._ws.send(reg_msg.to_json())  # type: ignore[union-attr]

                deadline = asyncio.get_event_loop().time() + 10.0
                registered = False
                while True:
                    remaining = deadline - asyncio.get_event_loop().time()
                    if remaining <= 0:
                        break
                    raw = await asyncio.wait_for(
                        self._ws.recv(),  # type: ignore[union-attr]
                        timeout=remaining,
                    )
                    if isinstance(raw, bytes):
                        raw = raw.decode("utf-8")
                    resp = RelayMessage.from_json(raw)
                    if resp.type == MessageType.ACK:
                        registered = True
                        break
                    if resp.type == MessageType.DELIVER:
                        try:
                            packet = Packet.deserialize(
                                base64.b64decode(resp.payload)
                            )
                            await self._receive_queue.put(packet)
                        except Exception:
                            pass
                        continue

                if not registered:
                    raise NetworkError("Нет ACK от relay после переподключения")

                logger.info("Переподключено и зарегистрировано успешно")
                self._listener_task = asyncio.create_task(self._listen())

                # Уведомляем приложение (например, чтобы переотправить pending)
                if self._on_reconnect:
                    await self._on_reconnect()

                return  # Успех — выходим из цикла

            except Exception as e:
                logger.warning("Попытка переподключения %d не удалась: %s", attempt + 1, e)
                self._connected = False
                self._ws = None
                attempt += 1

    # ── Отключение ────────────────────────────────────────────────────────────

    async def disconnect(self) -> None:
        self._reconnect_enabled = False
        self._connected = False

        if self._reconnect_task and not self._reconnect_task.done():
            self._reconnect_task.cancel()
            try:
                await self._reconnect_task
            except asyncio.CancelledError:
                pass

        if self._listener_task:
            self._listener_task.cancel()
            try:
                await self._listener_task
            except asyncio.CancelledError:
                pass

        if self._ws:
            try:
                unreg = RelayMessage(type=MessageType.UNREGISTER)
                await self._ws.send(unreg.to_json())
            except Exception:
                pass
            await self._ws.close()
            self._ws = None

        logger.info("Отключено от relay")
