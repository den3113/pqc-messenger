"""
Double Ratchet для обеспечения Forward Secrecy.

Реализация основана на принципах Signal Double Ratchet Algorithm
(Marlinspike, 2016), адаптированная для гибридного PQC-контекста.

Два уровня ratchet:
1. Symmetric Ratchet (KDF Chain): генерация message keys из chain key
2. DH Ratchet: обновление root key при каждом обмене DH-ключами

Forward Secrecy: компрометация текущего ключа не раскрывает прошлые сообщения.
"""

from __future__ import annotations

import os
import json
from dataclasses import dataclass, field

from pqc_messenger.common.constants import (
    HKDF_INFO_MESSAGE,
    HKDF_INFO_RATCHET,
    MAX_SKIP,
)
from pqc_messenger.common.exceptions import CryptoError, KeyExpiredError, ProtocolError
from pqc_messenger.common.logging import get_logger
from pqc_messenger.crypto.aead import AEAD
from pqc_messenger.crypto.kdf import KDF
from pqc_messenger.crypto.keys import X25519KeyPair

logger = get_logger("protocol.ratchet")


@dataclass
class SymmetricRatchet:
    """
    Симметричный KDF Ratchet (цепочка ключей).

    Генерирует последовательность message keys из chain key:
        chain_key[n+1], message_key[n] = KDF(chain_key[n])

    Каждый message_key используется ровно один раз и затем уничтожается.
    """

    chain_key: bytes

    def next(self) -> tuple[bytes, bytes]:
        """
        Продвинуть ratchet: сгенерировать следующий message key.

        Returns:
            (message_key, new_chain_key):
                - message_key: ключ для шифрования одного сообщения
                - new_chain_key: новый chain key для следующего шага
        """
        # Используем HKDF для разделения chain_key на message_key + new_chain_key
        new_chain_key, message_key = KDF.derive_pair(
            input_key=self.chain_key,
            info=HKDF_INFO_MESSAGE,
        )
        self.chain_key = new_chain_key
        return message_key, new_chain_key

    def serialize(self) -> bytes:
        """Сериализовать состояние ratchet."""
        return self.chain_key

    @classmethod
    def deserialize(cls, data: bytes) -> SymmetricRatchet:
        """Восстановить ratchet из сериализованных данных."""
        return cls(chain_key=data)


@dataclass
class SessionRatchet:
    """
    Полный Double Ratchet с DH и Symmetric компонентами.

    Атрибуты:
        root_key: Корневой ключ для деривации chain keys
        sending_chain: Цепочка для шифрования исходящих сообщений
        receiving_chain: Цепочка для расшифрования входящих сообщений
        dh_keypair: Текущая пара DH-ключей для ratchet step
        remote_dh_public: Публичный DH-ключ собеседника
        send_count: Счётчик отправленных сообщений
        recv_count: Счётчик полученных сообщений
        skipped_keys: Кеш пропущенных message keys
    """

    root_key: bytes
    sending_chain: SymmetricRatchet | None = None
    receiving_chain: SymmetricRatchet | None = None
    dh_keypair: X25519KeyPair | None = None
    remote_dh_public: bytes | None = None
    send_count: int = 0
    recv_count: int = 0
    skipped_keys: dict[tuple[bytes, int], bytes] = field(default_factory=dict)

    @classmethod
    def initialize_as_initiator(
        cls,
        shared_secret: bytes,
        own_dh_keypair: X25519KeyPair,
        remote_dh_public: bytes,
    ) -> SessionRatchet:
        """
        Инициализировать ratchet на стороне инициатора (после Handshake).

        Инициатор устанавливает sending chain на основе DH(own_identity, peer_identity).
        DH keypair НЕ заменяется — identity pub будет отправлен в первом сообщении,
        и респондент ожидает именно его.

        Args:
            shared_secret: Общий секрет из Handshake.
            own_dh_keypair: Своя пара DH-ключей (identity X25519).
            remote_dh_public: DH публичный ключ респондента (identity X25519).

        Returns:
            Инициализированный SessionRatchet.
        """
        ratchet = cls(root_key=shared_secret)
        ratchet.dh_keypair = own_dh_keypair
        ratchet.remote_dh_public = remote_dh_public

        # Начальный DH: DH(own_identity, peer_identity) → sending chain
        peer_pub = X25519KeyPair.public_from_bytes(remote_dh_public)
        dh_output = ratchet.dh_keypair.shared_secret(peer_pub)
        new_root_key, chain_key = KDF.derive_pair(
            input_key=ratchet.root_key + dh_output,
            info=HKDF_INFO_RATCHET,
        )
        ratchet.root_key = new_root_key
        ratchet.sending_chain = SymmetricRatchet(chain_key=chain_key)

        # НЕ генерируем новый DH keypair — identity pub пойдёт в заголовке
        # первого сообщения, и респондент ожидает именно его.
        # Receiving chain будет создан при получении первого ответа (DH ratchet step).

        logger.info("Ratchet инициализирован (initiator)")
        return ratchet

    @classmethod
    def initialize_as_responder(
        cls,
        shared_secret: bytes,
        own_dh_keypair: X25519KeyPair,
        remote_dh_public: bytes,
    ) -> SessionRatchet:
        """
        Инициализировать ratchet на стороне респондента.

        Респондент устанавливает только receiving chain на основе
        DH(own_identity, peer_identity) — она совпадает с sending chain инициатора.
        Sending chain будет создан при DH ratchet step (при отправке первого ответа).

        Args:
            shared_secret: Общий секрет из Handshake.
            own_dh_keypair: Своя пара DH-ключей.
            remote_dh_public: Публичный DH-ключ инициатора.

        Returns:
            Инициализированный SessionRatchet.
        """
        ratchet = cls(root_key=shared_secret)
        ratchet.dh_keypair = own_dh_keypair
        ratchet.remote_dh_public = remote_dh_public

        # Устанавливаем receiving chain:
        # DH(own_dh, remote_dh) → receiving chain
        # Это тот же DH output, что и у инициатора → цепочки совпадают.
        peer_pub = X25519KeyPair.public_from_bytes(remote_dh_public)
        dh_output = ratchet.dh_keypair.shared_secret(peer_pub)
        new_root_key, recv_chain_key = KDF.derive_pair(
            input_key=ratchet.root_key + dh_output,
            info=HKDF_INFO_RATCHET,
        )
        ratchet.root_key = new_root_key
        ratchet.receiving_chain = SymmetricRatchet(chain_key=recv_chain_key)

        # НЕ создаём sending chain сразу — он будет создан при первой
        # отправке через DH ratchet step (_perform_dh_ratchet).

        logger.info("Ratchet инициализирован (responder)")
        return ratchet

    def _dh_ratchet_step(self) -> None:
        """
        Выполнить DH ratchet step.

        Обновляет root_key и создаёт новый sending_chain.
        """
        if self.remote_dh_public is None or self.dh_keypair is None:
            raise ProtocolError("DH ratchet step невозможен: отсутствуют ключи")

        # DH exchange
        peer_pub = X25519KeyPair.public_from_bytes(self.remote_dh_public)
        dh_output = self.dh_keypair.shared_secret(peer_pub)

        # Деривация нового root_key и sending chain_key
        new_root_key, chain_key = KDF.derive_pair(
            input_key=self.root_key + dh_output,
            info=HKDF_INFO_RATCHET,
        )

        self.root_key = new_root_key
        self.sending_chain = SymmetricRatchet(chain_key=chain_key)
        self.send_count = 0

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Зашифровать сообщение с ratchet.

        Формат выходных данных:
            dh_public(32) + send_count(4) + encrypted_message

        Args:
            plaintext: Открытый текст.

        Returns:
            Зашифрованные данные с метаинформацией для ratchet.
        """
        if self.sending_chain is None:
            # Респондент ещё не отправлял сообщений —
            # генерируем новый DH keypair и создаём sending chain.
            # Новый DH pub пойдёт в заголовке сообщения, и получатель
            # увидит новый ключ → выполнит DH ratchet → создаст receiving chain.
            if self.remote_dh_public is not None and self.dh_keypair is not None:
                self.dh_keypair = X25519KeyPair.generate()
                peer_pub = X25519KeyPair.public_from_bytes(self.remote_dh_public)
                dh_output = self.dh_keypair.shared_secret(peer_pub)
                new_root_key, chain_key = KDF.derive_pair(
                    input_key=self.root_key + dh_output,
                    info=HKDF_INFO_RATCHET,
                )
                self.root_key = new_root_key
                self.sending_chain = SymmetricRatchet(chain_key=chain_key)
                self.send_count = 0
            else:
                raise ProtocolError("Sending chain не инициализирован")
        if self.dh_keypair is None:
            raise ProtocolError("DH keypair не инициализирован")

        # Получаем message key
        message_key, _ = self.sending_chain.next()

        # Шифруем сообщение
        encrypted = AEAD.encrypt(message_key, plaintext)

        # Формируем выходной блок
        import struct
        dh_pub = self.dh_keypair.serialize_public()
        count_bytes = struct.pack("!I", self.send_count)
        self.send_count += 1

        # Безопасное удаление message_key из памяти
        # (в Python полноценное удаление невозможно, но обнуляем переменную)
        del message_key

        return dh_pub + count_bytes + encrypted

    def decrypt(self, data: bytes) -> bytes:
        """
        Расшифровать входящее сообщение с ratchet.

        Args:
            data: Зашифрованные данные в формате dh_public + count + encrypted.

        Returns:
            Расшифрованный открытый текст.
        """
        import struct

        if len(data) < 36:  # 32 (dh_pub) + 4 (count)
            raise ProtocolError("Сообщение слишком короткое для ratchet")

        # Разбор данных
        remote_dh_pub = data[:32]
        (msg_count,) = struct.unpack("!I", data[32:36])
        encrypted = data[36:]

        # Проверяем, нужен ли DH ratchet step
        if self.remote_dh_public is None or remote_dh_pub != self.remote_dh_public:
            # Новый DH ключ от собеседника → DH ratchet step.
            # Сначала кешируем пропущенные ключи в СТАРОЙ receiving chain (если есть),
            # затем выполняем DH ratchet и сбрасываем счётчик.
            if self.receiving_chain is not None:
                self._skip_message_keys(msg_count)
            self._perform_dh_ratchet(remote_dh_pub)
            self.recv_count = 0

        # Пропуск ключей, если есть пробелы в нумерации (уже на новой цепочке)
        self._skip_message_keys(msg_count)

        # Получаем message key
        if self.receiving_chain is None:
            raise ProtocolError("Receiving chain не инициализирован")

        message_key, _ = self.receiving_chain.next()
        self.recv_count += 1

        # Расшифровка
        try:
            plaintext = AEAD.decrypt(message_key, encrypted)
        finally:
            del message_key

        return plaintext

    def _perform_dh_ratchet(self, remote_dh_pub: bytes) -> None:
        """
        Выполнить DH ratchet при получении нового DH ключа от собеседника.
        """
        self.remote_dh_public = remote_dh_pub

        if self.dh_keypair is None:
            raise ProtocolError("DH keypair не инициализирован")

        # Вычисляем receiving chain
        peer_pub = X25519KeyPair.public_from_bytes(remote_dh_pub)
        dh_output = self.dh_keypair.shared_secret(peer_pub)
        new_root_key, recv_chain_key = KDF.derive_pair(
            input_key=self.root_key + dh_output,
            info=HKDF_INFO_RATCHET,
        )
        self.root_key = new_root_key
        self.receiving_chain = SymmetricRatchet(chain_key=recv_chain_key)

        # Генерируем новую DH пару для отправки
        self.dh_keypair = X25519KeyPair.generate()

        # Обновляем sending chain
        peer_pub = X25519KeyPair.public_from_bytes(remote_dh_pub)
        dh_output = self.dh_keypair.shared_secret(peer_pub)
        new_root_key, send_chain_key = KDF.derive_pair(
            input_key=self.root_key + dh_output,
            info=HKDF_INFO_RATCHET,
        )
        self.root_key = new_root_key
        self.sending_chain = SymmetricRatchet(chain_key=send_chain_key)
        self.send_count = 0

    def _skip_message_keys(self, until: int) -> None:
        """
        Кешировать пропущенные message keys (для обработки out-of-order сообщений).
        """
        if self.receiving_chain is None:
            return

        if until > self.recv_count + MAX_SKIP:
            raise ProtocolError(
                f"Слишком много пропущенных ключей: {until - self.recv_count} > {MAX_SKIP}"
            )

        while self.recv_count < until:
            message_key, _ = self.receiving_chain.next()
            if self.remote_dh_public is not None:
                self.skipped_keys[(self.remote_dh_public, self.recv_count)] = message_key
            self.recv_count += 1

    def rotate_dh(self) -> bytes:
        """
        Принудительная ротация DH ключа.

        Вызывается для создания нового ephemeral key pair,
        обеспечивая Forward Secrecy для последующих сообщений.

        Returns:
            Новый DH публичный ключ для передачи собеседнику.
        """
        self.dh_keypair = X25519KeyPair.generate()

        if self.remote_dh_public is not None:
            self._dh_ratchet_step()

        logger.info("DH ключ ротирован (Forward Secrecy)")
        return self.dh_keypair.serialize_public()

    def serialize(self) -> bytes:
        """Сериализовать состояние ratchet для хранения."""
        # Сериализуем skipped_keys: ключ — (dh_pub_hex, count), значение — key_hex
        skipped = {
            f"{dh_pub.hex()}:{count}": key.hex()
            for (dh_pub, count), key in self.skipped_keys.items()
        }
        state = {
            "root_key": self.root_key.hex(),
            "sending_chain": (
                self.sending_chain.chain_key.hex()
                if self.sending_chain
                else None
            ),
            "receiving_chain": (
                self.receiving_chain.chain_key.hex()
                if self.receiving_chain
                else None
            ),
            "dh_private": (
                self.dh_keypair.serialize_private().hex()
                if self.dh_keypair
                else None
            ),
            "remote_dh_public": (
                self.remote_dh_public.hex()
                if self.remote_dh_public
                else None
            ),
            "send_count": self.send_count,
            "recv_count": self.recv_count,
            "skipped_keys": skipped,
        }
        return json.dumps(state).encode("utf-8")

    @classmethod
    def deserialize(cls, data: bytes) -> SessionRatchet:
        """Восстановить ratchet из сериализованных данных."""
        state = json.loads(data)

        ratchet = cls(root_key=bytes.fromhex(state["root_key"]))

        if state["sending_chain"]:
            ratchet.sending_chain = SymmetricRatchet(
                chain_key=bytes.fromhex(state["sending_chain"])
            )
        if state["receiving_chain"]:
            ratchet.receiving_chain = SymmetricRatchet(
                chain_key=bytes.fromhex(state["receiving_chain"])
            )
        if state["dh_private"]:
            ratchet.dh_keypair = X25519KeyPair.from_private_bytes(
                bytes.fromhex(state["dh_private"])
            )
        if state["remote_dh_public"]:
            ratchet.remote_dh_public = bytes.fromhex(state["remote_dh_public"])

        ratchet.send_count = state["send_count"]
        ratchet.recv_count = state["recv_count"]

        # Восстанавливаем skipped_keys (ключ хранится как "dh_pub_hex:count")
        for composite_key, key_hex in state.get("skipped_keys", {}).items():
            dh_pub_hex, count_str = composite_key.rsplit(":", 1)
            dh_pub = bytes.fromhex(dh_pub_hex)
            count = int(count_str)
            ratchet.skipped_keys[(dh_pub, count)] = bytes.fromhex(key_hex)

        return ratchet
