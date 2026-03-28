"""
Double Ratchet для обеспечения Forward Secrecy.

Реализация основана на принципах Signal Double Ratchet Algorithm
(Marlinspike, 2016), адаптированная для гибридного PQC-контекста.

Fix #2: кэш пропущенных ключей теперь ограничен MAX_SKIPPED_KEYS_TOTAL
        записями суммарно. При переполнении самые старые записи вытесняются.
"""

from __future__ import annotations

import json
import os
import struct
from collections import OrderedDict
from dataclasses import dataclass, field

from pqc_messenger.common.constants import (
    HKDF_INFO_MESSAGE,
    HKDF_INFO_RATCHET,
    MAX_SKIP,
    MAX_SKIPPED_KEYS_TOTAL,
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
    """

    chain_key: bytes

    def next(self) -> tuple[bytes, bytes]:
        """Продвинуть ratchet: сгенерировать следующий message key."""
        new_chain_key, message_key = KDF.derive_pair(
            input_key=self.chain_key,
            info=HKDF_INFO_MESSAGE,
        )
        self.chain_key = new_chain_key
        return message_key, new_chain_key

    def serialize(self) -> bytes:
        return self.chain_key

    @classmethod
    def deserialize(cls, data: bytes) -> SymmetricRatchet:
        return cls(chain_key=data)


class _BoundedSkippedKeys:
    """
    OrderedDict с ограниченным числом записей.

    При добавлении новой записи сверх лимита вытесняется самая старая.
    Сериализуется/десериализуется как обычный словарь для совместимости.
    """

    def __init__(self, max_size: int = MAX_SKIPPED_KEYS_TOTAL) -> None:
        self._max  = max_size
        self._data: OrderedDict[tuple[bytes, int], bytes] = OrderedDict()

    def __setitem__(self, key: tuple[bytes, int], value: bytes) -> None:
        if key in self._data:
            self._data.move_to_end(key)
        else:
            if len(self._data) >= self._max:
                evicted = self._data.popitem(last=False)
                logger.warning(
                    "Кэш пропущенных ключей переполнен (%d записей): "
                    "вытесняется старейший ключ (dh=%s, n=%d)",
                    self._max, evicted[0][0][:4].hex(), evicted[0][1],
                )
        self._data[key] = value

    def __getitem__(self, key: tuple[bytes, int]) -> bytes:
        return self._data[key]

    def __contains__(self, key: object) -> bool:
        return key in self._data

    def __delitem__(self, key: tuple[bytes, int]) -> None:
        del self._data[key]

    def pop(self, key: tuple[bytes, int], *args):
        return self._data.pop(key, *args)

    def clear(self) -> None:
        self._data.clear()

    def items(self):
        return self._data.items()

    def __len__(self) -> int:
        return len(self._data)

    def to_dict(self) -> dict[str, str]:
        """Сериализовать для JSON-хранения."""
        return {
            f"{dh_pub.hex()}:{count}": key.hex()
            for (dh_pub, count), key in self._data.items()
        }

    @classmethod
    def from_dict(cls, raw: dict[str, str], max_size: int = MAX_SKIPPED_KEYS_TOTAL) -> "_BoundedSkippedKeys":
        """Восстановить из JSON-хранения."""
        obj = cls(max_size=max_size)
        for composite_key, key_hex in raw.items():
            dh_pub_hex, count_str = composite_key.rsplit(":", 1)
            dh_pub = bytes.fromhex(dh_pub_hex)
            count  = int(count_str)
            obj[(dh_pub, count)] = bytes.fromhex(key_hex)
        return obj


@dataclass
class SessionRatchet:
    """
    Полный Double Ratchet с DH и Symmetric компонентами.

    skipped_keys использует _BoundedSkippedKeys вместо обычного dict.
    """

    root_key: bytes
    sending_chain: SymmetricRatchet | None = None
    receiving_chain: SymmetricRatchet | None = None
    dh_keypair: X25519KeyPair | None = None
    remote_dh_public: bytes | None = None
    send_count: int = 0
    recv_count: int = 0

    skipped_keys: _BoundedSkippedKeys = field(default_factory=_BoundedSkippedKeys)

    @classmethod
    def initialize_as_initiator(
        cls,
        shared_secret: bytes,
        own_dh_keypair: X25519KeyPair,
        remote_dh_public: bytes,
    ) -> SessionRatchet:
        """Инициализировать ratchet на стороне инициатора."""
        ratchet = cls(root_key=shared_secret)
        ratchet.dh_keypair = own_dh_keypair
        ratchet.remote_dh_public = remote_dh_public

        peer_pub = X25519KeyPair.public_from_bytes(remote_dh_public)
        dh_output = ratchet.dh_keypair.shared_secret(peer_pub)
        new_root_key, chain_key = KDF.derive_pair(
            input_key=ratchet.root_key + dh_output,
            info=HKDF_INFO_RATCHET,
        )
        ratchet.root_key = new_root_key
        ratchet.sending_chain = SymmetricRatchet(chain_key=chain_key)

        logger.info("Ratchet инициализирован (initiator)")
        return ratchet

    @classmethod
    def initialize_as_responder(
        cls,
        shared_secret: bytes,
        own_dh_keypair: X25519KeyPair,
        remote_dh_public: bytes,
    ) -> SessionRatchet:
        """Инициализировать ratchet на стороне респондента."""
        ratchet = cls(root_key=shared_secret)
        ratchet.dh_keypair = own_dh_keypair
        ratchet.remote_dh_public = remote_dh_public

        peer_pub = X25519KeyPair.public_from_bytes(remote_dh_public)
        dh_output = ratchet.dh_keypair.shared_secret(peer_pub)
        new_root_key, recv_chain_key = KDF.derive_pair(
            input_key=ratchet.root_key + dh_output,
            info=HKDF_INFO_RATCHET,
        )
        ratchet.root_key = new_root_key
        ratchet.receiving_chain = SymmetricRatchet(chain_key=recv_chain_key)

        logger.info("Ratchet инициализирован (responder)")
        return ratchet

    def _dh_ratchet_step(self) -> None:
        if self.remote_dh_public is None or self.dh_keypair is None:
            raise ProtocolError("DH ratchet step невозможен: отсутствуют ключи")

        peer_pub = X25519KeyPair.public_from_bytes(self.remote_dh_public)
        dh_output = self.dh_keypair.shared_secret(peer_pub)

        new_root_key, chain_key = KDF.derive_pair(
            input_key=self.root_key + dh_output,
            info=HKDF_INFO_RATCHET,
        )

        self.root_key = new_root_key
        self.sending_chain = SymmetricRatchet(chain_key=chain_key)
        self.send_count = 0

    def encrypt(self, plaintext: bytes) -> bytes:
        """Зашифровать сообщение с ratchet."""
        if self.sending_chain is None:
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

        message_key, _ = self.sending_chain.next()

        encrypted = AEAD.encrypt(message_key, plaintext)

        dh_pub = self.dh_keypair.serialize_public()
        count_bytes = struct.pack("!I", self.send_count)
        self.send_count += 1

        del message_key

        return dh_pub + count_bytes + encrypted

    def decrypt(self, data: bytes) -> bytes:
        """Расшифровать входящее сообщение с ratchet."""
        if len(data) < 36:
            raise ProtocolError("Сообщение слишком короткое для ratchet")

        remote_dh_pub = data[:32]
        (msg_count,) = struct.unpack("!I", data[32:36])
        encrypted = data[36:]

        if self.remote_dh_public is None or remote_dh_pub != self.remote_dh_public:
            if self.receiving_chain is not None:
                self._skip_message_keys(msg_count)
            self._perform_dh_ratchet(remote_dh_pub)
            self.recv_count = 0

        self._skip_message_keys(msg_count)

        if self.receiving_chain is None:
            raise ProtocolError("Receiving chain не инициализирован")

        message_key, _ = self.receiving_chain.next()
        self.recv_count += 1

        try:
            plaintext = AEAD.decrypt(message_key, encrypted)
        finally:
            del message_key

        return plaintext

    def _perform_dh_ratchet(self, remote_dh_pub: bytes) -> None:
        self.remote_dh_public = remote_dh_pub

        if self.dh_keypair is None:
            raise ProtocolError("DH keypair не инициализирован")

        peer_pub = X25519KeyPair.public_from_bytes(remote_dh_pub)
        dh_output = self.dh_keypair.shared_secret(peer_pub)
        new_root_key, recv_chain_key = KDF.derive_pair(
            input_key=self.root_key + dh_output,
            info=HKDF_INFO_RATCHET,
        )
        self.root_key = new_root_key
        self.receiving_chain = SymmetricRatchet(chain_key=recv_chain_key)

        self.dh_keypair = X25519KeyPair.generate()

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
        Кешировать пропущенные message keys.

        _BoundedSkippedKeys автоматически вытесняет старые записи
        при превышении MAX_SKIPPED_KEYS_TOTAL.
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
        """Принудительная ротация DH ключа (Forward Secrecy)."""
        self.dh_keypair = X25519KeyPair.generate()

        if self.remote_dh_public is not None:
            self._dh_ratchet_step()

        logger.info("DH ключ ротирован (Forward Secrecy)")
        return self.dh_keypair.serialize_public()

    def serialize(self) -> bytes:
        """Сериализовать состояние ratchet для хранения."""
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

            "skipped_keys": self.skipped_keys.to_dict(),
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


        ratchet.skipped_keys = _BoundedSkippedKeys.from_dict(
            state.get("skipped_keys", {})
        )

        return ratchet
