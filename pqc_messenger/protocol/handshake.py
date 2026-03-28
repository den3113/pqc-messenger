"""
Гибридный протокол Handshake (X25519 + Kyber-768).

Fix #3: process_init теперь принимает trusted_contact_ids — множество
        разрешённых fingerprint'ов. Неизвестные инициаторы отклоняются
        через UnknownPeerError без раскрытия причины отказа.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

from pqc_messenger.common.constants import HKDF_INFO_HANDSHAKE
from pqc_messenger.common.exceptions import HandshakeError, UnknownPeerError
from pqc_messenger.common.logging import get_logger
from pqc_messenger.crypto.aead import AEAD
from pqc_messenger.crypto.identity import Identity
from pqc_messenger.crypto.kem import HybridKEM
from pqc_messenger.crypto.kdf import KDF
from pqc_messenger.crypto.keys import IdentityKeyBundle, KyberKeyPair, X25519KeyPair

logger = get_logger("protocol.handshake")


@dataclass
class HandshakeInitMessage:
    """Данные сообщения HANDSHAKE_INIT."""

    initiator_x25519_pub: bytes
    initiator_kyber_pub: bytes
    ephemeral_x25519_pub: bytes
    kyber_ciphertext: bytes

    def serialize(self) -> bytes:
        data = {
            "ix": self.initiator_x25519_pub.hex(),
            "ik": self.initiator_kyber_pub.hex(),
            "ex": self.ephemeral_x25519_pub.hex(),
            "kc": self.kyber_ciphertext.hex(),
        }
        return json.dumps(data, separators=(",", ":")).encode("utf-8")

    @classmethod
    def deserialize(cls, raw: bytes) -> HandshakeInitMessage:
        try:
            data = json.loads(raw)
            return cls(
                initiator_x25519_pub=bytes.fromhex(data["ix"]),
                initiator_kyber_pub=bytes.fromhex(data["ik"]),
                ephemeral_x25519_pub=bytes.fromhex(data["ex"]),
                kyber_ciphertext=bytes.fromhex(data["kc"]),
            )
        except Exception as e:
            raise HandshakeError(f"Ошибка разбора HANDSHAKE_INIT: {e}") from e


@dataclass
class HandshakeRespMessage:
    """Данные сообщения HANDSHAKE_RESP."""

    responder_x25519_pub: bytes
    responder_kyber_pub: bytes
    ephemeral_x25519_pub: bytes
    kyber_ciphertext: bytes
    encrypted_ack: bytes

    def serialize(self) -> bytes:
        data = {
            "rx": self.responder_x25519_pub.hex(),
            "rk": self.responder_kyber_pub.hex(),
            "ex": self.ephemeral_x25519_pub.hex(),
            "kc": self.kyber_ciphertext.hex(),
            "ea": self.encrypted_ack.hex(),
        }
        return json.dumps(data, separators=(",", ":")).encode("utf-8")

    @classmethod
    def deserialize(cls, raw: bytes) -> HandshakeRespMessage:
        try:
            data = json.loads(raw)
            return cls(
                responder_x25519_pub=bytes.fromhex(data["rx"]),
                responder_kyber_pub=bytes.fromhex(data["rk"]),
                ephemeral_x25519_pub=bytes.fromhex(data["ex"]),
                kyber_ciphertext=bytes.fromhex(data["kc"]),
                encrypted_ack=bytes.fromhex(data["ea"]),
            )
        except Exception as e:
            raise HandshakeError(f"Ошибка разбора HANDSHAKE_RESP: {e}") from e


class Handshake:
    """
    Менеджер гибридного Handshake.

    process_init требует явный список доверенных контактов.
    """

    @staticmethod
    def create_init(
        initiator: IdentityKeyBundle,
        responder_x25519_pub: bytes,
        responder_kyber_pub: bytes,
    ) -> tuple[HandshakeInitMessage, bytes]:
        """
        Создать HANDSHAKE_INIT (сторона инициатора).

        Returns:
            (init_message, shared_secret).
        """
        try:
            encap = HybridKEM.encapsulate(
                sender_x25519=initiator.x25519,
                recipient_x25519_pub=responder_x25519_pub,
                recipient_kyber_pub=responder_kyber_pub,
            )

            init_msg = HandshakeInitMessage(
                initiator_x25519_pub=initiator.x25519.serialize_public(),
                initiator_kyber_pub=initiator.kyber.public_key,
                ephemeral_x25519_pub=encap.x25519_ephemeral_pub,
                kyber_ciphertext=encap.kyber_ciphertext,
            )

            logger.info("HANDSHAKE_INIT создан")
            return init_msg, encap.shared_secret

        except Exception as e:
            raise HandshakeError(f"Ошибка создания HANDSHAKE_INIT: {e}") from e

    @staticmethod
    def process_init(
        responder: IdentityKeyBundle,
        init_msg: HandshakeInitMessage,
        trusted_contact_ids: set[str],
    ) -> tuple[HandshakeRespMessage, bytes]:
        """
        Обработать HANDSHAKE_INIT и создать HANDSHAKE_RESP (сторона респондента).

        Проверяет, что fingerprint инициатора входит в trusted_contact_ids.
        При неизвестном инициаторе выбрасывает UnknownPeerError — без раскрытия
        конкретной причины отказа (защита от fingerprinting атак).

        Args:
            responder: Ключи респондента.
            init_msg: Полученное HANDSHAKE_INIT сообщение.
            trusted_contact_ids: Множество разрешённых fingerprint'ов контактов.

        Returns:
            (resp_message, shared_secret).

        Raises:
            UnknownPeerError: Инициатор не в списке доверенных.
            HandshakeError: Ошибка протокола.
        """
        initiator_id = Identity.compute_id(
            init_msg.initiator_x25519_pub,
            init_msg.initiator_kyber_pub,
        )
        if initiator_id not in trusted_contact_ids:

            logger.warning(
                "Handshake отклонён: неизвестный инициатор %s...",
                initiator_id[:16],
            )
            raise UnknownPeerError(
                "Входящий handshake отклонён: инициатор не является доверенным контактом."
            )

        try:
            initiator_shared = HybridKEM.decapsulate(
                recipient_x25519=responder.x25519,
                recipient_kyber=responder.kyber,
                sender_x25519_ephemeral_pub=init_msg.ephemeral_x25519_pub,
                kyber_ciphertext=init_msg.kyber_ciphertext,
            )

            resp_encap = HybridKEM.encapsulate(
                sender_x25519=responder.x25519,
                recipient_x25519_pub=init_msg.initiator_x25519_pub,
                recipient_kyber_pub=init_msg.initiator_kyber_pub,
            )

            final_secret = KDF.derive(
                input_key=initiator_shared + resp_encap.shared_secret,
                info=HKDF_INFO_HANDSHAKE,
            )

            ack_data = b"HANDSHAKE_ACK_OK"
            encrypted_ack = AEAD.encrypt(final_secret, ack_data)

            resp_msg = HandshakeRespMessage(
                responder_x25519_pub=responder.x25519.serialize_public(),
                responder_kyber_pub=responder.kyber.public_key,
                ephemeral_x25519_pub=resp_encap.x25519_ephemeral_pub,
                kyber_ciphertext=resp_encap.kyber_ciphertext,
                encrypted_ack=encrypted_ack,
            )

            logger.info("HANDSHAKE_RESP создан для %s...", initiator_id[:16])
            return resp_msg, final_secret

        except (HandshakeError, UnknownPeerError):
            raise
        except Exception as e:
            raise HandshakeError(f"Ошибка обработки HANDSHAKE_INIT: {e}") from e

    @staticmethod
    def complete_handshake(
        initiator: IdentityKeyBundle,
        init_shared_secret: bytes,
        resp_msg: HandshakeRespMessage,
    ) -> bytes:
        """
        Завершить Handshake на стороне инициатора.

        Returns:
            Финальный общий секрет сессии.
        """
        try:
            # 1. Декапсуляция обратного KEM
            resp_shared = HybridKEM.decapsulate(
                recipient_x25519=initiator.x25519,
                recipient_kyber=initiator.kyber,
                sender_x25519_ephemeral_pub=resp_msg.ephemeral_x25519_pub,
                kyber_ciphertext=resp_msg.kyber_ciphertext,
            )

            # 2. Финальный секрет
            final_secret = KDF.derive(
                input_key=init_shared_secret + resp_shared,
                info=HKDF_INFO_HANDSHAKE,
            )

            # 3. Проверка ACK
            try:
                ack_data = AEAD.decrypt(final_secret, resp_msg.encrypted_ack)
                if ack_data != b"HANDSHAKE_ACK_OK":
                    raise HandshakeError("Неверное подтверждение Handshake")
            except Exception as e:
                raise HandshakeError(
                    f"Ошибка проверки ACK: {e}. Возможна атака MITM."
                ) from e

            logger.info("Handshake успешно завершён")
            return final_secret

        except HandshakeError:
            raise
        except Exception as e:
            raise HandshakeError(f"Ошибка завершения Handshake: {e}") from e
