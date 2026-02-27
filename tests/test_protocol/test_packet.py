"""Тесты структуры пакетов и протокола Handshake."""

import struct

from pqc_messenger.protocol.packet import Packet, PacketType
from pqc_messenger.protocol.handshake import Handshake
from pqc_messenger.crypto.keys import IdentityKeyBundle


class TestPacket:
    """Тесты для Packet."""

    def test_serialize_deserialize(self):
        """Roundtrip сериализации/десериализации пакета."""
        original = Packet(
            packet_type=PacketType.MESSAGE,
            recipient_hash=b"\xab" * 32,
            payload=b"encrypted_data_here",
        )

        serialized = original.serialize()
        restored = Packet.deserialize(serialized)

        assert restored.version == original.version
        assert restored.packet_type == original.packet_type
        assert restored.recipient_hash == original.recipient_hash
        assert restored.payload == original.payload
        assert restored.timestamp == original.timestamp

    def test_all_packet_types(self):
        """Все типы пакетов корректно сериализуются."""
        for ptype in PacketType:
            packet = Packet(
                packet_type=ptype,
                recipient_hash=b"\x00" * 32,
                payload=b"test",
            )
            data = packet.serialize()
            restored = Packet.deserialize(data)
            assert restored.packet_type == ptype

    def test_empty_payload(self):
        """Пакет с пустой нагрузкой."""
        packet = Packet(
            packet_type=PacketType.ACK,
            recipient_hash=b"\xff" * 32,
            payload=b"",
        )
        data = packet.serialize()
        restored = Packet.deserialize(data)
        assert restored.payload == b""

    def test_large_payload(self):
        """Пакет с большой нагрузкой."""
        payload = b"\xde" * 65536
        packet = Packet(
            packet_type=PacketType.MESSAGE,
            recipient_hash=b"\x01" * 32,
            payload=payload,
        )
        data = packet.serialize()
        restored = Packet.deserialize(data)
        assert restored.payload == payload

    def test_header_bytes_for_aad(self):
        """Заголовок можно использовать как AAD."""
        packet = Packet(
            packet_type=PacketType.MESSAGE,
            recipient_hash=b"\x42" * 32,
            payload=b"data",
        )
        header = packet.header_bytes()
        assert len(header) == 42  # 1 + 1 + 32 + 8


class TestHandshake:
    """Тесты для Handshake протокола."""

    def test_create_init(self):
        """Создание HANDSHAKE_INIT."""
        alice = IdentityKeyBundle.generate()
        bob = IdentityKeyBundle.generate()
        bob_pub = bob.public_bundle()

        init_msg, shared_secret = Handshake.create_init(
            initiator=alice,
            responder_x25519_pub=bob_pub["x25519"],
            responder_kyber_pub=bob_pub["kyber"],
        )

        assert init_msg.initiator_x25519_pub == alice.x25519.serialize_public()
        assert len(shared_secret) == 32

    def test_init_serialize_deserialize(self):
        """Roundtrip сериализации HANDSHAKE_INIT."""
        from pqc_messenger.protocol.handshake import HandshakeInitMessage

        alice = IdentityKeyBundle.generate()
        bob = IdentityKeyBundle.generate()
        bob_pub = bob.public_bundle()

        init_msg, _ = Handshake.create_init(
            initiator=alice,
            responder_x25519_pub=bob_pub["x25519"],
            responder_kyber_pub=bob_pub["kyber"],
        )

        raw = init_msg.serialize()
        restored = HandshakeInitMessage.deserialize(raw)

        assert restored.initiator_x25519_pub == init_msg.initiator_x25519_pub
        assert restored.kyber_ciphertext == init_msg.kyber_ciphertext
