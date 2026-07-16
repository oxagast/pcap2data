from src.backend.decoders.bittorrent import decodeBitTorrent
from src.backend.decoders.smpp import decodeSMPP
from src.backend.decoders.soulseek import decodeSoulseek


def test_decode_smpp_bind_transmitter_header():
    payload = bytes(
        [
            0x00,
            0x00,
            0x00,
            0x10,
            0x00,
            0x00,
            0x00,
            0x02,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x2A,
        ]
    )

    decoded = decodeSMPP(payload)

    assert decoded is not None
    assert decoded["Command"] == "bind_transmitter"
    assert decoded["Sequence Number"] == 42
    assert decoded["Body Length"] == 0


def test_decode_soulseek_length_prefixed_message():
    body = b"alice"
    message_length = (4 + len(body)).to_bytes(4, "little")
    message_code = (1).to_bytes(4, "little")
    payload = message_length + message_code + body

    decoded = decodeSoulseek(payload)

    assert decoded is not None
    assert decoded["Message Code"] == 1
    assert decoded["Message Length"] == 9
    assert decoded["Body Length"] == 5
    assert "alice" in decoded.get("Payload Preview", "")


def test_decode_bittorrent_handshake_payload():
    payload = (
        b"\x13BitTorrent protocol"
        + b"\x00" * 8
        + b"\xAA" * 20
        + b"-UT1000-abcdefghijkl"[:20]
    )

    decoded = decodeBitTorrent(payload)

    assert decoded is not None
    assert decoded["Type"] == "Handshake"
    assert decoded["Protocol"] == "BitTorrent protocol"
    assert decoded["bittorrent.signature"] == "handshake"


def test_decode_bittorrent_krpc_payload():
    payload = b"d1:ad2:id20:abcdefghij0123456789e1:q9:find_node1:t2:aa1:y1:qe"

    decoded = decodeBitTorrent(payload)

    assert decoded is not None
    assert decoded["Type"] == "DHT KRPC"
    assert decoded["Transaction Type"] == "q"
