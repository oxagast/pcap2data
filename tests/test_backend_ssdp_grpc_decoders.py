"""Focused unit tests for SSDP/UPnP and gRPC backend decoders."""

from src.backend.decoders.grpc import decodeGRPC
from src.backend.decoders.ssdp import decodeSSDP


def test_ssdp_upnp_response():
    payload = (
        b"HTTP/1.1 200 OK\r\n"
        b"CACHE-CONTROL: max-age=1800\r\n"
        b"LOCATION: http://192.0.2.10/rootDesc.xml\r\n"
        b"ST: upnp:rootdevice\r\n\r\n"
    )
    decoded = decodeSSDP(payload)
    assert decoded is not None
    assert decoded["Protocol Profile"] == "UPnP"
    assert decoded["UPnP"] is True
    assert decoded["Location"] == "http://192.0.2.10/rootDesc.xml"


def test_ssdp_msearch():
    payload = (
        b"M-SEARCH * HTTP/1.1\r\n"
        b"HOST: 239.255.255.250:1900\r\n"
        b"MAN: \"ssdp:discover\"\r\n"
        b"MX: 1\r\n"
        b"ST: ssdp:all\r\n\r\n"
    )
    decoded = decodeSSDP(payload)
    assert decoded is not None
    assert decoded["Type"] == "M-SEARCH"
    assert decoded["Protocol Profile"] == "SSDP"


def test_grpc_envelope():
    payload = bytes([0, 0, 0, 0, 3, 0x0A, 0x01, 0x78])
    decoded = decodeGRPC(payload)
    assert decoded is not None
    assert decoded["Profile"] == "gRPC"
    assert decoded["Message Count"] == 1
    assert decoded["Messages"][0]["length"] == 3


def test_grpc_rejects_bad_envelope():
    assert decodeGRPC(bytes([0, 0, 0, 0, 4, 1])) is None
    assert decodeGRPC(bytes([2, 0, 0, 0, 0])) is None
