"""Tests for the STP (IEEE 802.1D Spanning Tree Protocol) backend decoder."""

import struct
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.backend.decoders.stp import decodeSTP


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_config_bpdu(
    version=0,
    bpdu_type=0x00,
    flags=0x00,
    root_priority=0x8001,
    root_mac=b"\x00\x19\x06\xea\xb8\x80",
    root_path_cost=0,
    bridge_priority=0x8001,
    bridge_mac=b"\x00\x19\x06\xea\xb8\x80",
    port_id=0x8005,
    message_age=0,
    max_age=0x1400,
    hello_time=0x0200,
    fwd_delay=0x0F00,
):
    """Build a raw Configuration BPDU (starting at the LLC payload, i.e. after
    the 3-byte LLC header)."""
    bpdu = struct.pack(">HBB", 0x0000, version, bpdu_type)
    bpdu += struct.pack(">B", flags)
    bpdu += struct.pack(">H", root_priority) + root_mac
    bpdu += struct.pack(">I", root_path_cost)
    bpdu += struct.pack(">H", bridge_priority) + bridge_mac
    bpdu += struct.pack(">H", port_id)
    bpdu += struct.pack(">H", message_age)
    bpdu += struct.pack(">H", max_age)
    bpdu += struct.pack(">H", hello_time)
    bpdu += struct.pack(">H", fwd_delay)
    return bpdu


def _build_llc_stp_frame(bpdu):
    """Wrap a BPDU in the 3-byte LLC header (DSAP=0x42 SSAP=0x42 Control=0x03)."""
    return bytes([0x42, 0x42, 0x03]) + bpdu


class _LayerInstance:
    def __init__(self, raw_bytes=None, **attrs):
        self._raw = raw_bytes
        for key, value in attrs.items():
            setattr(self, key, value)

    def __bytes__(self):
        return self._raw if self._raw is not None else b""


class _PacketStub:
    """Minimal scapy-like packet stub for STP layer access."""

    def __init__(self, stp_bytes, layer_name="STP"):
        self._layer_name = layer_name
        self._stp_layer = _LayerInstance(
            raw_bytes=stp_bytes,
            **{
                "proto": struct.unpack_from(">H", stp_bytes, 0)[0],
                "version": int(stp_bytes[2]),
                "bpdutype": int(stp_bytes[3]),
                "bpduflags": int(stp_bytes[4]) if len(stp_bytes) > 4 else 0,
                "rootid": struct.unpack_from(">H", stp_bytes, 5)[0] if len(stp_bytes) >= 7 else 0,
                "rootmac": ":".join(f"{b:02x}" for b in stp_bytes[7:13]) if len(stp_bytes) >= 13 else "00:00:00:00:00:00",
                "pathcost": struct.unpack_from(">I", stp_bytes, 13)[0] if len(stp_bytes) >= 17 else 0,
                "bridgeid": struct.unpack_from(">H", stp_bytes, 17)[0] if len(stp_bytes) >= 19 else 0,
                "bridgemac": ":".join(f"{b:02x}" for b in stp_bytes[19:25]) if len(stp_bytes) >= 25 else "00:00:00:00:00:00",
                "portid": struct.unpack_from(">H", stp_bytes, 25)[0] if len(stp_bytes) >= 27 else 0,
                "age": (struct.unpack_from(">H", stp_bytes, 27)[0] / 256.0) if len(stp_bytes) >= 29 else 0.0,
                "maxage": (struct.unpack_from(">H", stp_bytes, 29)[0] / 256.0) if len(stp_bytes) >= 31 else 0.0,
                "hellotime": (struct.unpack_from(">H", stp_bytes, 31)[0] / 256.0) if len(stp_bytes) >= 33 else 0.0,
                "fwddelay": (struct.unpack_from(">H", stp_bytes, 33)[0] / 256.0) if len(stp_bytes) >= 35 else 0.0,
            }
        )
        # Store the raw bytes so __bytes__ can return them
        self._raw = stp_bytes

    def haslayer(self, name):
        key = getattr(name, "__name__", name)
        return str(key).lower() == self._layer_name.lower()

    def __getitem__(self, name):
        key = getattr(name, "__name__", name)
        if str(key).lower() == self._layer_name.lower():
            return self._stp_layer
        raise KeyError(key)

    def __bytes__(self):
        return self._raw


# ---------------------------------------------------------------------------
# Tests — Configuration BPDU via raw bytes
# ---------------------------------------------------------------------------

def test_decode_stp_config_bpdu_from_raw_llc_payload():
    """Configuration BPDU extracted from LLC payload (no scapy packet)."""
    bpdu = _build_config_bpdu()
    frame = _build_llc_stp_frame(bpdu)

    decoded = decodeSTP(p=None, linkRaw=frame)

    assert decoded is not None
    assert decoded["Protocol Identifier"] == 0
    assert decoded["stp.proto_id"] == 0
    assert decoded["Protocol Version"] == 0
    assert decoded["stp.version"] == 0
    assert decoded["BPDU Type"] == "Configuration BPDU"
    assert decoded["stp.bpdu_type"] == "Configuration BPDU"
    assert decoded["BPDU Type Code"] == "0x00"
    assert decoded["Type"] == "Config"
    assert decoded["stp.type"] == "Config"


def test_decode_stp_root_and_bridge_ids():
    """Root and Bridge IDs are decoded with priority + MAC."""
    bpdu = _build_config_bpdu(
        root_priority=0x8001,
        root_mac=b"\x00\x19\x06\xea\xb8\x80",
        bridge_priority=0x8001,
        bridge_mac=b"\x00\x19\x06\xea\xb8\x80",
    )
    frame = _build_llc_stp_frame(bpdu)

    decoded = decodeSTP(p=None, linkRaw=frame)

    assert decoded is not None
    assert decoded["Root Priority"] == 0x8001
    assert decoded["stp.root_priority"] == 0x8001
    assert decoded["Root MAC"] == "00:19:06:ea:b8:80"
    assert decoded["stp.root_mac"] == "00:19:06:ea:b8:80"
    assert decoded["Bridge Priority"] == 0x8001
    assert decoded["stp.bridge_priority"] == 0x8001
    assert decoded["Bridge MAC"] == "00:19:06:ea:b8:80"
    assert decoded["stp.bridge_mac"] == "00:19:06:ea:b8:80"
    # Bridge ID string format: Extended System ID — 0x8001 = base 8, VLAN 1
    assert decoded["Root Bridge ID"] == "8.1/00:19:06:ea:b8:80"
    assert decoded["stp.root_bridge_id"] == "8.1/00:19:06:ea:b8:80"
    assert decoded["Bridge ID"] == "8.1/00:19:06:ea:b8:80"
    assert decoded["stp.bridge_id"] == "8.1/00:19:06:ea:b8:80"


def test_decode_stp_timers_and_port():
    """STP timers are converted from 1/256s to human-readable seconds."""
    bpdu = _build_config_bpdu(
        port_id=0x8005,
        message_age=0x0000,
        max_age=0x1400,    # 20s
        hello_time=0x0200,  # 2s
        fwd_delay=0x0F00,  # 15s
    )
    frame = _build_llc_stp_frame(bpdu)

    decoded = decodeSTP(p=None, linkRaw=frame)

    assert decoded is not None
    assert decoded["Port ID"] == "0x8005"
    assert decoded["stp.port_id"] == "0x8005"
    assert decoded["Message Age"] == "0s"
    assert decoded["Max Age"] == "20s"
    assert decoded["Hello Time"] == "2s"
    assert decoded["Forward Delay"] == "15s"
    assert decoded["stp.max_age"] == "20s"
    assert decoded["stp.hello_time"] == "2s"
    assert decoded["stp.forward_delay"] == "15s"


def test_decode_stp_root_path_cost():
    """Root Path Cost is decoded as a 4-byte big-endian integer."""
    bpdu = _build_config_bpdu(root_path_cost=0x0000000A)
    frame = _build_llc_stp_frame(bpdu)

    decoded = decodeSTP(p=None, linkRaw=frame)

    assert decoded is not None
    assert decoded["Root Path Cost"] == 10
    assert decoded["stp.root_path_cost"] == 10


def test_decode_stp_flags_topology_change():
    """TC flag is decoded for classic STP."""
    bpdu = _build_config_bpdu(flags=0x01)
    frame = _build_llc_stp_frame(bpdu)

    decoded = decodeSTP(p=None, linkRaw=frame)

    assert decoded is not None
    assert "Topology Change (TC)" in decoded["Flags"]
    assert decoded["Flags Code"] == "0x01"
    assert decoded["stp.flags_code"] == "0x01"


def test_decode_stp_flags_tca():
    """TCA flag is decoded for classic STP."""
    bpdu = _build_config_bpdu(flags=0x80)
    frame = _build_llc_stp_frame(bpdu)

    decoded = decodeSTP(p=None, linkRaw=frame)

    assert decoded is not None
    assert "Topology Change Acknowledgment (TCA)" in decoded["Flags"]


def test_decode_stp_triple_key_namespace():
    """All three key variants (human, stp.*, link.stp.*) are present."""
    bpdu = _build_config_bpdu()
    frame = _build_llc_stp_frame(bpdu)

    decoded = decodeSTP(p=None, linkRaw=frame)

    assert decoded is not None
    # Check link.stp.* namespace keys
    assert "link.stp.proto_id" in decoded
    assert "link.stp.version" in decoded
    assert "link.stp.bpdu_type" in decoded
    assert "link.stp.root_bridge_id" in decoded
    assert "link.stp.bridge_id" in decoded
    assert "link.stp.root_path_cost" in decoded
    assert "link.stp.port_id" in decoded
    assert "link.stp.max_age" in decoded
    assert "link.stp.hello_time" in decoded
    assert "link.stp.forward_delay" in decoded


# ---------------------------------------------------------------------------
# Tests — TCN BPDU
# ---------------------------------------------------------------------------

def test_decode_stp_tcn_bpdu():
    """Topology Change Notification BPDU (type 0x80) has header only, no body."""
    # TCN BPDU: proto(2) + version(1) + type(1) = 4 bytes
    bpdu = struct.pack(">HBB", 0x0000, 0x00, 0x80)
    frame = _build_llc_stp_frame(bpdu)

    decoded = decodeSTP(p=None, linkRaw=frame)

    assert decoded is not None
    assert decoded["BPDU Type"] == "Topology Change Notification (TCN)"
    assert decoded["stp.bpdu_type"] == "Topology Change Notification (TCN)"
    assert decoded["Type"] == "TCN"
    assert decoded["stp.type"] == "TCN"
    # TCN has no flags or bridge fields
    assert "Flags" not in decoded
    assert "Root Bridge ID" not in decoded


# ---------------------------------------------------------------------------
# Tests — RSTP (Rapid Spanning Tree)
# ---------------------------------------------------------------------------

def test_decode_stp_rstp_bpdu():
    """RSTP BPDU (version=2, type=0x02) is detected and gets RSTP flag set."""
    bpdu = _build_config_bpdu(version=2, bpdu_type=0x02, flags=0x3C)
    frame = _build_llc_stp_frame(bpdu)

    decoded = decodeSTP(p=None, linkRaw=frame)

    assert decoded is not None
    assert decoded["Protocol Version"] == 2
    assert decoded["BPDU Type"] == "Rapid Spanning Tree (RSTP) BPDU"
    assert decoded["Type"] == "RSTP"
    assert decoded["stp.type"] == "RSTP"
    # RSTP flags: 0x3C = 0x04|0x08|0x10|0x20 = Learning|Forwarding|Agreement|Synchronization
    assert "Learning" in decoded["Flags"]
    assert "Forwarding" in decoded["Flags"]
    assert "Agreement" in decoded["Flags"]
    assert "Synchronization" in decoded["Flags"]


# ---------------------------------------------------------------------------
# Tests — Extended System ID (VLAN)
# ---------------------------------------------------------------------------

def test_decode_stp_extended_system_id_vlan():
    """Bridge priority with extended System ID (lower 12 bits = VLAN) is formatted."""
    # Priority 0x8100 = base 0x8 (32768+4096) + VLAN 0x100 (256)
    # Actually: 0x8100 → base_priority = 0x8100 >> 12 = 0x8 = 8
    #           vlan_id = 0x8100 & 0x0FFF = 0x100 = 256
    bpdu = _build_config_bpdu(
        root_priority=0x8100,
        bridge_priority=0x8100,
    )
    frame = _build_llc_stp_frame(bpdu)

    decoded = decodeSTP(p=None, linkRaw=frame)

    assert decoded is not None
    # Should show "8.256/..." format (base.vlan/mac)
    assert "256/" in decoded["Root Bridge ID"]
    assert "256/" in decoded["Bridge ID"]


# ---------------------------------------------------------------------------
# Tests — Scapy packet stub
# ---------------------------------------------------------------------------

def test_decode_stp_from_scapy_packet_stub():
    """STP decoder works when given a scapy-like packet with STP layer."""
    bpdu = _build_config_bpdu()
    p = _PacketStub(bpdu)

    decoded = decodeSTP(p=p, linkRaw=None)

    assert decoded is not None
    assert decoded["BPDU Type"] == "Configuration BPDU"
    assert decoded["stp.bpdu_type"] == "Configuration BPDU"
    assert decoded["Root MAC"] == "00:19:06:ea:b8:80"
    assert decoded["stp.root_mac"] == "00:19:06:ea:b8:80"


# ---------------------------------------------------------------------------
# Tests — Negative cases
# ---------------------------------------------------------------------------

def test_decode_stp_returns_none_for_non_stp_llc():
    """Non-STP LLC frame (wrong DSAP/SSAP) returns None."""
    # DSAP=0xAA (SNAP) instead of 0x42
    frame = bytes([0xAA, 0xAA, 0x03]) + _build_config_bpdu()
    decoded = decodeSTP(p=None, linkRaw=frame)
    assert decoded is None


def test_decode_stp_returns_none_for_wrong_protocol_id():
    """BPDU with non-zero protocol ID is rejected."""
    bpdu = struct.pack(">HBB", 0x0001, 0x00, 0x00)
    frame = _build_llc_stp_frame(bpdu)
    decoded = decodeSTP(p=None, linkRaw=frame)
    assert decoded is None


def test_decode_stp_returns_none_for_too_short():
    """Frames shorter than the BPDU header return None."""
    decoded = decodeSTP(p=None, linkRaw=bytes([0x42, 0x42, 0x03, 0x00]))
    assert decoded is None


def test_decode_stp_returns_none_for_empty():
    """Empty input returns None."""
    assert decodeSTP(p=None, linkRaw=None) is None
    assert decodeSTP(p=None, linkRaw=b"") is None


def test_decode_stp_returns_none_for_random_data():
    """Random non-BPDU data returns None."""
    assert decodeSTP(p=None, linkRaw=b"\x42\x42\x03\xff\xff\xff\xff") is None