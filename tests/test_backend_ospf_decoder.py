"""Tests for the OSPF (OSPFv2 + OSPFv3) backend decoder.

Covers all five message-type walks (Hello, DBD, LSR, LSU, LSAck) for both
OSPFv2 and OSPFv3, the LSA type library wiring, and area/neighbour topology
extraction.
"""

import struct
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.backend.decoders.ospf import (
    decodeOSPF,
    extractTopology,
    OSPF_LSA_TYPES_V2,
    OSPF_LSA_TYPES_V3,
)


# ---------------------------------------------------------------------------
# Packet builders
# ---------------------------------------------------------------------------

def _ip(addr):
    """Convert a dotted-quad string to 4 raw bytes."""
    return bytes(int(b) for b in addr.split("."))


def _build_ospf_v2_header(msgType, routerId, areaId, bodyLen, authType=0):
    """Build a 24-byte OSPFv2 header.  *bodyLen* is the length of the body
    that will be appended (total packet length = 24 + bodyLen)."""
    pktLen = 24 + bodyLen
    hdr = struct.pack(">BBH", 2, msgType, pktLen)
    hdr += _ip(routerId)
    hdr += _ip(areaId)
    hdr += struct.pack(">H", 0)          # checksum (ignored by decoder)
    hdr += struct.pack(">H", authType)   # auth type
    hdr += b"\x00" * 8                    # auth data
    return hdr


def _build_ospf_v3_header(msgType, routerId, areaId, bodyLen, instanceId=0):
    """Build a 16-byte OSPFv3 header."""
    pktLen = 16 + bodyLen
    hdr = struct.pack(">BBH", 3, msgType, pktLen)
    hdr += _ip(routerId)
    hdr += _ip(areaId)
    hdr += struct.pack(">H", 0)          # checksum
    hdr += struct.pack(">BB", instanceId, 0)
    return hdr


def _build_lsa_header_v2(lsType, linkStateId, advRouter, seq=1, length=20, age=10, options=0):
    """Build a 20-byte OSPFv2 LSA header."""
    hdr = struct.pack(">HBB", age, options, lsType)
    hdr += _ip(linkStateId)
    hdr += _ip(advRouter)
    hdr += struct.pack(">I", seq)
    hdr += struct.pack(">H", 0)  # checksum
    hdr += struct.pack(">H", length)
    return hdr


def _build_lsa_header_v3(lsType, linkStateId, advRouter, seq=1, length=20, age=10):
    """Build a 20-byte OSPFv3 LSA header."""
    hdr = struct.pack(">HH", age, lsType)
    hdr += _ip(linkStateId)
    hdr += _ip(advRouter)
    hdr += struct.pack(">I", seq)
    hdr += struct.pack(">H", 0)  # checksum
    hdr += struct.pack(">H", length)
    return hdr


# ---------------------------------------------------------------------------
# OSPFv2 tests
# ---------------------------------------------------------------------------

class TestOspfV2Hello:
    def test_hello_with_neighbors(self):
        body = _ip("255.255.255.0")          # network mask
        body += struct.pack(">H", 10)         # hello interval
        body += bytes([0x02])                 # options
        body += bytes([1])                    # priority
        body += struct.pack(">I", 40)         # dead interval
        body += _ip("10.0.0.1")               # DR
        body += _ip("10.0.0.2")               # BDR
        body += _ip("1.1.1.2")               # neighbor 1
        body += _ip("1.1.1.3")               # neighbor 2
        raw = _build_ospf_v2_header(1, "1.1.1.1", "0.0.0.0", len(body)) + body
        result = decodeOSPF(None, raw)
        assert result is not None
        assert result["Type"] == "Hello"
        assert result["Router ID"] == "1.1.1.1"
        assert result["Hello Interval (s)"] == 10
        assert result["Dead Interval (s)"] == 40
        assert result["Designated Router"] == "10.0.0.1"
        assert result["Active Neighbors"] == ["1.1.1.2", "1.1.1.3"]
        assert result["Neighbor Count"] == 2

    def test_hello_no_neighbors(self):
        body = _ip("255.255.255.0")
        body += struct.pack(">H", 10)
        body += bytes([0x02, 1])
        body += struct.pack(">I", 40)
        body += _ip("0.0.0.0")
        body += _ip("0.0.0.0")
        raw = _build_ospf_v2_header(1, "1.1.1.1", "0.0.0.0", len(body)) + body
        result = decodeOSPF(None, raw)
        assert result is not None
        assert result["Type"] == "Hello"
        assert "Active Neighbors" not in result


class TestOspfV2Dbd:
    def test_dbd_with_lsa_headers(self):
        body = struct.pack(">H", 1500)       # MTU
        body += bytes([0x02])                 # options
        body += bytes([0x07])                 # flags: MS | M | I
        body += struct.pack(">I", 42)         # sequence
        # Two LSA headers
        lsa1 = _build_lsa_header_v2(1, "10.0.0.1", "1.1.1.1")
        lsa2 = _build_lsa_header_v2(2, "10.0.0.2", "1.1.1.2")
        body += lsa1 + lsa2
        raw = _build_ospf_v2_header(2, "1.1.1.1", "0.0.0.0", len(body)) + body
        result = decodeOSPF(None, raw)
        assert result is not None
        assert result["Type"] == "Database Description"
        assert result["Interface MTU"] == 1500
        assert "MS" in result["DD Flags"]
        assert "M" in result["DD Flags"]
        assert "I" in result["DD Flags"]
        assert result["DD Sequence"] == 42
        assert len(result["LSA Headers"]) == 2
        assert result["LSA Headers"][0]["LS Type"] == "Router-LSA"
        assert result["LSA Headers"][1]["LS Type"] == "Network-LSA"


class TestOspfV2Lsr:
    def test_lsr_entries(self):
        body = b""
        # LSR entry: 3 reserved + 1 type + 4 LS ID + 4 adv router = 12
        body += bytes([0, 0, 0, 1]) + _ip("10.0.0.1") + _ip("1.1.1.1")
        body += bytes([0, 0, 0, 2]) + _ip("10.0.0.2") + _ip("1.1.1.2")
        raw = _build_ospf_v2_header(3, "1.1.1.1", "0.0.0.0", len(body)) + body
        result = decodeOSPF(None, raw)
        assert result is not None
        assert result["Type"] == "Link State Request"
        assert len(result["LS Requests"]) == 2
        assert result["LS Requests"][0]["LS Type"] == "Router-LSA"
        assert result["LS Requests"][1]["LS Type"] == "Network-LSA"
        assert result["ospf.lsr_count"] == 2


class TestOspfV2Lsu:
    def test_lsu_router_lsa_with_links(self):
        # Router-LSA body: 1 flags + 1 reserved + 2 numLinks + links (12 each)
        lsaBody = bytes([0x02, 0x00]) + struct.pack(">H", 1)  # E flag, 1 link
        lsaBody += _ip("10.0.0.1")       # Link ID
        lsaBody += _ip("255.255.255.0")  # Link Data
        lsaBody += bytes([1])            # Type: point-to-point
        lsaBody += bytes([0])            # TOS count
        lsaBody += struct.pack(">H", 10)  # metric
        lsaHdr = _build_lsa_header_v2(1, "1.1.1.1", "1.1.1.1",
                                      length=20 + len(lsaBody))
        lsa = lsaHdr + lsaBody

        body = struct.pack(">I", 1) + lsa  # count=1 + LSA
        raw = _build_ospf_v2_header(4, "1.1.1.1", "0.0.0.0", len(body)) + body
        result = decodeOSPF(None, raw)
        assert result is not None
        assert result["Type"] == "Link State Update"
        assert result["LSA Count"] == 1
        assert len(result["LSAs"]) == 1
        lsa = result["LSAs"][0]
        assert lsa["LS Type"] == "Router-LSA"
        assert "E (ASBR)" in lsa["V/B Flags"]
        assert lsa["Link Count"] == 1
        assert len(lsa["Links"]) == 1
        assert lsa["Links"][0]["Type"] == "Point-to-point connection"
        assert lsa["Links"][0]["Metric"] == 10

    def test_lsu_network_lsa(self):
        # Network-LSA body: 4 mask + 4+4 attached routers
        lsaBody = _ip("255.255.255.0") + _ip("1.1.1.1") + _ip("1.1.1.2")
        lsaHdr = _build_lsa_header_v2(2, "10.0.0.1", "1.1.1.1",
                                      length=20 + len(lsaBody))
        lsa = lsaHdr + lsaBody
        body = struct.pack(">I", 1) + lsa
        raw = _build_ospf_v2_header(4, "1.1.1.1", "0.0.0.0", len(body)) + body
        result = decodeOSPF(None, raw)
        assert result is not None
        lsa = result["LSAs"][0]
        assert lsa["LS Type"] == "Network-LSA"
        assert lsa["Network Mask"] == "255.255.255.0"
        assert lsa["Attached Routers"] == ["1.1.1.1", "1.1.1.2"]

    def test_lsu_external_lsa(self):
        # AS-External-LSA body: 4 mask + 4 metric + 4 fwd addr + 4 route tag
        lsaBody = _ip("255.255.255.0")
        lsaBody += struct.pack(">I", 100)
        lsaBody += _ip("10.0.0.1")
        lsaBody += struct.pack(">I", 0)
        lsaHdr = _build_lsa_header_v2(5, "0.0.0.0", "1.1.1.1",
                                      length=20 + len(lsaBody))
        lsa = lsaHdr + lsaBody
        body = struct.pack(">I", 1) + lsa
        raw = _build_ospf_v2_header(4, "1.1.1.1", "0.0.0.0", len(body)) + body
        result = decodeOSPF(None, raw)
        assert result is not None
        lsa = result["LSAs"][0]
        assert lsa["LS Type"] == "AS-External-LSA"
        assert lsa["Forwarding Address"] == "10.0.0.1"


class TestOspfV2Lsack:
    def test_lsack_headers(self):
        lsa1 = _build_lsa_header_v2(1, "10.0.0.1", "1.1.1.1")
        lsa2 = _build_lsa_header_v2(3, "10.0.0.3", "1.1.1.3")
        body = lsa1 + lsa2
        raw = _build_ospf_v2_header(5, "1.1.1.1", "0.0.0.0", len(body)) + body
        result = decodeOSPF(None, raw)
        assert result is not None
        assert result["Type"] == "Link State ACK"
        assert len(result["LSA ACKs"]) == 2
        assert result["LSA ACKs"][0]["LS Type"] == "Router-LSA"
        assert result["ospf.lsack_count"] == 2


# ---------------------------------------------------------------------------
# OSPFv3 tests
# ---------------------------------------------------------------------------

class TestOspfV3Hello:
    def test_hello_v3(self):
        body = struct.pack(">I", 1)          # interface ID
        body += bytes([1])                    # priority
        body += bytes([0x00, 0x00, 0x13])     # 3-byte options
        body += struct.pack(">H", 10)         # hello interval
        body += struct.pack(">H", 40)         # dead interval
        body += _ip("10.0.0.1")               # DR
        body += _ip("10.0.0.2")               # BDR
        body += _ip("1.1.1.2")               # neighbor
        raw = _build_ospf_v3_header(1, "1.1.1.1", "0.0.0.0", len(body)) + body
        result = decodeOSPF(None, raw)
        assert result is not None
        assert result["Version"] == "OSPFv3"
        assert result["Type"] == "Hello"
        assert result["Interface ID"] == 1
        assert result["Hello Interval (s)"] == 10
        assert result["Active Neighbors"] == ["1.1.1.2"]


class TestOspfV3Dbd:
    def test_dbd_v3(self):
        body = bytes([0])                          # reserved
        body += bytes([0x00, 0x00, 0x13])          # 3-byte options
        body += struct.pack(">H", 1500)            # MTU
        body += bytes([0])                          # reserved
        body += bytes([0x06])                       # flags: M | I
        body += struct.pack(">I", 99)              # sequence
        lsa1 = _build_lsa_header_v3(0x2001, "1.1.1.1", "1.1.1.1")
        body += lsa1
        raw = _build_ospf_v3_header(2, "1.1.1.1", "0.0.0.0", len(body)) + body
        result = decodeOSPF(None, raw)
        assert result is not None
        assert result["Type"] == "Database Description"
        assert result["Interface MTU"] == 1500
        assert "M" in result["DD Flags"]
        assert "I" in result["DD Flags"]
        assert result["DD Sequence"] == 99
        assert len(result["LSA Headers"]) == 1
        assert result["LSA Headers"][0]["LS Type"] == "Router-LSA"


class TestOspfV3Lsr:
    def test_lsr_v3(self):
        body = struct.pack(">H", 0x2001)   # LS type
        body += struct.pack(">H", 0)       # reserved
        body += _ip("1.1.1.1")             # link state ID
        body += _ip("1.1.1.2")             # adv router
        raw = _build_ospf_v3_header(3, "1.1.1.1", "0.0.0.0", len(body)) + body
        result = decodeOSPF(None, raw)
        assert result is not None
        assert result["Type"] == "Link State Request"
        assert len(result["LS Requests"]) == 1
        assert result["LS Requests"][0]["LS Type"] == "Router-LSA"


class TestOspfV3Lsu:
    def test_lsu_v3_router_lsa(self):
        # OSPFv3 Router-LSA body: 1 flags + 1 options + 2 numLinks + 16/link
        lsaBody = bytes([0x00, 0x00]) + struct.pack(">H", 1)
        lsaBody += struct.pack(">I", 1)       # interface ID
        lsaBody += struct.pack(">I", 2)       # neighbor interface ID
        lsaBody += _ip("1.1.1.2")             # neighbor router ID
        lsaBody += struct.pack(">H", 10)      # metric
        lsaBody += bytes([1])                 # type: point-to-point
        lsaBody += bytes([0])                 # reserved
        lsaHdr = _build_lsa_header_v3(0x2001, "1.1.1.1", "1.1.1.1",
                                      length=20 + len(lsaBody))
        lsa = lsaHdr + lsaBody
        body = struct.pack(">I", 1) + lsa
        raw = _build_ospf_v3_header(4, "1.1.1.1", "0.0.0.0", len(body)) + body
        result = decodeOSPF(None, raw)
        assert result is not None
        assert result["LSA Count"] == 1
        lsa = result["LSAs"][0]
        assert lsa["LS Type"] == "Router-LSA"
        assert lsa["Link Count"] == 1
        assert len(lsa["Links"]) == 1
        assert lsa["Links"][0]["Metric"] == 10


class TestOspfV3Lsack:
    def test_lsack_v3(self):
        lsa1 = _build_lsa_header_v3(0x2001, "1.1.1.1", "1.1.1.1")
        raw = _build_ospf_v3_header(5, "1.1.1.1", "0.0.0.0", len(lsa1)) + lsa1
        result = decodeOSPF(None, raw)
        assert result is not None
        assert result["Type"] == "Link State ACK"
        assert len(result["LSA ACKs"]) == 1


# ---------------------------------------------------------------------------
# LSA type library tests
# ---------------------------------------------------------------------------

class TestLsaTypeLibrary:
    def test_v2_library_has_all_core_types(self):
        for code, name in [(1, "Router-LSA"), (2, "Network-LSA"),
                           (3, "Summary-LSA"), (5, "AS-External-LSA"),
                           (7, "Type-7-LSA"), (10, "Opaque-LSA")]:
            assert code in OSPF_LSA_TYPES_V2
            assert name.split("-")[0] in OSPF_LSA_TYPES_V2[code]

    def test_v3_library_has_all_core_types(self):
        for code, name in [(1, "Router-LSA"), (2, "Network-LSA"),
                           (5, "AS-External"), (8, "Link-LSA"),
                           (9, "Intra-Area-Prefix")]:
            assert code in OSPF_LSA_TYPES_V3
            assert name.split("-")[0] in OSPF_LSA_TYPES_V3[code]

    def test_lsa_type_annotated_in_lsu(self):
        lsaHdr = _build_lsa_header_v2(1, "1.1.1.1", "1.1.1.1")
        body = struct.pack(">I", 1) + lsaHdr
        raw = _build_ospf_v2_header(4, "1.1.1.1", "0.0.0.0", len(body)) + body
        result = decodeOSPF(None, raw)
        assert result["LSAs"][0]["LS Type"] == "Router-LSA"


# ---------------------------------------------------------------------------
# Topology extraction tests
# ---------------------------------------------------------------------------

class TestTopologyExtraction:
    def test_hello_adjacency(self):
        pkt1 = decodeOSPF(None, _build_v2_hello("1.1.1.1", "0.0.0.0", ["1.1.1.2"]))
        pkt2 = decodeOSPF(None, _build_v2_hello("1.1.1.2", "0.0.0.0", ["1.1.1.1"]))
        topo = extractTopology([pkt1, pkt2])
        assert topo["summary"]["areas"] == 1
        assert topo["summary"]["routers"] == 2
        assert topo["summary"]["adjacencies"] == 1
        assert "1.1.1.1 <-> 1.1.1.2" in topo["adjacencies"]

    def test_lsu_feeds_lsa_graph(self):
        lsaHdr = _build_lsa_header_v2(1, "1.1.1.1", "1.1.1.1")
        body = struct.pack(">I", 1) + lsaHdr
        raw = _build_ospf_v2_header(4, "1.1.1.1", "0.0.0.1", len(body)) + body
        pkt = decodeOSPF(None, raw)
        topo = extractTopology([pkt])
        assert "1.1.1.1" in topo["lsa_graph"]
        assert topo["lsa_graph"]["1.1.1.1"][0]["type"] == "Router-LSA"
        assert topo["lsa_graph"]["1.1.1.1"][0]["area"] == "0.0.0.1"

    def test_multiple_areas(self):
        pkt1 = decodeOSPF(None, _build_v2_hello("1.1.1.1", "0.0.0.0", []))
        pkt2 = decodeOSPF(None, _build_v2_hello("2.2.2.2", "0.0.0.1", []))
        topo = extractTopology([pkt1, pkt2])
        assert topo["summary"]["areas"] == 2
        assert "0.0.0.0" in topo["areas"]
        assert "0.0.0.1" in topo["areas"]

    def test_empty_input(self):
        topo = extractTopology([])
        assert topo["summary"]["areas"] == 0
        assert topo["summary"]["routers"] == 0
        assert topo["summary"]["adjacencies"] == 0


def _build_v2_hello(routerId, areaId, neighbors):
    """Build a minimal OSPFv2 Hello packet."""
    body = _ip("255.255.255.0")
    body += struct.pack(">H", 10)
    body += bytes([0x02, 1])
    body += struct.pack(">I", 40)
    body += _ip("0.0.0.0")
    body += _ip("0.0.0.0")
    for n in neighbors:
        body += _ip(n)
    return _build_ospf_v2_header(1, routerId, areaId, len(body)) + body


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_too_short(self):
        assert decodeOSPF(None, b"\x02\x01") is None

    def test_invalid_version(self):
        assert decodeOSPF(None, b"\x01\x01" + b"\x00" * 30) is None

    def test_unknown_msg_type(self):
        raw = _build_ospf_v2_header(99, "1.1.1.1", "0.0.0.0", 0)
        result = decodeOSPF(None, raw)
        assert result is not None
        assert "Unknown" in result["Type"]

    def test_none_payload(self):
        assert decodeOSPF(None, None) is None