import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.backend.decoders.wan_link import decodeWanLinkProtocols


class _LayerType:
    def __init__(self, name):
        self.__name__ = name


class _LayerInstance:
    def __init__(self, **attrs):
        for key, value in attrs.items():
            setattr(self, key, value)


class _PacketStub:
    def __init__(self, layer_names, layer_map):
        self._layer_names = list(layer_names)
        self._layer_map = {str(key).lower(): value for key, value in layer_map.items()}

    def layers(self):
        return [_LayerType(name) for name in self._layer_names]

    def haslayer(self, layer_name):
        key = getattr(layer_name, "__name__", layer_name)
        return str(key).lower() in self._layer_map

    def __getitem__(self, layer_name):
        key = getattr(layer_name, "__name__", layer_name)
        return self._layer_map[str(key).lower()]


def test_decode_wan_link_protocols_detects_pppoe_session_and_ppp_fields():
    packet = _PacketStub(
        layer_names=["Ether", "PPPoE", "PPP"],
        layer_map={
            "ether": _LayerInstance(type=0x8864),
            "pppoe": _LayerInstance(code=0x00, sessionid=0x0042),
            "ppp": _LayerInstance(proto=0x0021),
        },
    )

    decoded = decodeWanLinkProtocols(packet)

    assert decoded is not None
    assert "PPP" in decoded["wan.detected"]
    assert "PPPoE" in decoded["wan.detected"]
    assert decoded["PPP Protocol Field"] == "0x0021 (IPv4)"
    assert decoded["link.proto"] == "pppoe"
    assert decoded["pppoe.stage"] == "Session"
    assert decoded["pppoe.code"] == "0x00 (Session)"
    assert decoded["pppoe.session_id"] == "0x0042"
    assert decoded["ether.type"] == "0x8864"


def test_decode_wan_link_protocols_detects_pppoe_discovery_frames():
    packet = _PacketStub(
        layer_names=["Ether", "PPPoE"],
        layer_map={
            "ether": _LayerInstance(type=0x8863),
            "pppoe": _LayerInstance(code=0x09, sessionid=0x0000),
        },
    )

    decoded = decodeWanLinkProtocols(packet)

    assert decoded is not None
    assert "PPPoE" in decoded["wan.detected"]
    assert decoded["pppoe.stage"] == "Discovery"
    assert decoded["pppoe.code"] == "0x09 (PADI)"
    assert decoded["ether.type"] == "0x8863"


def test_decode_wan_link_protocols_detects_lldp_by_ethertype_and_fields():
    packet = _PacketStub(
        layer_names=["Ether", "LLDP"],
        layer_map={
            "ether": _LayerInstance(type=0x88CC),
            "lldp": _LayerInstance(chassisid="00:11:22:33:44:55", portid="Gi1/0/1", ttl=120),
        },
    )

    decoded = decodeWanLinkProtocols(packet)

    assert decoded is not None
    assert "LLDP" in decoded["wan.detected"]
    assert decoded["link.proto"] in {"lldp", "ether"}
    assert decoded["ether.type"] == "0x88cc"
    assert decoded["lldp.chassis_id"] == "00:11:22:33:44:55"
    assert decoded["lldp.port_id"] == "Gi1/0/1"
    assert decoded["lldp.ttl"] == 120
