"""Unit tests for the IEEE 802.11 (WEP) decoder path.

These tests cover the WEP-decryption parity contract: WEP frames
should round-trip through `decryptWifiPayload` with the same shape
that AES-CCMP frames do, but without requiring a 4-way handshake.

The decoder is loaded directly so the tests are independent of the
backend's HTTP service and can be run quickly during local development.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


def _load_decoder():
    decoder_path = _PROJECT_ROOT / "src" / "backend" / "decoders" / "wireless_80211.py"
    spec = importlib.util.spec_from_file_location(
        "wireless_80211_wep_unit_test", decoder_path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load wireless_80211 decoder module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_get_wireless_layers_recognises_dot11wep():
    """getWirelessLayers should surface Dot11WEP as the encrypted layer
    so the WEP decryption branch can pick up the IV from the proper
    scapy attribute (mirroring how the CCMP path picks up Dot11CCMP)."""
    decoder = _load_decoder()
    from scapy.all import rdpcap
    from scapy.layers.dot11 import Dot11WEP

    pcap_path = _PROJECT_ROOT / "samples" / "pcaps" / "wep-smaller.pcap"
    if not pcap_path.exists():
        pytest.skip(f"WEP sample pcap not found: {pcap_path}")

    pkts = rdpcap(str(pcap_path))
    wep_frames = [p for p in pkts[:20] if p.haslayer(Dot11WEP)]
    assert wep_frames, "Expected at least one WEP frame in the sample pcap"

    for p in wep_frames:
        dot11, _, encrypted = decoder.getWirelessLayers(p)
        assert dot11 is not None, "Dot11 layer should be present on a WEP frame"
        assert encrypted is not None, (
            "Dot11WEP should be returned as the encrypted layer, not None"
        )
        assert isinstance(encrypted, Dot11WEP), (
            f"Expected Dot11WEP layer, got {type(encrypted).__name__}"
        )


def test_wep_decrypt_produces_valid_llc_snap_plaintext():
    """The WEP-40 RC4 decryptor should recover bytes that start with
    the LLC/SNAP header (DSAP=0xAA SSAP=0xAA Control=0x03) and contain
    a valid EtherType in the IANA assignment range."""
    decoder = _load_decoder()
    from scapy.all import rdpcap
    from scapy.layers.dot11 import Dot11WEP

    pcap_path = _PROJECT_ROOT / "samples" / "pcaps" / "wep-smaller.pcap"
    if not pcap_path.exists():
        pytest.skip(f"WEP sample pcap not found: {pcap_path}")

    pkts = rdpcap(str(pcap_path))
    wep_frames = [p for p in pkts[:50] if p.haslayer(Dot11WEP)]
    assert wep_frames, "Expected at least one WEP frame in the sample pcap"

    wep_key = b"\xA4\x81\x53\xB4\xCF"
    for p in wep_frames:
        plaintext, _icv_ok = decoder._wepDecrypt(wep_key, bytes(p[Dot11WEP]))
        assert plaintext is not None, "WEP decrypt should not return None for the right key"
        assert plaintext[:3] == b"\xaa\xaa\x03", (
            f"Plaintext must start with LLC/SNAP header; got {plaintext[:8].hex()}"
        )
        assert decoder._wepPlaintextLooksValid(plaintext), (
            "Plaintext sanity check (LLC/SNAP + valid EtherType) should pass"
        )


def test_wep_decrypt_rejects_wrong_key_with_sanity_check():
    """A wrong WEP key should produce garbage that fails the plaintext
    sanity check (LLC/SNAP + valid EtherType), even though the
    underlying RC4 always 'succeeds' technically.  This is the guard
    that prevents false positives when ICV verification is lenient
    (WEP pcaps often have corrupt ICVs)."""
    decoder = _load_decoder()
    from scapy.all import rdpcap
    from scapy.layers.dot11 import Dot11WEP

    pcap_path = _PROJECT_ROOT / "samples" / "pcaps" / "wep-smaller.pcap"
    if not pcap_path.exists():
        pytest.skip(f"WEP sample pcap not found: {pcap_path}")

    pkts = rdpcap(str(pcap_path))
    wep_frames = [p for p in pkts[:50] if p.haslayer(Dot11WEP)]
    assert wep_frames, "Expected at least one WEP frame in the sample pcap"

    wrong_key = b"\xDE\xAD\xBE\xEF\xCA"
    false_positives = 0
    for p in wep_frames:
        plaintext, _ = decoder._wepDecrypt(wrong_key, bytes(p[Dot11WEP]))
        if plaintext is not None and decoder._wepPlaintextLooksValid(plaintext):
            false_positives += 1
    assert false_positives == 0, (
        f"Wrong key must never produce a plaintext that passes the "
        f"sanity check; got {false_positives}/{len(wep_frames)} false "
        f"positives"
    )


def test_decrypt_wifi_payload_wep_returns_parity_shape():
    """decryptWifiPayload should return the same dict shape for WEP
    as it does for CCMP: ``{ok, plaintextHex, algorithm, ssid, bssid}``
    with ``algorithm`` set to "WEP".  This is the API contract that
    the renderer relies on for both wifi-wpa-psk and wifi-wep keys."""
    decoder = _load_decoder()
    from scapy.all import rdpcap
    from scapy.layers.dot11 import Dot11WEP

    pcap_path = _PROJECT_ROOT / "samples" / "pcaps" / "wep-smaller.pcap"
    if not pcap_path.exists():
        pytest.skip(f"WEP sample pcap not found: {pcap_path}")

    pkts = rdpcap(str(pcap_path))
    wep_frames = [p for p in pkts[:20] if p.haslayer(Dot11WEP)]
    assert wep_frames, "Expected at least one WEP frame in the sample pcap"

    wep_key_hex = "A48153B4CF"
    p = wep_frames[0]
    result = decoder.decryptWifiPayload(p, [{"wepKeyHex": wep_key_hex}])
    assert isinstance(result, dict), "decryptWifiPayload must return a dict"
    assert result.get("ok") is True, (
        f"Right WEP key should decrypt; got {result}"
    )
    assert result.get("algorithm") == "WEP"
    assert isinstance(result.get("plaintextHex"), str)
    assert len(result["plaintextHex"]) > 0
    # BSSID should be set so the renderer can attribute the key.
    assert result.get("bssid") is not None


def test_wep_plaintext_looks_valid_rejects_obvious_garbage():
    """The plaintext sanity check must reject arbitrary bytes that
    happen to look IPv4-ish (top nibble 4) but lack an LLC/SNAP or
    Ethernet II header.  This is the regression test for the
    earlier false-positive that affected the wrong key."""
    decoder = _load_decoder()
    # Random bytes with top nibble 4 but no real frame structure.
    fake_garbage = b"\x40\x00\x00\x00" + b"\x00" * 60
    assert not decoder._wepPlaintextLooksValid(fake_garbage), (
        "Garbage without LLC/SNAP or Ethernet II header must be rejected"
    )
    # Bytes whose EtherType at offset 12 is below the IANA assignment
    # range must also be rejected (the "EtherType" check).
    fake_garbage2 = b"\x00" * 12 + b"\x00\x00" + b"\x00" * 60
    assert not decoder._wepPlaintextLooksValid(fake_garbage2)


def test_wep_plaintext_looks_valid_accepts_known_ethertypes():
    """LLC/SNAP-wrapped frames with a known IANA EtherType (IPv4,
    IPv6, ARP, EAPOL) must be accepted.  These are the most common
    payloads in 802.11 data frames."""
    decoder = _load_decoder()
    # LLC/SNAP + IPv4
    pt_ipv4 = b"\xaa\xaa\x03\x00\x00\x00\x08\x00" + b"\x45" + b"\x00" * 20
    assert decoder._wepPlaintextLooksValid(pt_ipv4)
    # LLC/SNAP + IPv6
    pt_ipv6 = b"\xaa\xaa\x03\x00\x00\x00\x86\xDD" + b"\x60" + b"\x00" * 20
    assert decoder._wepPlaintextLooksValid(pt_ipv6)
    # LLC/SNAP + EAPOL
    pt_eapol = b"\xaa\xaa\x03\x00\x00\x00\x88\x8E" + b"\x02" + b"\x00" * 20
    assert decoder._wepPlaintextLooksValid(pt_eapol)


def test_resolve_wep_key_accepts_5_13_16_byte_keys():
    """WEP supports 40-bit (5 byte), 104-bit (13 byte) and 128-bit
    (16 byte) keys.  _resolveWepKey must accept all three with the
    same hex form the renderer's wifi-wep entry type produces."""
    decoder = _load_decoder()
    # 5-byte key (WEP-40)
    key_40 = decoder._resolveWepKey({"wepKeyHex": "A48153B4CF"})
    assert key_40 == b"\xA4\x81\x53\xB4\xCF"
    # 13-byte key (WEP-104) — 26 hex chars
    key_104 = decoder._resolveWepKey(
        {"wepKeyHex": "A48153B4CFA48153B4CFA48153"}
    )
    assert isinstance(key_104, (bytes, bytearray))
    assert len(key_104) == 13
    # 16-byte key (WEP-128) — 32 hex chars
    key_128 = decoder._resolveWepKey(
        {"wepKeyHex": "A48153B4CFA48153B4CFA48153B4CFA4"}
    )
    assert isinstance(key_128, (bytes, bytearray))
    assert len(key_128) == 16
    # Invalid lengths must be rejected.
    assert decoder._resolveWepKey({"wepKeyHex": "AABBCC"}) is None
    assert decoder._resolveWepKey({"wepKeyHex": ""}) is None
    assert decoder._resolveWepKey({}) is None
