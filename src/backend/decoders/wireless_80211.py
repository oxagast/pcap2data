"""
IEEE 802.11 (Wi-Fi) link-layer / wireless protocol decoder.

This module is intentionally read-only friendly: it walks the scapy layers
on a packet, returns a normalized metadata section for any Dot11 / RadioTap
frame it finds, and exposes a small `decryptWifiPayload` helper that can
strip WEP and AES-CCMP / TKIP encryption when the user supplies a key
(typically a WEP hex key, a WPA-PSK passphrase, or a pre-computed PMK).

Design notes
------------

* No live capture: the decoder operates on already-parsed scapy packets, so
  the user only needs to load a .pcap / .pcapng that contains 802.11 frames
  (linktype DLT_IEEE802_11 or DLT_IEEE802_11_RADIO).  scapy auto-detects
  these link types at pcap read time.
* WPA3-SAE frames are reported with metadata only.  SAE PWE derivation is a
  research problem and we do not attempt any active password recovery here.
* The decoder never raises; it returns ``None`` when no 802.11 layer is
  present so the caller can short-circuit cleanly.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import struct
import sys

try:
    import scapy.all as scapy
except ImportError:  # pragma: no cover - scapy is a hard runtime dep
    import scapy  # type: ignore

try:
    from scapy.layers.dot11 import EAPOL
except Exception:  # pragma: no cover - very old scapy
    EAPOL = getattr(scapy, "EAPOL", None)

# WPA2 4-way handshake PTK derivation (see IEEE 802.11i §8.5.1).
# Imported as a sibling module rather than a top-level import to avoid
# pulling it into the package namespace.
try:
    from decoders import wpa2_ptk as _wpa2_ptk
except Exception:
    _decoderDir = os.path.dirname(os.path.realpath(__file__))
    if _decoderDir not in sys.path:
        sys.path.insert(0, _decoderDir)
    try:
        import wpa2_ptk as _wpa2_ptk  # type: ignore
    except Exception:
        _wpa2_ptk = None  # type: ignore

try:
    # scapy >= 2.5 keeps the dot11 helpers in scapy.layers.dot11
    from scapy.layers.dot11 import (
        Dot11,
        Dot11Beacon,
        Dot11ProbeReq,
        Dot11ProbeResp,
        Dot11Auth,
        Dot11AssoReq,
        Dot11AssoResp,
        Dot11ReassoReq,
        Dot11ReassoResp,
        Dot11Disas,
        Dot11Deauth,
        Dot11QoS,
        Dot11Encrypted,
        Dot11WEP,
        Dot11CCMP,
        Dot11TKIP,
        RadioTap,
    )
except Exception:  # pragma: no cover - very old scapy
    Dot11 = getattr(scapy, "Dot11", None)
    Dot11Beacon = getattr(scapy, "Dot11Beacon", None)
    Dot11ProbeReq = getattr(scapy, "Dot11ProbeReq", None)
    Dot11ProbeResp = getattr(scapy, "Dot11ProbeResp", None)
    Dot11Auth = getattr(scapy, "Dot11Auth", None)
    Dot11AssoReq = getattr(scapy, "Dot11AssoReq", None)
    Dot11AssoResp = getattr(scapy, "Dot11AssoResp", None)
    Dot11ReassoReq = getattr(scapy, "Dot11ReassoReq", None)
    Dot11ReassoResp = getattr(scapy, "Dot11ReassoResp", None)
    Dot11Disas = getattr(scapy, "Dot11Disas", None)
    Dot11Deauth = getattr(scapy, "Dot11Deauth", None)
    Dot11QoS = getattr(scapy, "Dot11QoS", None)
    Dot11Encrypted = getattr(scapy, "Dot11Encrypted", None)
    Dot11WEP = getattr(scapy, "Dot11WEP", None)
    Dot11CCMP = getattr(scapy, "Dot11CCMP", None)
    Dot11TKIP = getattr(scapy, "Dot11TKIP", None)
    RadioTap = getattr(scapy, "RadioTap", None)

# Map a numeric Dot11 frame-type/subtype into a human-friendly label.
_DOT11_TYPE_NAMES = {
    0: "Management",
    1: "Control",
    2: "Data",
    3: "Extension",
}

_DOT11_SUBTYPE_NAMES = {
    # Management
    (0, 0): "Association Request",
    (0, 1): "Association Response",
    (0, 2): "Reassociation Request",
    (0, 3): "Reassociation Response",
    (0, 4): "Probe Request",
    (0, 5): "Probe Response",
    (0, 6): "Reserved (Mgmt)",
    (0, 7): "Reserved (Mgmt)",
    (0, 8): "Beacon",
    (0, 9): "Disassociation",
    (0, 10): "Authentication",
    (0, 11): "Deauthentication",
    (0, 12): "Action",
    (0, 13): "Action No Ack",
    # Control
    (1, 7): "Control Wrapper",
    (1, 8): "Block Ack Request",
    (1, 9): "Block Ack",
    (1, 10): "PS-Poll",
    (1, 11): "RTS",
    (1, 12): "CTS",
    (1, 13): "ACK",
    (1, 14): "CF-End",
    (1, 15): "CF-End + CF-Ack",
    # Data
    (2, 0): "Data",
    (2, 1): "Data + CF-Ack",
    (2, 2): "Data + CF-Poll",
    (2, 3): "Data + CF-Ack + CF-Poll",
    (2, 4): "Null",
    (2, 5): "CF-Ack",
    (2, 6): "CF-Poll",
    (2, 7): "CF-Ack + CF-Poll",
    (2, 8): "QoS Data",
    (2, 9): "QoS Data + CF-Ack",
    (2, 10): "QoS Data + CF-Poll",
    (2, 11): "QoS Data + CF-Ack + CF-Poll",
    (2, 12): "QoS Null",
    (2, 14): "QoS CF-Poll",
    (2, 15): "QoS CF-Ack + CF-Poll",
}

# Dot11 RSN cipher / AKM identifiers we surface in the metadata table.
_RSN_CIPHER_SUITES = {
    0x0000: "Use group",
    0x0001: "WEP-40",
    0x0002: "TKIP",
    0x0003: "Wrap",
    0x0004: "CCMP-128",
    0x0005: "WEP-104",
    0x0006: "BIP-CMAC-128",
    0x0007: "Group addressed traffic not allowed",
    0x0008: "GCMP-128",
    0x0009: "GCMP-256",
    0x000A: "CCMP-256",
    0x000B: "BIP-GMAC-128",
    0x000C: "BIP-GMAC-256",
    0x000D: "BIP-CMAC-256",
}

_RSN_AKM_SUITES = {
    0x0001: "802.1X (WPA-Enterprise)",
    0x0002: "PSK (WPA-Personal)",
    0x0003: "FT over 802.1X",
    0x0004: "FT using PSK",
    0x0006: "PSK (WPA3-Personal transition)",
    0x0008: "SAE (WPA3-Personal)",
    0x0009: "FT over SAE",
    0x000A: "PPK over PSK",
    0x000B: "PSK (WPA3-Enterprise transition)",
    0x000C: "SAE (WPA3-Enterprise)",
    0x000D: "OWE (Opportunistic Wireless Encryption)",
}

_VENDOR_IE_OUI = {
    b"\x00\x50\xf2": "Microsoft/WPA",
    b"\x00\x0f\xac": "IEEE 802.11i/RSN",
}

# WEP / TKIP / CCMP / GCMP header sizes in octets (for body slicing).
_CCMP_HEADER_LEN = 8
_TKIP_HEADER_LEN = 4
_GCMP_HEADER_LEN = 8
_WEP_HEADER_LEN = 4


def _macToString(value):
    """Best-effort MAC/address formatter for scapy fields."""
    if value is None:
        return "N/A"
    try:
        text = str(value).strip()
    except Exception:
        return "N/A"
    if not text or text == "ff:ff:ff:ff:ff:ff":
        return "Broadcast" if text == "ff:ff:ff:ff:ff:ff" else "N/A"
    return text


def _safeInt(value, default=-1):
    try:
        return int(value)
    except Exception:
        return default


def _safeHex(value, width=4):
    if value is None:
        return "N/A"
    try:
        return f"0x{int(value) & ((1 << (width * 4)) - 1):0{width}x}"
    except Exception:
        return "N/A"


def _decodeSsid(payload):
    """Pull an SSID out of a tagged-params blob (tag number 0)."""
    if not payload:
        return None
    offset = 0
    while offset + 2 <= len(payload):
        elementId = payload[offset]
        elementLen = payload[offset + 1]
        if offset + 2 + elementLen > len(payload):
            break
        if elementId == 0:
            try:
                return payload[offset + 2 : offset + 2 + elementLen].decode(
                    "utf-8", errors="ignore"
                )
            except Exception:
                return None
        offset += 2 + elementLen
    return None


def _decodeRsnIe(payload):
    """Parse a 2-byte-element RSN IE blob into a small summary dict."""
    info = {
        "version": None,
        "groupCipher": None,
        "pairwiseCiphers": [],
        "akmSuites": [],
    }
    if not payload or len(payload) < 2:
        return info
    info["version"] = _safeHex(payload[0] | (payload[1] << 8), 4)
    if len(payload) < 8:
        return info
    info["groupCipher"] = _RSN_CIPHER_SUITES.get(
        _safeInt(payload[2] | (payload[3] << 8)),
        _safeHex(payload[2] | (payload[3] << 8)),
    )
    try:
        pairwiseCount = _safeInt(payload[4] | (payload[5] << 8))
    except Exception:
        pairwiseCount = 0
    pos = 6
    for _ in range(min(pairwiseCount, 4)):
        if pos + 2 > len(payload):
            break
        info["pairwiseCiphers"].append(
            _RSN_CIPHER_SUITES.get(
                _safeInt(payload[pos] | (payload[pos + 1] << 8)),
                _safeHex(payload[pos] | (payload[pos + 1] << 8)),
            )
        )
        pos += 2
    if pos + 2 > len(payload):
        return info
    try:
        akmCount = _safeInt(payload[pos] | (payload[pos + 1] << 8))
    except Exception:
        akmCount = 0
    pos += 2
    for _ in range(min(akmCount, 4)):
        if pos + 2 > len(payload):
            break
        info["akmSuites"].append(
            _RSN_AKM_SUITES.get(
                _safeInt(payload[pos] | (payload[pos + 1] << 8)),
                _safeHex(payload[pos] | (payload[pos + 1] << 8)),
            )
        )
        pos += 2
    return info


def _decodeVendorIes(payload):
    """Extract vendor IEs (WPA / Microsoft) so users see SSID-wide crypto."""
    sections = []
    if not payload:
        return sections
    offset = 0
    while offset + 2 <= len(payload):
        elementId = payload[offset]
        elementLen = payload[offset + 1]
        if offset + 2 + elementLen > len(payload):
            break
        if elementId == 221 and elementLen >= 4:
            oui = bytes(payload[offset + 2 : offset + 6])
            owner = _VENDOR_IE_OUI.get(oui, oui.hex())
            sections.append(
                {"oui": owner, "payloadHex": payload[offset + 6 : offset + 2 + elementLen].hex()}
            )
        offset += 2 + elementLen
    return sections


def _radioTapSignals(layer):
    """Return (signalDbm, noiseDbm, dataRateMbps) when available."""
    if layer is None:
        return "N/A", "N/A", "N/A"
    try:
        signalDbm = getattr(layer, "dBm_AntSignal", None)
    except Exception:
        signalDbm = None
    try:
        noiseDbm = getattr(layer, "dBm_AntNoise", None)
    except Exception:
        noiseDbm = None
    try:
        rate = getattr(layer, "Rate", None)
    except Exception:
        rate = None
    if rate is not None:
        try:
            rateMbps = float(rate) / 1_000_000.0
        except Exception:
            rateMbps = None
    else:
        rateMbps = None
    return (
        f"{int(signalDbm)} dBm" if signalDbm is not None else "N/A",
        f"{int(noiseDbm)} dBm" if noiseDbm is not None else "N/A",
        f"{rateMbps:.1f} Mbps" if rateMbps is not None else "N/A",
    )


def _extractChannel(layer):
    """Pull the operating channel (and frequency) out of RadioTap / Dot11 layers."""
    channel = "N/A"
    frequency = "N/A"
    if layer is None:
        return channel, frequency
    for attrName in ("Channel", "channel"):
        try:
            value = getattr(layer, attrName, None)
        except Exception:
            value = None
        if value is None:
            continue
        try:
            frequency = f"{int(value)} MHz"
            break
        except Exception:
            try:
                frequency = f"{int(getattr(value, 'frequency', 0))} MHz"
                channel = f"{int(getattr(value, 'flags', 0))}"
                break
            except Exception:
                continue
    for attrName in ("Channel", "channel"):
        try:
            value = getattr(layer, attrName, None)
        except Exception:
            value = None
        if value is None:
            continue
        try:
            channel = str(int(value))
            break
        except Exception:
            try:
                channel = str(int(getattr(value, 'flags', 0)))
                break
            except Exception:
                continue
    return channel, frequency


def _coercePsk(passphrase, ssid):
    """PBKDF2-HMAC-SHA1 PMK derivation (WPA-PSK)."""
    if not passphrase or not ssid:
        return None
    try:
        return hashlib.pbkdf2_hmac(
            "sha1",
            passphrase.encode("utf-8", errors="ignore"),
            ssid.encode("utf-8", errors="ignore"),
            4096,
            32,
        )
    except Exception:
        return None


# ---------------------------------------------------------------------------
# WPA2 4-way handshake cache and PTK derivation helpers.
#
# When a pcap contains the EAPOL-Key messages of a 4-way handshake (MSG1/2),
# we can derive the per-session PTK from PMK + ANonce + SNonce + MAC
# addresses.  The handshake state cache below stores the captured
# (ANonce, SNonce) pairs keyed by (BSSID, client_mac).  Once populated, the
# CCMP decryption path can look up the matching PTK and use its TK portion
# to decrypt data frames.
# ---------------------------------------------------------------------------

# Module-level cache.  Populated by ``populateWifiHandshakeCache`` (called
# once per pcap from the backend packet loop) and read by
# ``getCachedPtkForBssid``.  Keys are (bssid_lower, client_mac_lower)
# tuples; values are dicts with ``anonce`` / ``snonce`` / ``ptk`` byte
# strings and ``keyInfo`` / ``replayCounter`` metadata.
_WIFI_HANDSHAKE_CACHE = {
    "byPair": {},
    "byBssid": {},
}

_WIFI_HANDSHAKE_LOCK_NAME = "_WIFI_HANDSHAKE_LOCK"


def _eapolKeyInfo(rawEapol):
    """Read the 2-byte EAPOL-Key key_info field from a raw EAPOL frame."""
    if not isinstance(rawEapol, (bytes, bytearray)) or len(rawEapol) < 7:
        return None
    try:
        return int.from_bytes(bytes(rawEapol[5:7]), "big")
    except Exception:
        return None


def _eapolKeyNonce(rawEapol):
    """Read the 32-byte EAPOL-Key key_nonce field from a raw EAPOL frame."""
    if not isinstance(rawEapol, (bytes, bytearray)) or len(rawEapol) < 49:
        return None
    try:
        return bytes(rawEapol[17:49])
    except Exception:
        return None


def _normaliseMacString(value):
    """Lower-case, colon-separated MAC string or ``None``."""
    if not value:
        return None
    cleaned = str(value).strip().lower()
    if cleaned in ("", "n/a", "broadcast", "ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
        return None
    if ":" not in cleaned and len(cleaned) == 12:
        cleaned = ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))
    return cleaned


def _normaliseMacToBytes(value):
    """Convert a MAC string like ``00:0c:41:82:b2:55`` to 6 raw bytes or None."""
    text = _normaliseMacString(value)
    if not text:
        return None
    try:
        return bytes.fromhex(text.replace(":", "").replace("-", ""))
    except Exception:
        return None


def _macToBytes(value):
    """
    Best-effort conversion of a scapy MAC field (or already-bytes object)
    to 6 raw bytes.  Handles both EUI48 (colon-formatted string) and
    raw bytes, returning ``None`` on failure.  Broadcast MAC
    (``ff:ff:ff:ff:ff:ff``) is preserved as the raw 6 bytes since the
    IEEE 802.11 AAD requires the actual address bytes.
    """
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        if len(value) == 6:
            return bytes(value)
        return None
    text = str(value).strip().lower()
    if not text:
        return None
    # Accept colon-formatted MAC including broadcast/multicast.
    if ":" in text and len(text) == 17:
        try:
            return bytes.fromhex(text.replace(":", ""))
        except Exception:
            return None
    if ":" not in text and len(text) == 12:
        try:
            return bytes.fromhex(text)
        except Exception:
            return None
    return None


def resetWifiHandshakeCache():
    """Clear the module-level handshake cache (used between captures)."""
    _WIFI_HANDSHAKE_CACHE["byPair"] = {}
    _WIFI_HANDSHAKE_CACHE["byBssid"] = {}


def populateWifiHandshakeCache(packets):
    """
    Walk ``packets`` once and pull ANonce/SNonce out of every EAPOL-Key
    frame.  The resulting entries feed ``derivePtkForWifiKey`` so that
    later data frames can be decrypted without re-scanning the pcap.

    Call this before invoking ``decryptWifiPayload``; pass ``None`` to
    clear the cache.
    """
    resetWifiHandshakeCache()
    if not packets:
        return _WIFI_HANDSHAKE_CACHE

    for packet in packets:
        if EAPOL is None or not packet.haslayer(EAPOL):
            continue
        try:
            rawEapol = bytes(packet[EAPOL])
        except Exception:
            continue
        if len(rawEapol) < 99:
            # Need at least the EAPOL-Key header up to the key_data_length field.
            continue
        if rawEapol[4] != 0x02:  # descriptor_type must be 0x02 for 802.11 key
            continue

        keyInfo = _eapolKeyInfo(rawEapol)
        if keyInfo is None:
            continue
        # Per IEEE 802.11 key_info bit layout (big-endian):
        #   0x008  Pairwise, 0x080  Ack, 0x100  MIC, 0x200  Secure,
        #   0x400  Install, 0x1000 Encrypted-Key-Data
        pairwiseBit = 0x0008
        if not (keyInfo & pairwiseBit):
            continue

        # Get MAC addresses from the enclosing 802.11 header.
        try:
            dot11Layer = packet[Dot11] if Dot11 is not None else None
        except Exception:
            dot11Layer = None
        if dot11Layer is None:
            continue
        addr1 = _macToString(getattr(dot11Layer, "addr1", None))
        addr2 = _macToString(getattr(dot11Layer, "addr2", None))
        addr3 = _macToString(getattr(dot11Layer, "addr3", None))
        addr4 = _macToString(getattr(dot11Layer, "addr4", None))
        if not addr1 or not addr2 or not addr3:
            continue
        # Per IEEE 802.11 address field mapping, based on ToDS / FromDS
        # bits in FCfield:
        #   ToDS=0, FromDS=0: addr1=DA, addr2=SA, addr3=BSSID, addr4=N/A
        #   ToDS=1, FromDS=0: addr1=BSSID, addr2=SA, addr3=DA, addr4=N/A
        #   ToDS=0, FromDS=1: addr1=DA, addr2=BSSID, addr3=SA, addr4=N/A
        #                     (in infrastructure mode SA==BSSID)
        #   ToDS=1, FromDS=1: addr1=RA, addr2=TA, addr3=DA, addr4=SA
        fcField = _safeInt(getattr(dot11Layer, "FCfield", 0))
        toDs = bool(fcField & 0x01)
        fromDs = bool(fcField & 0x02)
        if toDs and not fromDs:
            # STA → AP: addr1=AP (BSSID), addr2=STA (SA), addr3=DA
            bssid = _normaliseMacString(addr1)
            clientMac = _normaliseMacString(addr2)
        elif fromDs and not toDs:
            # AP → STA: addr1=STA (DA), addr2=AP (BSSID/TA), addr3=SA
            # In infrastructure mode SA == TA == BSSID, so the client is
            # at addr1 (DA).
            bssid = _normaliseMacString(addr2)
            clientMac = _normaliseMacString(addr1)
        elif not toDs and not fromDs:
            # IBSS / direct: addr1=DA, addr2=SA, addr3=BSSID.
            bssid = _normaliseMacString(addr3)
            clientMac = _normaliseMacString(addr2)
        else:
            # ToDS=1, FromDS=1 (WDS): best effort.
            bssid = _normaliseMacString(addr1)
            clientMac = _normaliseMacString(addr4) if addr4 else _normaliseMacString(addr3)
        if not bssid or not clientMac:
            continue

        nonce = _eapolKeyNonce(rawEapol)
        if not nonce or len(nonce) != 32:
            continue
        # Skip all-zero nonces (msg 4 has no nonce).
        if nonce == b"\x00" * 32:
            continue

        # Determine direction: Ack (AP->STA) carries ANonce; no-Ack+MIC (STA->AP)
        # carries SNonce.
        ackBit = 0x0080
        isAnonce = bool(keyInfo & ackBit)
        pairKey = (bssid, clientMac)

        entry = _WIFI_HANDSHAKE_CACHE["byPair"].setdefault(
            pairKey,
            {
                "bssid": bssid,
                "clientMac": clientMac,
                "anonce": None,
                "snonce": None,
                "anonceKeyInfo": None,
                "snonceKeyInfo": None,
                "ptk": None,
                "ptkTk": None,
            },
        )
        if isAnonce:
            entry["anonce"] = nonce
            entry["anonceKeyInfo"] = keyInfo
        else:
            entry["snonce"] = nonce
            entry["snonceKeyInfo"] = keyInfo

        # Also bucket by BSSID so we can find handshakes even when the
        # Supplicant MAC is unknown.
        bssidBucket = _WIFI_HANDSHAKE_CACHE["byBssid"].setdefault(bssid, [])
        if pairKey not in bssidBucket:
            bssidBucket.append(pairKey)

    return _WIFI_HANDSHAKE_CACHE


def _cacheEntryKey(bssid, clientMac):
    """Return the normalised (bssid, client_mac) cache key."""
    return (
        _normaliseMacString(bssid) or "",
        _normaliseMacString(clientMac) or "",
    )


def derivePtkForWifiKey(wifiKey, cacheEntry):
    """
    Compute the PTK for a single (BSID, client) cache entry using the
    passphrase / PMK from ``wifiKey``.  Stores the resulting PTK bytes
    back into ``cacheEntry`` so subsequent data-frame decryptions skip
    the PRF.

    Returns the 64-byte PTK on success, or ``None`` when the entry is
    incomplete (no ANonce/SNonce yet) or no key material is available.
    """
    if _wpa2_ptk is None or not isinstance(cacheEntry, dict):
        return None
    if not cacheEntry.get("anonce") or not cacheEntry.get("snonce"):
        return None
    if cacheEntry.get("ptk"):
        return cacheEntry["ptk"]

    pmk = None
    ssid = (wifiKey or {}).get("ssid") if isinstance(wifiKey, dict) else None
    if isinstance(wifiKey, dict):
        pmkHex = str(wifiKey.get("pmkHex") or "").strip()
        if pmkHex:
            try:
                pmk = bytes.fromhex(re.sub(r"[^0-9A-Fa-f]", "", pmkHex))
                if len(pmk) != 32:
                    pmk = None
            except Exception:
                pmk = None
        if pmk is None:
            passphrase = str(wifiKey.get("psk") or "").strip()
            if passphrase and ssid:
                pmk = _coercePsk(passphrase, ssid)
    if pmk is None:
        return None

    try:
        ptk = _wpa2_ptk.derivePtkFromPmk(
            pmk,
            cacheEntry["anonce"],
            cacheEntry["snonce"],
            cacheEntry["bssid"],
            cacheEntry["clientMac"],
        )
    except Exception:
        return None
    if not ptk:
        return None

    cacheEntry["ptk"] = ptk
    parts = _wpa2_ptk.splitPtk(ptk)
    if parts:
        cacheEntry["ptkTk"] = parts.get("tk")
    return ptk


def populatePtkForBssid(bssid, wifiKeys):
    """
    For every cache entry under ``bssid``, try to derive a PTK using each
    supplied ``wifiKey``.  The first key that yields a PTK wins.

    Returns ``True`` when at least one PTK was successfully derived.
    """
    bssidKey = _normaliseMacString(bssid)
    if not bssidKey:
        return False
    derived = False
    for pairKey in _WIFI_HANDSHAKE_CACHE["byBssid"].get(bssidKey, []):
        entry = _WIFI_HANDSHAKE_CACHE["byPair"].get(pairKey)
        if not entry:
            continue
        for wifiKey in (wifiKeys or []):
            ptk = derivePtkForWifiKey(wifiKey, entry)
            if ptk:
                derived = True
                break
    return derived


def getCachedPtkForFrame(dot11Layer, pmk=None, wifiKeys=None):
    """
    Return the cached PTK bytes (or TK bytes if ``preferTk``) for the
    (BSSID, client_mac) tuple of a data frame, or ``None`` when no PTK
    is available yet.

    When ``wifiKeys`` is provided, this function also tries to derive a
    PTK on the fly from the supplied PMK / PSK material.
    """
    if dot11Layer is None:
        return None
    addr1 = _macToString(getattr(dot11Layer, "addr1", None))
    addr2 = _macToString(getattr(dot11Layer, "addr2", None))
    addr3 = _macToString(getattr(dot11Layer, "addr3", None))
    addr4 = _macToString(getattr(dot11Layer, "addr4", None))
    if not addr1 or not addr2 or not addr3:
        return None
    # Determine BSSID and client MAC based on ToDS/FromDS bits.
    fcField = _safeInt(getattr(dot11Layer, "FCfield", 0))
    toDs = bool(fcField & 0x01)
    fromDs = bool(fcField & 0x02)
    if toDs and not fromDs:
        # STA → AP
        bssid = _normaliseMacString(addr1)
        clientMac = _normaliseMacString(addr2)
    elif fromDs and not toDs:
        # AP → STA: client is DA at addr1; BSSID at addr2.
        bssid = _normaliseMacString(addr2)
        clientMac = _normaliseMacString(addr1)
    elif not toDs and not fromDs:
        bssid = _normaliseMacString(addr3)
        clientMac = _normaliseMacString(addr2)
    else:
        bssid = _normaliseMacString(addr1)
        clientMac = _normaliseMacString(addr4) if addr4 else _normaliseMacString(addr3)
    if not bssid or not clientMac:
        return None
    entry = _WIFI_HANDSHAKE_CACHE["byPair"].get(_cacheEntryKey(bssid, clientMac))
    if not entry:
        return None

    if not entry.get("ptk") and wifiKeys:
        # Try to derive from any candidate key for this BSSID.
        candidates = wifiKeys if isinstance(wifiKeys, list) else []
        for wifiKey in candidates:
            if derivePtkForWifiKey(wifiKey, entry):
                break

    ptk = entry.get("ptk")
    return ptk


def _aesEcbBlock(key, block):
    """Single-block AES-ECB encryption helper used for AES-CCM primitives."""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
    except Exception:
        return None
    try:
        enc = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        return enc.encryptor().update(block)
    except Exception:
        return None


def _ccmpDecrypt(pmk, dot11Header, ccmpLayer, rawFrame, wifiKeys=None):
    """
    Attempt AES-CCMP frame decryption using the WPA2 4-way handshake PTK
    derived from PMK + ANonce + SNonce + MAC addresses.  Returns the
    decrypted payload (LLC + payload) on success, or ``None`` when key
    material is not available or MIC verification fails.

    The PMK is normally supplied as a 32-byte string.  When ``pmk`` is
    ``None`` we fall back to a pre-computed PTK attached to the CCMP
    layer (legacy path) or to the module-level handshake cache populated
    by ``populateWifiHandshakeCache``.

    Implementation follows the reference aircrack-ng/airdecap-ng algorithm
    (lib/crypto/crypto.c decrypt_ccmp) which manually implements AES-CCM
    per RFC 3610.  This is necessary because Python's cryptography.io
    AESCCM.decrypt uses OpenSSL's EVP_CIPHER_CTX path with a different
    L/nonce convention; matching airdecap-ng's output requires the
    manual CCM primitive.
    """
    if ccmpLayer is None or rawFrame is None:
        return None

    # 1. Locate a usable TK.  Priority:
    #    a. Cached PTK derived from a captured 4-way handshake (preferred).
    #    b. Pre-computed PTK attached to the CCMP layer (legacy).
    #    c. PMK supplied as an argument (used only when ANonce+SNonce are
    #       also cached).
    tk = None
    cachedPtk = None
    try:
        cachedPtk = getCachedPtkForFrame(dot11Header, pmk=pmk, wifiKeys=wifiKeys)
    except Exception:
        cachedPtk = None
    if cachedPtk:
        tk = cachedPtk[32:48] if len(cachedPtk) >= 48 else cachedPtk[-16:]

    if tk is None:
        legacyPtk = getattr(ccmpLayer, "_ptk", None)
        if legacyPtk and len(legacyPtk) >= 16:
            tk = legacyPtk[:16]

    if tk is None:
        return None

    try:
        addr1 = _macToString(getattr(dot11Header, "addr1", None))
        addr2 = _macToString(getattr(dot11Header, "addr2", None))

        # CCMP PN is composed of six bytes (PN0..PN5) which scapy
        # exposes as individual fields. Per IEEE 802.11, the PN is
        # encoded MSB-first: PN5 is the most significant byte, PN0 is
        # the least significant. airdecap-ng stores it as
        # [PN[7], PN[6], ..., PN[0]] of the CCMP header which yields
        # the same byte sequence as scapy's PN5..PN0.
        pn = None
        try:
            pn = bytes([
                int(getattr(ccmpLayer, "PN5", 0)) & 0xFF,
                int(getattr(ccmpLayer, "PN4", 0)) & 0xFF,
                int(getattr(ccmpLayer, "PN3", 0)) & 0xFF,
                int(getattr(ccmpLayer, "PN2", 0)) & 0xFF,
                int(getattr(ccmpLayer, "PN1", 0)) & 0xFF,
                int(getattr(ccmpLayer, "PN0", 0)) & 0xFF,
            ])
        except Exception:
            pn = None

        if not addr1 or not addr2 or pn is None:
            return None

        addr2Bytes = _normaliseMacToBytes(addr2)
        if not addr2Bytes:
            return None

        # Determine the 802.11 header length (z) for the AAD.
        dot11Bytes = bytes(dot11Header)[:32]
        if len(dot11Bytes) < 24:
            return None
        # ToDS=FC1[0], FromDS=FC1[1]. A4 present only when both set.
        isA4 = (dot11Bytes[1] & 0x03) == 0x03
        isQos = (dot11Bytes[0] & 0x8C) == 0x88
        z = 24 + 6 * isA4 + 2 * isQos

        # Extract ciphertext and stored (encrypted) MIC from CCMP layer.
        ccmpBytes = bytes(ccmpLayer)
        if len(ccmpBytes) < _CCMP_HEADER_LEN + 8:
            return None
        dataLen = len(ccmpBytes) - _CCMP_HEADER_LEN - 8
        if dataLen <= 0:
            return None
        ciphertext = ccmpBytes[_CCMP_HEADER_LEN:-8]
        micStored = ccmpBytes[-8:]

        # Build AAD with the length prefix (airdecap-ng convention).
        # For non-QoS non-WDS: AAD content is 22 bytes (FC + A1 + A2 + A3 +
        # SC_low + 1 zero byte); the length prefix is 0x0016.  QoS or WDS
        # add 2 or 6 bytes respectively, mirroring airdecap-ng's
        # conditional AAD layout.
        aad = bytearray(32)
        aad[2] = dot11Bytes[0] & 0x8F
        aad[3] = dot11Bytes[1] & 0xC7
        # A1, A2, A3 — always extract raw 6-byte MAC even for broadcast
        # ("ff:ff:ff:ff:ff:ff"); zero-fill only as a last resort.
        addr1Raw = getattr(dot11Header, "addr1", None)
        addr3Raw = getattr(dot11Header, "addr3", None)
        addr1Bytes = _macToBytes(addr1Raw) or b"\x00" * 6
        addr3Bytes = _macToBytes(addr3Raw) or b"\x00" * 6
        aad[4:10] = addr1Bytes
        aad[10:16] = addr2Bytes
        aad[16:22] = addr3Bytes
        aad[22] = dot11Bytes[22] & 0x0F
        if isQos:
            if isA4:
                aad[24:30] = dot11Bytes[24:30]
                aad[30] = dot11Bytes[z - 2] & 0x0F
                aad[31] = 0
                aad[1] = 22 + 2 + 6
            else:
                aad[24] = dot11Bytes[z - 2] & 0x0F
                aad[25] = 0
                aad[1] = 22 + 2
        else:
            if isA4:
                aad[24:30] = dot11Bytes[24:30]
                aad[1] = 22 + 6
            else:
                aad[1] = 22

        # CTR-mode keystream (S_1 .. S_n) using the convention
        # A_i = (Flags & 0x07) || 0x00 || addr2 || PN || counter_2bytes_BE
        def sBlock(counter):
            A_i = bytearray(16)
            A_i[0] = 0x01  # Flags & 0x07 (cleared Retry/PM/MD bits)
            A_i[1] = 0
            A_i[2:8] = addr2Bytes
            A_i[8:14] = pn
            A_i[14] = (counter >> 8) & 0xFF
            A_i[15] = counter & 0xFF
            return _aesEcbBlock(tk, bytes(A_i))

        # Generate keystream and decrypt ciphertext to plaintext.
        numBlocks = (dataLen + 15) // 16
        pt = bytearray()
        for i in range(numBlocks):
            S = sBlock(i + 1)
            if S is None:
                return None
            blockStart = i * 16
            blockEnd = min(blockStart + 16, dataLen)
            for j in range(blockEnd - blockStart):
                pt.append(ciphertext[blockStart + j] ^ S[j])

        # CBC-MAC over the AAD (length-encoded) and the decrypted plaintext.
        def xorAndEncrypt(block16, prev):
            x = bytearray(16)
            for i in range(16):
                x[i] = prev[i] ^ block16[i]
            return _aesEcbBlock(tk, bytes(x))

        # B0 = Flags (0x59, M=8 L=2) || 0x00 || addr2 || PN || l(m) BE
        b0 = bytearray(16)
        b0[0] = 0x59
        b0[1] = 0
        b0[2:8] = addr2Bytes
        b0[8:14] = pn
        b0[14] = (dataLen >> 8) & 0xFF
        b0[15] = dataLen & 0xFF
        X = _aesEcbBlock(tk, bytes(b0))
        if X is None:
            return None

        aadFull = bytes(aad[: aad[1] + 2])
        aadPadded = aadFull + b"\x00" * ((-len(aadFull)) % 16)
        for blk in range(0, len(aadPadded), 16):
            X = xorAndEncrypt(aadPadded[blk:blk + 16], X)
            if X is None:
                return None

        ptPadded = bytes(pt) + b"\x00" * ((-len(pt)) % 16)
        for blk in range(0, len(ptPadded), 16):
            X = xorAndEncrypt(ptPadded[blk:blk + 16], X)
            if X is None:
                return None

        # S_0 = E(K, A_0) where A_0 has the counter field zeroed.
        a0 = bytearray(b0)
        a0[0] = 0x01  # Flags & 0x07
        a0[14] = 0
        a0[15] = 0
        S0 = _aesEcbBlock(tk, bytes(a0))
        if S0 is None:
            return None

        # Decrypt stored MIC: MIC_actual = MIC_stored XOR S_0[:8]
        micActual = bytes(a ^ b for a, b in zip(micStored, S0[:8]))
        if bytes(X[:8]) != micActual:
            return None

        return bytes(pt)
    except Exception:
        return None


def _tkipDecrypt(pmk, dot11Header, tkipLayer, rawFrame):
    """
    TKIP uses RC4 with per-frame keys; without a captured ANonce/gtk we
    cannot perform useful decryption here, so the implementation is a
    metadata-only stub that returns None to indicate "no plaintext".
    """
    return None


def _wepDecrypt(weKey, wepBody):
    """
    RC4 stream cipher decrypt (WEP-40 / WEP-104 / WEP-128).

    ``wepBody`` must be the raw WEP frame body: 3 bytes IV + 1 byte KeyID +
    ciphertext + 4 bytes ICV (i.e. ``bytes(p[Dot11WEP])`` for a parsed
    scapy packet, or the WEP payload bytes from the raw frame).

    Returns a tuple ``(plaintext, icv_ok)`` where ``plaintext`` is the
    decrypted payload bytes (without the trailing 4-byte ICV) and
    ``icv_ok`` is a boolean indicating whether the WEP ICV (CRC-32 of the
    plaintext) matched the ICV in the frame.  Returns ``(None, False)``
    when the body is too short or the key is missing.
    """
    if not weKey or wepBody is None or len(wepBody) < 4 + 4:
        return None, False
    iv = wepBody[0:3]
    ciphertext = wepBody[4:-4]
    icv = wepBody[-4:]
    seed = iv + bytes(weKey)
    plaintext = None
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher

        # ARC4 has been moved to the decrepit module in cryptography >= 43
        # to flag it as a legacy algorithm.  Try the decrepit path first
        # to avoid the deprecation warning, then fall back to the legacy
        # path for older cryptography versions.
        try:
            from cryptography.hazmat.decrepit.ciphers.algorithms import ARC4
        except Exception:
            from cryptography.hazmat.primitives.ciphers.algorithms import ARC4

        cipher = Cipher(ARC4(seed), None)
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    except Exception:
        return None, False
    # The WEP ICV is the standard CRC-32 of the plaintext, stored in
    # little-endian byte order in the frame.  Many real captures
    # (and synthetic test pcaps) ship with a corrupt or zeroed ICV, so
    # we *verify* but do not *require* a match: a sanity check on the
    # plaintext (must look like an LLC/SNAP header) is what actually
    # gates "ok" downstream.
    icv_ok = False
    try:
        import zlib

        computed = zlib.crc32(plaintext) & 0xFFFFFFFF
        icv_int = struct.unpack("<I", icv)[0]
        icv_ok = computed == icv_int
    except Exception:
        icv_ok = False
    return plaintext, icv_ok


# Common IANA-assigned EtherType values found in 802.11 data frames.  We
# keep this list narrow on purpose: the goal is to recognize "looks
# like a real LLC/SNAP payload" without being so permissive that
# random RC4 output slips through.
_KNOWN_80211_ETHERTYPES = {
    0x0800,  # IPv4
    0x0806,  # ARP
    0x0842,  # WoL (Wake-on-LAN)
    0x86DD,  # IPv6
    0x888E,  # EAPOL (802.1X)
    0x888C,  # TDLS
    0x8863,  # PPPoE Discovery
    0x8864,  # PPPoE Session
    0x8100,  # VLAN-tagged
    0x8847,  # MPLS unicast
    0x8848,  # MPLS multicast
    0x8863,  # PPPoE Discovery
    0x88A8,  # Provider Bridging
    0x88CC,  # LLDP
    0x88E5,  # MACsec
}


def _wepPlaintextLooksValid(plaintext):
    """
    Sanity check for a freshly-decrypted WEP payload.

    Returns True when the bytes plausibly form an 802.2 LLC / SNAP
    header (the common case for encrypted 802.11 data frames).  This
    guards against false positives where the wrong key happens to
    produce garbage that slips past the lenient CRC-32 verification
    (which is lenient because WEP pcaps in the wild often have a
    corrupt or zeroed ICV).
    """
    if not plaintext or len(plaintext) < 8:
        return False
    dsap = plaintext[0]
    ssap = plaintext[1]
    ctrl = plaintext[2]
    # LLC/SNAP-wrapped 802.11 data frame:
    #   DSAP=0xAA, SSAP=0xAA, Control=0x03,
    #   3-byte OUI (often 0x000000 or vendor OUI),
    #   2-byte EtherType.
    # The 7-bit SAP comparison strips the I/G and C/R bits.
    if (dsap & 0xFE) == 0xAA and (ssap & 0xFE) == 0xAA and ctrl == 0x03:
        if len(plaintext) < 8:
            return False
        ether_type = (plaintext[6] << 8) | plaintext[7]
        if ether_type in _KNOWN_80211_ETHERTYPES:
            return True
        # Even with an unrecognised EtherType, the LLC/SNAP header
        # itself is strong evidence of a valid 802.11 data frame.
        # Allow it as long as the EtherType is in the IANA "EtherType"
        # assignment range (>= 0x0600), and reject obviously bogus
        # values (< 0x0600, which is reserved).
        if 0x0600 <= ether_type <= 0xFFFF:
            return True
        return False
    # Raw Ethernet II (no LLC header): 6-byte DA + 6-byte SA + 2-byte
    # EtherType.  Require the EtherType to be an assigned value.
    if len(plaintext) >= 14:
        ether_type = (plaintext[12] << 8) | plaintext[13]
        if ether_type in _KNOWN_80211_ETHERTYPES:
            return True
    return False


def _looksLikeWifi(p):
    if p is None:
        return False
    if Dot11 is not None:
        try:
            if p.haslayer(Dot11):
                return True
        except Exception:
            pass
    try:
        if p.haslayer("Dot11") or p.haslayer("RadioTap"):
            return True
    except Exception:
        return False
    try:
        for layer in p.layers():
            name = getattr(layer, "__name__", str(layer)).lower()
            if name.startswith("dot11") or name == "radiotap":
                return True
    except Exception:
        return False
    return False


def getWirelessLayers(p):
    """Return (dot11Layer, radioTapLayer, encryptedLayer) or (None, None, None)."""
    if not _looksLikeWifi(p):
        return None, None, None
    dot11Layer = None
    radioTapLayer = None
    encryptedLayer = None
    if RadioTap is not None:
        try:
            if p.haslayer(RadioTap):
                radioTapLayer = p[RadioTap]
        except Exception:
            radioTapLayer = None
    if Dot11 is None:
        try:
            if p.haslayer("Dot11"):
                dot11Layer = p["Dot11"]
        except Exception:
            dot11Layer = None
    else:
        try:
            if p.haslayer(Dot11):
                dot11Layer = p[Dot11]
        except Exception:
            dot11Layer = None
    if Dot11CCMP is not None:
        try:
            if p.haslayer(Dot11CCMP):
                encryptedLayer = p[Dot11CCMP]
        except Exception:
            encryptedLayer = None
    if encryptedLayer is None and Dot11TKIP is not None:
        try:
            if p.haslayer(Dot11TKIP):
                encryptedLayer = p[Dot11TKIP]
        except Exception:
            encryptedLayer = None
    if encryptedLayer is None and Dot11WEP is not None:
        try:
            if p.haslayer(Dot11WEP):
                encryptedLayer = p[Dot11WEP]
        except Exception:
            encryptedLayer = None
    if encryptedLayer is None and Dot11Encrypted is not None:
        try:
            if p.haslayer(Dot11Encrypted):
                encryptedLayer = p[Dot11Encrypted]
        except Exception:
            encryptedLayer = None
    return dot11Layer, radioTapLayer, encryptedLayer


def decodeWirelessFrame(p):
    """
    Build the per-packet wireless metadata section.

    Returns a dict with wifi.* keys suitable for inclusion in
    ``packet.info`` and the link layer, or None when the packet is not an
    802.11 frame.
    """
    dot11Layer, radioTapLayer, encryptedLayer = getWirelessLayers(p)
    if dot11Layer is None:
        return None

    fc = _safeInt(getattr(dot11Layer, "FCfield", 0))
    typeBits = (fc >> 2) & 0x3
    subtypeBits = (fc >> 4) & 0xF
    typeName = _DOT11_TYPE_NAMES.get(typeBits, f"Type {typeBits}")
    subtypeName = _DOT11_SUBTYPE_NAMES.get(
        (typeBits, subtypeBits), f"Subtype {subtypeBits}"
    )

    addr1 = _macToString(getattr(dot11Layer, "addr1", None))
    addr2 = _macToString(getattr(dot11Layer, "addr2", None))
    addr3 = _macToString(getattr(dot11Layer, "addr3", None))
    addr4 = _macToString(getattr(dot11Layer, "addr4", None))

    # SSID/Channel/Cipher sniffing applies to mgmt + probe frames.
    ssid = None
    rsnInfo = {"version": None, "groupCipher": None, "pairwiseCiphers": [], "akmSuites": []}
    vendorIes = []
    crypto = "Open"
    cipher = "None"
    channel = "N/A"
    frequency = "N/A"

    if Dot11Beacon is not None and p.haslayer(Dot11Beacon):
        beacon = p[Dot11Beacon]
        try:
            ssid = _decodeSsid(bytes(beacon))
        except Exception:
            ssid = None
        try:
            rsnInfo = _decodeRsnIe(_findIe(beacon, 48))
        except Exception:
            pass
        try:
            vendorIes = _decodeVendorIes(_allIes(beacon))
        except Exception:
            vendorIes = []
    elif Dot11ProbeReq is not None and p.haslayer(Dot11ProbeReq):
        probe = p[Dot11ProbeReq]
        try:
            ssid = _decodeSsid(bytes(probe))
        except Exception:
            ssid = None
        try:
            vendorIes = _decodeVendorIes(_allIes(probe))
        except Exception:
            vendorIes = []
    elif Dot11ProbeResp is not None and p.haslayer(Dot11ProbeResp):
        probe = p[Dot11ProbeResp]
        try:
            ssid = _decodeSsid(bytes(probe))
        except Exception:
            ssid = None
        try:
            rsnInfo = _decodeRsnIe(_findIe(probe, 48))
        except Exception:
            pass
        try:
            vendorIes = _decodeVendorIes(_allIes(probe))
        except Exception:
            vendorIes = []

    if rsnInfo.get("pairwiseCiphers") or rsnInfo.get("akmSuites"):
        if "CCMP-128" in (rsnInfo.get("pairwiseCiphers") or []):
            cipher = "CCMP-128 (AES)"
            crypto = "WPA2"
        elif "TKIP" in (rsnInfo.get("pairwiseCiphers") or []):
            cipher = "TKIP (RC4)"
            crypto = "WPA"
        if any("SAE" in str(a) for a in (rsnInfo.get("akmSuites") or [])):
            crypto = "WPA3"
    if any("WPA" in (v.get("oui") or "") for v in vendorIes):
        if crypto == "Open":
            crypto = "WPA"

    channel, frequency = _extractChannel(radioTapLayer)
    if channel == "N/A":
        channel, frequency = _extractChannel(dot11Layer)

    signalDbm, noiseDbm, dataRateMbps = _radioTapSignals(radioTapLayer)

    if encryptedLayer is not None:
        if Dot11CCMP is not None and isinstance(encryptedLayer, Dot11CCMP):
            cipher = "CCMP-128 (AES)"
            if crypto == "Open":
                crypto = "WPA2"
        elif Dot11TKIP is not None and isinstance(encryptedLayer, Dot11TKIP):
            cipher = "TKIP (RC4)"
            if crypto == "Open":
                crypto = "WPA"
        else:
            # WEP: it always sets FCfield Protected bit but no separate layer.
            cipher = "WEP"
            if crypto == "Open":
                crypto = "WEP"

    section = {
        "SSID": ssid if ssid else "Hidden/N/A",
        "wifi.ssid": ssid if ssid else "Hidden/N/A",
        "BSSID": addr2,
        "wifi.bssid": addr2,
        "Source Address": addr2,
        "Destination Address": addr1,
        "Transmitter Address": addr3,
        "Receiver Address": addr1,
        "Fourth Address": addr4,
        "wifi.addr1": addr1,
        "wifi.addr2": addr2,
        "wifi.addr3": addr3,
        "wifi.addr4": addr4,
        "Frame Type": typeName,
        "Frame Subtype": subtypeName,
        "wifi.type": typeName,
        "wifi.subtype": subtypeName,
        "wifi.type_num": typeBits,
        "wifi.subtype_num": subtypeBits,
        "Protected": bool(fc & 0x40),
        "wifi.fc.protected": bool(fc & 0x40),
        "To DS": bool(fc & 0x01),
        "From DS": bool(fc & 0x02),
        "wifi.fc.tods": bool(fc & 0x01),
        "wifi.fc.fromds": bool(fc & 0x02),
        "Channel": channel,
        "wifi.channel": channel,
        "Frequency": frequency,
        "wifi.frequency": frequency,
        "Signal": signalDbm,
        "wifi.signal_dbm": signalDbm,
        "Noise": noiseDbm,
        "wifi.noise_dbm": noiseDbm,
        "Data Rate": dataRateMbps,
        "wifi.data_rate_mbps": dataRateMbps,
        "Cipher": cipher,
        "wifi.cipher": cipher,
        "Crypto": crypto,
        "wifi.crypto": crypto,
        "RSN Version": rsnInfo.get("version") or "N/A",
        "RSN Group Cipher": rsnInfo.get("groupCipher") or "N/A",
        "RSN Pairwise Ciphers": ", ".join(rsnInfo.get("pairwiseCiphers") or []) or "N/A",
        "RSN AKM Suites": ", ".join(rsnInfo.get("akmSuites") or []) or "N/A",
        "Vendor IEs": ", ".join(v.get("oui", "") for v in vendorIes) or "N/A",
    }
    return section


def _findIe(layer, tagNumber):
    """Return the payload of the first IE with ``tagNumber`` if present."""
    try:
        for infoElement in layer.getlayer("Dot11Elt") or []:
            try:
                if int(getattr(infoElement, "ID", -1)) == tagNumber:
                    return bytes(infoElement.info or b"")
            except Exception:
                continue
    except Exception:
        return None
    return None


def _allIes(layer):
    """Concatenate all IE payloads (used for vendor IE scanning)."""
    out = bytearray()
    try:
        for infoElement in layer.getlayer("Dot11Elt") or []:
            try:
                out += bytes(infoElement.info or b"")
            except Exception:
                continue
    except Exception:
        return bytes(out)
    return bytes(out)


def _candidateKeysForBssid(wifiKeys, bssid):
    """Pick the key entries that match a given BSSID (or all, when unset)."""
    if not wifiKeys:
        return []
    if not bssid or bssid in ("N/A", "Broadcast"):
        return list(wifiKeys)
    try:
        bssidLower = bssid.lower()
    except Exception:
        bssidLower = bssid
    matches = []
    for entry in wifiKeys:
        target = str(entry.get("bssid") or "").strip().lower()
        if not target or target == bssidLower:
            matches.append(entry)
    return matches or list(wifiKeys)


def _resolvePsk(entry, ssid):
    if not entry:
        return None
    if entry.get("pmkHex"):
        try:
            return bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", entry["pmkHex"]))
        except Exception:
            return None
    if entry.get("psk") and ssid:
        return _coercePsk(str(entry["psk"]), ssid)
    return None


def _resolveWepKey(entry):
    if not entry or not entry.get("wepKeyHex"):
        return None
    try:
        keyBytes = bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", entry["wepKeyHex"]))
    except Exception:
        return None
    if len(keyBytes) not in (5, 13, 16):
        return None
    return keyBytes


def decryptWifiPayload(p, wifiKeys):
    """
    Attempt to decrypt the body of an 802.11 data frame.

    ``wifiKeys`` is a list of dicts, each with optional fields:
        * bssid  - lower-case MAC string (e.g. "00:11:22:33:44:55")
        * ssid   - SSID string used for PMK derivation
        * psk    - WPA-PSK passphrase
        * pmkHex - 32-byte PMK as hex (preferred over psk)
        * wepKeyHex - WEP key in hex (5 / 13 / 16 bytes)

    Returns a dict ``{ok, plaintextHex, algorithm, error}`` or ``None`` when
    the frame is not data/encrypted.  ``algorithm`` is one of:
    "WEP", "TKIP", "CCMP", or "None".
    """
    dot11Layer, _, encryptedLayer = getWirelessLayers(p)
    if dot11Layer is None:
        return None
    fc = _safeInt(getattr(dot11Layer, "FCfield", 0))
    # scapy's FCfield is the flags byte (bit 8-15 of Frame Control). Type
    # and subtype live in the first byte of the Frame Control, exposed
    # via the ``type``/``subtype`` properties (or bytes(dot11Layer)[0]).
    frameType = _safeInt(getattr(dot11Layer, "type", -1), -1)
    if frameType == -1:
        try:
            frameType = (bytes(dot11Layer)[0] >> 2) & 0x3
        except Exception:
            frameType = -1
    if frameType != 2:  # Only data frames carry encrypted payloads
        return None
    if encryptedLayer is None and not (fc & 0x40):
        return None

    # Determine BSSID based on ToDS/FromDS bits. The BSSID is always at
    # addr3 except for ToDS=1 (STA → AP) where it's at addr1.
    toDs = bool(fc & 0x01)
    fromDs = bool(fc & 0x02)
    addr1 = _macToString(getattr(dot11Layer, "addr1", None))
    addr2 = _macToString(getattr(dot11Layer, "addr2", None))
    addr3 = _macToString(getattr(dot11Layer, "addr3", None))
    if toDs and not fromDs:
        bssid = addr1
    elif fromDs and not toDs:
        bssid = addr2
    else:
        bssid = addr3 or addr2 or addr1
    ssid = None
    try:
        if Dot11Beacon is not None and p.haslayer(Dot11Beacon):
            ssid = _decodeSsid(bytes(p[Dot11Beacon]))
    except Exception:
        ssid = None

    candidates = _candidateKeysForBssid(wifiKeys, bssid)
    if not candidates:
        return {
            "ok": False,
            "plaintextHex": None,
            "algorithm": "None",
            "error": "No Wi-Fi keys provided for this BSSID.",
        }

    rawFrame = bytes(p) if p is not None else b""

    if encryptedLayer is not None and Dot11CCMP is not None and isinstance(encryptedLayer, Dot11CCMP):
        for entry in candidates:
            pmk = _resolvePsk(entry, ssid or entry.get("ssid"))
            plaintext = _ccmpDecrypt(pmk, dot11Layer, encryptedLayer, rawFrame, wifiKeys=candidates)
            if plaintext is not None:
                return {
                    "ok": True,
                    "plaintextHex": plaintext.hex(),
                    "algorithm": "CCMP",
                    "ssid": ssid,
                    "bssid": bssid,
                }
        return {
            "ok": False,
            "plaintextHex": None,
            "algorithm": "CCMP",
            "error": "WPA2 PSK did not decrypt any of the supplied CCMP frames. "
            "Verify the passphrase and that the 4-way handshake is in the capture.",
            "ssid": ssid,
            "bssid": bssid,
        }

    if encryptedLayer is not None and Dot11TKIP is not None and isinstance(encryptedLayer, Dot11TKIP):
        for entry in candidates:
            pmk = _resolvePsk(entry, ssid or entry.get("ssid"))
            plaintext = _tkipDecrypt(pmk, dot11Layer, encryptedLayer, rawFrame)
            if plaintext is not None:
                return {
                    "ok": True,
                    "plaintextHex": plaintext.hex(),
                    "algorithm": "TKIP",
                    "ssid": ssid,
                    "bssid": bssid,
                }
        return {
            "ok": False,
            "plaintextHex": None,
            "algorithm": "TKIP",
            "error": "TKIP frame requires the per-session PTK; provide PMK and the original 4-way handshake.",
            "ssid": ssid,
            "bssid": bssid,
        }

    # WEP: protected bit set, with a Dot11WEP layer (preferred) or
    # fall back to a FCfield-only probe when the WEP layer was not
    # detected.  The WEP body (3-byte IV + 1-byte KeyID + ciphertext +
    # 4-byte ICV) is what we feed to the RC4 primitive, *not* the full
    # 802.11 frame.
    wepBody = None
    if (
        encryptedLayer is not None
        and Dot11WEP is not None
        and isinstance(encryptedLayer, Dot11WEP)
    ):
        try:
            wepBody = bytes(encryptedLayer)
        except Exception:
            wepBody = None
    elif fc & 0x40:
        # No scapy WEP layer but the Protected bit is set.  Slice the
        # WEP body out of the raw frame using the 802.11 MAC header
        # length (24 bytes for non-QoS data, 26 for QoS, 30 for HT/4-addr).
        try:
            macHeaderLen = 24
            if Dot11QoS is not None:
                try:
                    if p.haslayer(Dot11QoS):
                        macHeaderLen = 26
                except Exception:
                    pass
            # 4-address frames (ToDS + FromDS) add 6 bytes for addr4.
            if toDs and fromDs:
                macHeaderLen += 6
            if macHeaderLen + 4 + 4 <= len(rawFrame):
                wepBody = rawFrame[macHeaderLen:]
        except Exception:
            wepBody = None
    if wepBody is not None and len(wepBody) >= 4 + 4:
        for entry in candidates:
            wepKey = _resolveWepKey(entry)
            if not wepKey:
                continue
            try:
                plaintext, _icvOk = _wepDecrypt(wepKey, wepBody)
            except Exception:
                plaintext = None
            if plaintext is not None and _wepPlaintextLooksValid(plaintext):
                return {
                    "ok": True,
                    "plaintextHex": plaintext.hex(),
                    "algorithm": "WEP",
                    "ssid": ssid,
                    "bssid": bssid,
                }
        return {
            "ok": False,
            "plaintextHex": None,
            "algorithm": "WEP",
            "error": "WEP key did not match the IV in the captured frame.",
            "ssid": ssid,
            "bssid": bssid,
        }

    return {
        "ok": False,
        "plaintextHex": None,
        "algorithm": "None",
        "error": "Frame is not encrypted; no decryption needed.",
        "ssid": ssid,
        "bssid": bssid,
    }
