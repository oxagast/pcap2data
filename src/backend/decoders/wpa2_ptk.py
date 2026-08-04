"""
WPA2 4-way handshake PTK derivation utilities.

Implements the IEEE 802.11i / WPA2-PSK key derivation:

  * PBKDF2-HMAC-SHA1 (PMK from passphrase + SSID)
  * PRF-384 (PTK from PMK + ANonce + SNonce + MAC addresses)

Together these let a captured EAPOL 4-way handshake (containing ANonce and
SNonce) be combined with a known WPA2 passphrase to derive the per-session
PTK. The PTK contains:
  * KCK (Key Confirmation Key, 16 bytes) — used to verify MICs in msgs 2/4
  * KEK (Key Encryption Key, 16 bytes)   — used to wrap the GTK in msg 3
  * TK  (Temporal Key, 16 bytes for CCMP) — the per-frame data-encryption key

For CCMP data frame decryption we only need TK; for our purposes we hand
back the full 64-byte PTK (or just the TK portion on demand).
"""

from __future__ import annotations

import hashlib
import hmac
import struct


def derivePmkFromPassphrase(passphrase, ssid):
    """
    Derive a 32-byte WPA2 PMK from a passphrase + SSID via PBKDF2-HMAC-SHA1
    with 4096 iterations (per IEEE 802.11i / WPA2 spec).
    """
    if not isinstance(passphrase, (str, bytes, bytearray)) or not passphrase:
        return None
    if not isinstance(ssid, (str, bytes, bytearray)) or not ssid:
        return None
    passBytes = passphrase.encode("utf-8") if isinstance(passphrase, str) else bytes(passphrase)
    ssidBytes = ssid.encode("utf-8") if isinstance(ssid, str) else bytes(ssid)
    return hashlib.pbkdf2_hmac(
        "sha1",
        passBytes,
        ssidBytes,
        4096,
        dklen=32,
    )


def _macBytes(macString):
    """Convert a MAC string like '00:0c:41:82:b2:55' to 6 raw bytes."""
    if not isinstance(macString, str):
        return None
    cleaned = macString.replace(":", "").replace("-", "").strip().lower()
    if len(cleaned) != 12:
        return None
    try:
        return bytes.fromhex(cleaned)
    except Exception:
        return None


def _prf384(key, label, data, outputLength):
    """
    WPA2 / 802.11i Pseudo-Random Function (PRF).

    This is the same algorithm used by wpa_supplicant (``sha1_prf`` in
    hostapd's ``crypto/sha1-prf.c``). Per wpa_supplicant:

        addr = [label || 0x00, data, &counter]
        len  = [strlen(label) + 1, data_len, 1]

        block_i = HMAC-SHA1(key, label || 0x00 || data || counter_i)
        for i = 0, 1, 2, ...

    Output = block_0 || block_1 || block_2 || ... truncated to
    outputLength bytes.

    Note that the ``label`` is null-terminated (the trailing 0x00 byte is
    counted in the HMAC payload) and the iteration counter byte is appended
    at the END of the message, not prepended.
    """
    if outputLength <= 0:
        return b""
    labelBytes = label.encode("ascii") if isinstance(label, str) else bytes(label)
    labelWithNull = labelBytes + b"\x00"
    out = b""
    counter = 0
    while len(out) < outputLength:
        msg = labelWithNull + data + bytes([counter])
        block = hmac.new(key, msg, hashlib.sha1).digest()
        out += block
        counter += 1
    return out[:outputLength]


def derivePtkFromPmk(pmk, anonce, snonce, authenticatorMac, supplicantMac):
    """
    Derive the 64-byte PTK from PMK + ANonce + SNonce + AP MAC + Client MAC.
    Returns the full PTK (KCK || KEK || TK) so callers can pick the portion
    they need (CCMP needs only the last 16 bytes — the TK).
    """
    if not isinstance(pmk, (bytes, bytearray)) or len(pmk) != 32:
        return None
    if not isinstance(anonce, (bytes, bytearray)) or len(anonce) != 32:
        return None
    if not isinstance(snonce, (bytes, bytearray)) or len(snonce) != 32:
        return None
    authBytes = _macBytes(authenticatorMac)
    suppBytes = _macBytes(supplicantMac)
    if authBytes is None or suppBytes is None:
        return None
    # Per IEEE 802.11i, MACs in the data are ordered with the smaller one first.
    macA, macB = sorted([authBytes, suppBytes])
    nonceA, nonceB = sorted([bytes(anonce), bytes(snonce)])
    data = macA + macB + nonceA + nonceB
    return _prf384(bytes(pmk), "Pairwise key expansion", data, 64)


def splitPtk(ptk):
    """
    Split a 64-byte PTK into its three components:
      * KCK  (0:16)  — Key Confirmation Key
      * KEK  (16:32) — Key Encryption Key
      * TK   (32:48) — Temporal Key (16 bytes for CCMP)
      * MIC_AP_TO_STA / MIC_STA_TO_AP (48:64) — optional MIC keys (unused
        for unicast data frames)

    Returns None when the input is not a 64-byte PTK.
    """
    if not isinstance(ptk, (bytes, bytearray)) or len(ptk) != 64:
        return None
    return {
        "kck": bytes(ptk[0:16]),
        "kek": bytes(ptk[16:32]),
        "tk": bytes(ptk[32:48]),
    }


def computeEapolMic(kck, eapolFrame):
    """
    Compute the EAPOL-Key MIC for a 4-way handshake message using KCK and
    HMAC-SHA1. The MIC is the first 16 bytes of HMAC-SHA1(KCK, eapolFrame)
    where the MIC field inside the frame itself is zeroed out.
    """
    if not isinstance(kck, (bytes, bytearray)) or len(kck) < 16:
        return None
    if not isinstance(eapolFrame, (bytes, bytearray)) or len(eapolFrame) < 95:
        return None
    # MIC field is at offset 81..97 in the EAPOL-Key body (1 descriptor +
    # 2 key_info + 2 key_length + 8 replay_counter + 32 nonce + 8 key_iv +
    # 8 key_rsc + 8 key_id + 16 mic + 2 key_data_length).
    # But the EAPOL frame already includes the 4-byte SNAP/EAPOL header
    # (1 version + 1 type + 2 length), so the MIC is at offset 81 in the
    # *full* EAPOL frame.
    # ... actually, double-check: EAPOL header = 4 bytes. EAPOL-Key body
    # starts at offset 4. Then:
    #   offset 4: descriptor_type (1)
    #   offset 5: key_information (2)
    #   offset 7: key_length (2)
    #   offset 9: replay_counter (8)
    #   offset 17: key_nonce (32)
    #   offset 49: key_iv (16)
    #   offset 65: key_rsc (8)
    #   offset 73: key_id (8)
    #   offset 81: key_mic (16) <-- MIC is here
    #   offset 97: key_data_length (2)
    #   offset 99: key_data (variable)
    micOffset = 81
    if len(eapolFrame) < micOffset + 16:
        return None
    frameForMic = bytes(eapolFrame)
    frameForMic = (
        frameForMic[:micOffset]
        + b"\x00" * 16
        + frameForMic[micOffset + 16:]
    )
    # The MIC is the first 16 bytes of HMAC-SHA1(KCK, frame).
    return hmac.new(bytes(kck[:16]), frameForMic, hashlib.sha1).digest()[:16]
