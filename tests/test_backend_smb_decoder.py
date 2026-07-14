from src.backend.decoders.smb import decodeSMB


def _security_buffer(length, offset):
    return length.to_bytes(2, "little") + length.to_bytes(2, "little") + offset.to_bytes(4, "little")


def _build_ntlm_auth_blob(domain="CORP", username="alice", workstation="WS01"):
    domain_bytes = domain.encode("utf-16le")
    user_bytes = username.encode("utf-16le")
    workstation_bytes = workstation.encode("utf-16le")
    lm_response = bytes(range(24))
    ntlm_response = bytes(range(24, 48))

    header = bytearray(b"NTLMSSP\x00")
    header += (3).to_bytes(4, "little")
    header += b"\x00" * (64 - len(header))

    data_offset = 64
    lm_offset = data_offset
    data_offset += len(lm_response)
    nt_offset = data_offset
    data_offset += len(ntlm_response)
    domain_offset = data_offset
    data_offset += len(domain_bytes)
    user_offset = data_offset
    data_offset += len(user_bytes)
    workstation_offset = data_offset
    data_offset += len(workstation_bytes)

    blob = bytearray(header)
    blob[12:20] = _security_buffer(len(lm_response), lm_offset)
    blob[20:28] = _security_buffer(len(ntlm_response), nt_offset)
    blob[28:36] = _security_buffer(len(domain_bytes), domain_offset)
    blob[36:44] = _security_buffer(len(user_bytes), user_offset)
    blob[44:52] = _security_buffer(len(workstation_bytes), workstation_offset)
    blob[60:64] = (0x00000001).to_bytes(4, "little")
    blob += lm_response
    blob += ntlm_response
    blob += domain_bytes
    blob += user_bytes
    blob += workstation_bytes
    return bytes(blob), lm_response.hex(), ntlm_response.hex()


def _build_smb2_session_setup_payload(with_nbss=False):
    ntlm_blob, lm_hex, ntlm_hex = _build_ntlm_auth_blob()
    payload = bytearray(64)
    payload[0:4] = b"\xfeSMB"
    payload[12:14] = (0x0001).to_bytes(2, "little")
    payload[16:20] = (0).to_bytes(4, "little")
    payload += ntlm_blob
    if with_nbss:
      nbss_length = len(payload).to_bytes(3, "big")
      return b"\x00" + nbss_length + bytes(payload), lm_hex, ntlm_hex
    return bytes(payload), lm_hex, ntlm_hex


def test_decode_smb2_ntlm_authentication_fields():
    payload, lm_hex, ntlm_hex = _build_smb2_session_setup_payload()

    decoded = decodeSMB(payload)

    assert decoded is not None
    assert decoded["Version"] == "SMBv2/v3"
    assert decoded["Command"] == "SESSION_SETUP"
    assert decoded["NTLMSSP"] == "AUTHENTICATE"
    assert decoded["Username"] == "alice"
    assert decoded["Domain"] == "CORP"
    assert decoded["Workstation"] == "WS01"
    assert decoded["LM Response"] == lm_hex
    assert decoded["NTLM Response"] == ntlm_hex


def test_decode_smb2_supports_netbios_wrapped_payloads():
    payload, _lm_hex, ntlm_hex = _build_smb2_session_setup_payload(with_nbss=True)

    decoded = decodeSMB(payload)

    assert decoded is not None
    assert decoded["Command"] == "SESSION_SETUP"
    assert decoded["Username"] == "alice"
    assert decoded["NTLM Response"] == ntlm_hex