"""Microsoft RPC Endpoint Mapper (EPMAP) decoder for TCP/UDP port 135."""

import struct

EPM_INTERFACE_UUID = "e1af8308-5d1f-11c9-91a4-08002b14a0fa"
EPM_OPNUMS = {
    0: "ept_insert", 1: "ept_delete", 2: "ept_lookup", 3: "ept_map",
    4: "ept_lookup_handle_free", 5: "ept_inq_object", 6: "ept_mgmt_delete",
}


def _uuid_from_wire(raw):
    if len(raw) != 16:
        return None
    data1 = raw[0:4][::-1].hex()
    data2 = raw[4:6][::-1].hex()
    data3 = raw[6:8][::-1].hex()
    data4 = raw[8:].hex()
    return f"{data1}-{data2}-{data3}-{data4[:4]}-{data4[4:]}"


def _u16le(data, offset):
    if offset + 2 > len(data):
        return None
    return struct.unpack_from("<H", data, offset)[0]


def _u32le(data, offset):
    if offset + 4 > len(data):
        return None
    return struct.unpack_from("<I", data, offset)[0]


def _parse_bound_epm(data, offset):
    if offset + 32 > len(data) or data[offset : offset + 2] != b"\x05\x00":
        return False
    pdu_type = data[offset + 2]
    if pdu_type not in (0x0B, 0x0C):
        return False
    frag_length = _u16le(data, offset + 8)
    if frag_length is None or frag_length < 32 or offset + frag_length > len(data):
        return False
    context_offset = offset + 16 + 12
    num_contexts = data[context_offset]
    cursor = context_offset + 4
    limit = offset + frag_length
    for _ in range(num_contexts):
        if cursor + 24 > limit:
            return False
        abstract_uuid = _uuid_from_wire(data[cursor + 4 : cursor + 20])
        if abstract_uuid == EPM_INTERFACE_UUID:
            return True
        transfer_count = data[cursor + 2]
        cursor += 24 + (20 * transfer_count)
        if cursor > limit:
            return False
    return False


def _parse_request_stub(stub):
    if len(stub) < 40:
        return {}
    inquiry_type = _u32le(stub, 4)
    object_uuid = _uuid_from_wire(stub[8:24])
    interface_uuid = _uuid_from_wire(stub[24:40])
    version_word = _u32le(stub, 40) if len(stub) >= 44 else None
    result = {
        "Inquiry Type": {0: "interface", 1: "object", 2: "both"}.get(inquiry_type, str(inquiry_type)),
        "Object UUID": object_uuid or "",
        "Interface UUID": interface_uuid or "",
    }
    if version_word is not None:
        result["Interface Version"] = f"{version_word >> 16}.{version_word & 0xffff}"
    return result


def decodeEPMAP(rawPayload):
    if rawPayload is None or len(rawPayload) < 32:
        return None
    try:
        bound = False
        fields = []
        cursor = 0
        while cursor + 16 <= len(rawPayload):
            if rawPayload[cursor : cursor + 2] != b"\x05\x00":
                cursor += 1
                continue
            pdu_type = rawPayload[cursor + 2]
            frag_length = _u16le(rawPayload, cursor + 8)
            if frag_length is None or frag_length < 16 or cursor + frag_length > len(rawPayload):
                cursor += 1
                continue
            if pdu_type in (0x0B, 0x0C) and _parse_bound_epm(rawPayload, cursor):
                bound = True
                fields.append({"name": "Bound Interface", "value": f"EPM {EPM_INTERFACE_UUID}"})
            if pdu_type in (0x00, 0x02) and frag_length >= 24:
                opnum = _u16le(rawPayload, cursor + 22)
                field_prefix = f"Message {len([f for f in fields if f['name'].endswith('Type')]) + 1}"
                fields.append({"name": f"{field_prefix} Type", "value": "Request" if pdu_type == 0 else "Response"})
                fields.append({"name": f"{field_prefix} Opnum", "value": EPM_OPNUMS.get(opnum, f"opnum {opnum}")})
                if pdu_type == 0 and cursor + 28 <= len(rawPayload):
                    stub_length = _u32le(rawPayload, cursor + 24) or 0
                    stub_start = cursor + 28
                    stub_end = min(stub_start + stub_length, cursor + frag_length, len(rawPayload))
                    request = _parse_request_stub(rawPayload[stub_start:stub_end])
                    for name, value in request.items():
                        fields.append({"name": f"{field_prefix} {name}", "value": value})
            cursor += frag_length
        if not bound:
            return None
        return {
            "Protocol": "EPMAP",
            "epmap.protocol": "EPMAP",
            "Fields": fields,
            "epmap.fields": fields,
            "Wire length": len(rawPayload),
            "wire.len": len(rawPayload),
        }
    except (IndexError, struct.error, ValueError):
        return None
