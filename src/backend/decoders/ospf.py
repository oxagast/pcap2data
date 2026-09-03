"""OSPF (Open Shortest Path First) protocol decoder for PacketSnitch backend.

Decodes OSPFv2 (RFC 2328) and OSPFv3 (RFC 5340) messages carried directly
over IP (protocol number 89). OSPF runs directly on IP — there is no TCP/UDP
transport layer.

OSPFv2 header (24 bytes):
  - Version        (1 byte, 2)
  - Type           (1 byte: 1=Hello, 2=DD, 3=LS Request, 4=LS Update, 5=LS ACK)
  - Packet length  (2 bytes, BE)
  - Router ID      (4 bytes, dotted)
  - Area ID        (4 bytes, dotted)
  - Checksum       (2 bytes)
  - Auth Type      (2 bytes: 0=None, 1=Simple, 2=Crypto)
  - Auth Data      (8 bytes)

OSPFv3 header (16 bytes, no authentication fields):
  - Version        (1 byte, 3)
  - Type           (1 byte)
  - Packet length  (2 bytes, BE)
  - Router ID      (4 bytes, dotted)
  - Area ID        (4 bytes, dotted)
  - Checksum       (2 bytes)
  - Instance ID    (1 byte)
  - Reserved       (1 byte, 0)

This decoder follows the same dual-key dict pattern as the other decoders,
returning a dict on success or ``None`` on mismatch.

All five OSPF message types are walked for both OSPFv2 and OSPFv3:
  - Hello (type 1)        — header + active neighbors
  - DBD  (type 2)         — MTU, options, flags, sequence, LSA headers
  - LSR  (type 3)         — LS type / Link State ID / Advertising Router tuples
  - LSU  (type 4)         — LSA count + per-LSA header + type-specific body
  - LSAck (type 5)        — list of LSA headers acknowledged

The LSA type library (``OSPF_LSA_TYPES_V2`` / ``OSPF_LSA_TYPES_V3``) is
wired into LSU and DBD / LSAck walks so each LSA header is annotated with
its human-readable type name.

After decoding, ``extractTopology`` builds an area/neighbour topology map
from the observed Hello adjacencies and LSU-advertised LSA payloads.
"""

import struct

OSPF_VERSIONS = {2: "OSPFv2", 3: "OSPFv3"}

OSPF_TYPES = {
    1: "Hello",
    2: "Database Description",
    3: "Link State Request",
    4: "Link State Update",
    5: "Link State ACK",
}

OSPF_AUTH_TYPES = {
    0: "None",
    1: "Simple Password",
    2: "Cryptographic (MD5)",
}

# ---------------------------------------------------------------------------
# LSA type library — used by LSU / DBD / LSAck / LSR walks
# ---------------------------------------------------------------------------

OSPF_LSA_TYPES_V2 = {
    1: "Router-LSA",
    2: "Network-LSA",
    3: "Summary-LSA (IP network)",
    4: "Summary-LSA (ASBR)",
    5: "AS-External-LSA",
    6: "Group-Membership-LSA",
    7: "Type-7-LSA (NSSA)",
    8: "External-Attributes-LSA",
    9: "Opaque-LSA (link-local)",
    10: "Opaque-LSA (area)",
    11: "Opaque-LSA (AS)",
}

OSPF_LSA_TYPES_V3 = {
    1: "Router-LSA",
    2: "Network-LSA",
    3: "Inter-Area-Prefix-LSA",
    4: "Inter-Area-Router-LSA",
    5: "AS-External-LSA",
    7: "Type-7-LSA (NSSA)",
    8: "Link-LSA",
    9: "Intra-Area-Prefix-LSA",
    10: "Opaque-LSA (area)",
    11: "Opaque-LSA (AS)",
}

# OSPFv2 LSA header = 20 bytes
LSA_HEADER_LEN_V2 = 20
# OSPFv3 LSA header = 20 bytes (same layout, but LS Type field is 2 bytes
# instead of 1, and the options field is 2 bytes — the total is still 20)
LSA_HEADER_LEN_V3 = 20

# DBD / LSAck carry bare LSA headers (no body); LSR carries 12-byte
# request tuples (LS Type + Link State ID + Advertising Router).
LSR_ENTRY_LEN_V2 = 12   # 2-byte padding + 4 + 4 (actual: 4+4+4 with 1-byte type)
LSR_ENTRY_LEN_V3 = 12   # 2-byte LS Type + 2 reserved + 4 + 4


def _formatIpv4(raw):
    if raw is None or len(raw) < 4:
        return "0.0.0.0"
    return ".".join(str(b) for b in raw[:4])


def _lsaTypeName(lsType, version):
    """Return the human-readable LSA type name for the given LS type code.

    OSPFv3 LS type codes carry scope/flag bits in the upper byte; the
    function code (used for lookup) is the lower 13 bits (``lsType & 0x1FFF``).
    """
    table = OSPF_LSA_TYPES_V2 if version == 2 else OSPF_LSA_TYPES_V3
    lookup = lsType if version == 2 else (lsType & 0x1FFF)
    return table.get(lookup, f"Unknown ({lsType})")


def _parseLsaHeaderV2(buf, off):
    """Parse a 20-byte OSPFv2 LSA header at *off*.

    Returns ``(dict, next_off)`` or ``(None, off)`` if not enough bytes.
    """
    if off + LSA_HEADER_LEN_V2 > len(buf):
        return None, off
    lsAge = struct.unpack_from(">H", buf, off)[0]
    options = int(buf[off + 2])
    lsType = int(buf[off + 3])
    linkStateId = _formatIpv4(buf[off + 4:off + 8])
    advRouter = _formatIpv4(buf[off + 8:off + 12])
    seqNum = struct.unpack_from(">I", buf, off + 12)[0]
    checksum = struct.unpack_from(">H", buf, off + 16)[0]
    length = struct.unpack_from(">H", buf, off + 18)[0]
    entry = {
        "LS Age": lsAge,
        "Options": hex(options),
        "LS Type Code": lsType,
        "LS Type": _lsaTypeName(lsType, 2),
        "Link State ID": linkStateId,
        "Advertising Router": advRouter,
        "Sequence Number": seqNum,
        "Checksum": hex(checksum),
        "Length": length,
    }
    return entry, off + LSA_HEADER_LEN_V2


def _parseLsaHeaderV3(buf, off):
    """Parse a 20-byte OSPFv3 LSA header at *off*.

    Returns ``(dict, next_off)`` or ``(None, off)`` if not enough bytes.
    """
    if off + LSA_HEADER_LEN_V3 > len(buf):
        return None, off
    lsAge = struct.unpack_from(">H", buf, off)[0]
    lsType = struct.unpack_from(">H", buf, off + 2)[0]
    linkStateId = _formatIpv4(buf[off + 4:off + 8])
    advRouter = _formatIpv4(buf[off + 8:off + 12])
    seqNum = struct.unpack_from(">I", buf, off + 12)[0]
    checksum = struct.unpack_from(">H", buf, off + 16)[0]
    length = struct.unpack_from(">H", buf, off + 18)[0]
    entry = {
        "LS Age": lsAge,
        "LS Type Code": lsType,
        "LS Type": _lsaTypeName(lsType, 3),
        "Link State ID": linkStateId,
        "Advertising Router": advRouter,
        "Sequence Number": seqNum,
        "Checksum": hex(checksum),
        "Length": length,
    }
    return entry, off + LSA_HEADER_LEN_V3


def _parseLsaBodyV2(entry, buf, bodyOff, bodyLen):
    """Walk the type-specific body of an OSPFv2 LSA.

    Mutates *entry* in-place with body fields. Truncation is tolerated
    (partial walks produce fewer entries).
    """
    lsType = entry["LS Type Code"]
    end = bodyOff + bodyLen
    if lsType == 1:  # Router-LSA
        if bodyOff + 4 > len(buf):
            return
        flags = int(buf[bodyOff])
        numLinks = struct.unpack_from(">H", buf, bodyOff + 2)[0]
        entry["V/B Flags"] = _routerLsaFlags(flags)
        entry["Link Count"] = numLinks
        links = []
        lo = bodyOff + 4
        for _ in range(numLinks):
            if lo + 12 > end or lo + 12 > len(buf):
                break
            linkId = _formatIpv4(buf[lo:lo + 4])
            linkData = _formatIpv4(buf[lo + 4:lo + 8])
            linkType = int(buf[lo + 8])
            tosMetrics = struct.unpack_from(">H", buf, lo + 9)[0]
            metric = struct.unpack_from(">H", buf, lo + 10)[0]
            links.append({
                "Link ID": linkId,
                "Link Data": linkData,
                "Type": _routerLinkType(linkType),
                "TOS Count": tosMetrics,
                "Metric": metric,
            })
            lo += 12
        if links:
            entry["Links"] = links
    elif lsType == 2:  # Network-LSA
        if bodyOff + 4 > len(buf):
            return
        mask = _formatIpv4(buf[bodyOff:bodyOff + 4])
        entry["Network Mask"] = mask
        routers = []
        ro = bodyOff + 4
        while ro + 4 <= end and ro + 4 <= len(buf):
            routers.append(_formatIpv4(buf[ro:ro + 4]))
            ro += 4
        if routers:
            entry["Attached Routers"] = routers
    elif lsType in (3, 4):  # Summary-LSA (network / ASBR)
        if bodyOff + 4 > len(buf):
            return
        mask = _formatIpv4(buf[bodyOff:bodyOff + 4])
        entry["Network Mask"] = mask
        if bodyOff + 8 <= len(buf):
            metric = struct.unpack_from(">I", buf, bodyOff + 4)[0] & 0x00FFFFFF
            entry["Metric"] = metric
    elif lsType == 5 or lsType == 7:  # AS-External / Type-7 NSSA
        if bodyOff + 4 > len(buf):
            return
        mask = _formatIpv4(buf[bodyOff:bodyOff + 4])
        entry["Network Mask"] = mask
        if bodyOff + 16 <= len(buf):
            metric = struct.unpack_from(">I", buf, bodyOff + 4)[0] & 0x00FFFFFF
            fwdAddr = _formatIpv4(buf[bodyOff + 8:bodyOff + 12])
            routeTag = struct.unpack_from(">I", buf, bodyOff + 12)[0]
            entry["Metric"] = metric
            entry["Forwarding Address"] = fwdAddr
            entry["External Route Tag"] = routeTag


def _parseLsaBodyV3(entry, buf, bodyOff, bodyLen):
    """Walk the type-specific body of an OSPFv3 LSA.

    Mutates *entry* in-place with body fields.
    """
    lsType = entry["LS Type Code"]
    end = bodyOff + bodyLen
    if lsType == 0x2001:  # Router-LSA (OSPFv3 uses 0x2001 etc.)
        if bodyOff + 4 > len(buf):
            return
        flags = int(buf[bodyOff])
        options = int(buf[bodyOff + 1])
        numLinks = struct.unpack_from(">H", buf, bodyOff + 2)[0]
        entry["V/B Flags"] = _routerLsaFlags(flags)
        entry["Options"] = hex(options)
        entry["Link Count"] = numLinks
        links = []
        lo = bodyOff + 4
        for _ in range(numLinks):
            if lo + 16 > end or lo + 16 > len(buf):
                break
            ifaceId = struct.unpack_from(">I", buf, lo)[0]
            nbrIfaceId = struct.unpack_from(">I", buf, lo + 4)[0]
            nbrRouterId = _formatIpv4(buf[lo + 8:lo + 12])
            metric = struct.unpack_from(">H", buf, lo + 12)[0]
            linkType = int(buf[lo + 14])
            links.append({
                "Interface ID": ifaceId,
                "Neighbor Interface ID": nbrIfaceId,
                "Neighbor Router ID": nbrRouterId,
                "Metric": metric,
                "Type": _routerLinkType(linkType),
            })
            lo += 16
        if links:
            entry["Links"] = links
    elif lsType == 0x2002:  # Network-LSA
        if bodyOff + 4 > len(buf):
            return
        options = struct.unpack_from(">I", buf, bodyOff)[0]
        entry["Options"] = hex(options)
        routers = []
        ro = bodyOff + 4
        while ro + 4 <= end and ro + 4 <= len(buf):
            routers.append(_formatIpv4(buf[ro:ro + 4]))
            ro += 4
        if routers:
            entry["Attached Routers"] = routers
    elif lsType == 0x2003:  # Inter-Area-Prefix-LSA
        if bodyOff + 4 > len(buf):
            return
        prefixLen = int(buf[bodyOff])
        prefixOpts = int(buf[bodyOff + 1])
        entry["Prefix Length"] = prefixLen
        entry["Prefix Options"] = hex(prefixOpts)
        metric = struct.unpack_from(">I", buf, bodyOff + 4)[0] & 0x00FFFFFF
        entry["Metric"] = metric
    elif lsType == 0x2004:  # Inter-Area-Router-LSA
        if bodyOff + 4 > len(buf):
            return
        metric = struct.unpack_from(">I", buf, bodyOff)[0] & 0x00FFFFFF
        entry["Metric"] = metric
        if bodyOff + 12 <= len(buf):
            entry["Destination Router ID"] = _formatIpv4(buf[bodyOff + 8:bodyOff + 12])
    elif lsType == 0x2005:  # AS-External-LSA
        _parseV3AsExternal(entry, buf, bodyOff, end)
    elif lsType == 0x2007:  # Type-7 NSSA
        _parseV3AsExternal(entry, buf, bodyOff, end)
    elif lsType == 0x0008:  # Link-LSA
        if bodyOff + 8 > len(buf):
            return
        priority = int(buf[bodyOff])
        options = struct.unpack_from(">H", buf, bodyOff + 1)[0]
        entry["Router Priority"] = priority
        entry["Options"] = hex(options)
        llAddr = _formatIpv4(buf[bodyOff + 4:bodyOff + 8])
        entry["Link-Local Address"] = llAddr
    elif lsType == 0x2009:  # Intra-Area-Prefix-LSA
        if bodyOff + 4 > len(buf):
            return
        numPrefixes = struct.unpack_from(">H", buf, bodyOff)[0]
        entry["Prefix Count"] = numPrefixes


def _parseV3AsExternal(entry, buf, bodyOff, end):
    """Parse the common OSPFv3 AS-External / Type-7 LSA body."""
    if bodyOff + 12 > len(buf):
        return
    flags = int(buf[bodyOff])
    metric = struct.unpack_from(">I", buf, bodyOff + 1)[0] & 0x00FFFFFF
    entry["Flags"] = hex(flags)
    entry["Metric"] = metric
    if bodyOff + 16 <= len(buf):
        refLsType = struct.unpack_from(">H", buf, bodyOff + 12)[0]
        refLsId = _formatIpv4(buf[bodyOff + 12 + 2:bodyOff + 16])
        entry["Referenced LS Type"] = _lsaTypeName(refLsType, 3)
        entry["Referenced Link State ID"] = refLsId


def _routerLsaFlags(flags):
    """Decode the V/B bits in a Router-LSA flags byte."""
    names = []
    if flags & 0x01:
        names.append("B (Border)")
    if flags & 0x02:
        names.append("E (ASBR)")
    if flags & 0x04:
        names.append("V (Virtual)")
    return " | ".join(names) if names else "None"


def _routerLinkType(code):
    """Map a Router-LSA link type code to its name."""
    return {
        1: "Point-to-point connection",
        2: "Connection to a transit network",
        3: "Connection to a stub network",
        4: "Virtual link",
    }.get(code, f"Unknown ({code})")


def _parseLsrEntryV2(buf, off):
    """Parse a 12-byte OSPFv2 LS Request entry at *off*.

    Layout: 3 reserved + 1 LS type + 4 Link State ID + 4 Adv Router.
    """
    if off + LSR_ENTRY_LEN_V2 > len(buf):
        return None, off
    lsType = int(buf[off + 3])
    linkStateId = _formatIpv4(buf[off + 4:off + 8])
    advRouter = _formatIpv4(buf[off + 8:off + 12])
    return {
        "LS Type Code": lsType,
        "LS Type": _lsaTypeName(lsType, 2),
        "Link State ID": linkStateId,
        "Advertising Router": advRouter,
    }, off + LSR_ENTRY_LEN_V2


def _parseLsrEntryV3(buf, off):
    """Parse a 12-byte OSPFv3 LS Request entry at *off*.

    Layout: 2 LS type + 2 reserved + 4 Link State ID + 4 Adv Router.
    """
    if off + LSR_ENTRY_LEN_V3 > len(buf):
        return None, off
    lsType = struct.unpack_from(">H", buf, off)[0]
    linkStateId = _formatIpv4(buf[off + 4:off + 8])
    advRouter = _formatIpv4(buf[off + 8:off + 12])
    return {
        "LS Type Code": lsType,
        "LS Type": _lsaTypeName(lsType, 3),
        "Link State ID": linkStateId,
        "Advertising Router": advRouter,
    }, off + LSR_ENTRY_LEN_V3


def _walkHelloV2(result, buf):
    """Walk OSPFv2 Hello body (offset 24+)."""
    if len(buf) < 44:
        return
    networkMask = _formatIpv4(buf[24:28])
    helloInterval = struct.unpack_from(">H", buf, 28)[0]
    options = int(buf[30])
    priority = int(buf[31])
    deadInterval = struct.unpack_from(">I", buf, 32)[0]
    dr = _formatIpv4(buf[36:40])
    bdr = _formatIpv4(buf[40:44])
    result.update(
        {
            "Network Mask": networkMask,
            "ospf.network_mask": networkMask,
            "network.ospf.network_mask": networkMask,
            "Hello Interval (s)": helloInterval,
            "ospf.hello_interval": helloInterval,
            "network.ospf.hello_interval": helloInterval,
            "Options": hex(options),
            "ospf.options": hex(options),
            "network.ospf.options": hex(options),
            "Router Priority": priority,
            "ospf.router_priority": priority,
            "network.ospf.router_priority": priority,
            "Dead Interval (s)": deadInterval,
            "ospf.dead_interval": deadInterval,
            "network.ospf.dead_interval": deadInterval,
            "Designated Router": dr,
            "ospf.dr": dr,
            "network.ospf.dr": dr,
            "Backup Designated Router": bdr,
            "ospf.bdr": bdr,
            "network.ospf.bdr": bdr,
        }
    )
    neighbors = []
    off = 44
    while off + 4 <= len(buf):
        neighbors.append(_formatIpv4(buf[off:off + 4]))
        off += 4
    if neighbors:
        result["Active Neighbors"] = neighbors
        result["ospf.neighbors"] = neighbors
        result["network.ospf.neighbors"] = neighbors
        result["Neighbor Count"] = len(neighbors)
        result["ospf.neighbor_count"] = len(neighbors)
        result["network.ospf.neighbor_count"] = len(neighbors)


def _walkDbdV2(result, buf):
    """Walk OSPFv2 Database Description body (offset 24+).

    After the 8-byte DD header (MTU + Options + Flags + Seq), the
    body carries zero or more 20-byte LSA headers.
    """
    if len(buf) < 32:
        return
    mtu = struct.unpack_from(">H", buf, 24)[0]
    options = int(buf[26])
    flags = int(buf[27])
    seqNum = struct.unpack_from(">I", buf, 28)[0]
    flagNames = []
    if flags & 0x01:
        flagNames.append("MS (Master/Slave)")
    if flags & 0x02:
        flagNames.append("M (More)")
    if flags & 0x04:
        flagNames.append("I (Init)")
    result.update(
        {
            "Interface MTU": mtu,
            "ospf.if_mtu": mtu,
            "network.ospf.if_mtu": mtu,
            "Options": hex(options),
            "ospf.options": hex(options),
            "network.ospf.options": hex(options),
            "DD Flags": " | ".join(flagNames) if flagNames else "None",
            "ospf.dd_flags": hex(flags),
            "network.ospf.dd_flags": hex(flags),
            "DD Sequence": seqNum,
            "ospf.dd_seq": seqNum,
            "network.ospf.dd_seq": seqNum,
        }
    )
    # LSA headers follow the 8-byte DD body header (offset 32)
    headers = []
    off = 32
    while off + LSA_HEADER_LEN_V2 <= len(buf):
        entry, off = _parseLsaHeaderV2(buf, off)
        if entry is None:
            break
        headers.append(entry)
    if headers:
        result["LSA Headers"] = headers
        result["ospf.lsa_headers"] = len(headers)
        result["network.ospf.lsa_headers"] = len(headers)


def _walkLsr(result, buf, off, version):
    """Walk Link State Request entries starting at *off*.

    Each entry is 12 bytes (LS Type + Link State ID + Adv Router).
    Works for both OSPFv2 and OSPFv3 with the appropriate parser.
    """
    entries = []
    if version == 2:
        while off + LSR_ENTRY_LEN_V2 <= len(buf):
            entry, off = _parseLsrEntryV2(buf, off)
            if entry is None:
                break
            entries.append(entry)
    else:
        while off + LSR_ENTRY_LEN_V3 <= len(buf):
            entry, off = _parseLsrEntryV3(buf, off)
            if entry is None:
                break
            entries.append(entry)
    if entries:
        result["LS Requests"] = entries
        result["ospf.lsr_count"] = len(entries)
        result["network.ospf.lsr_count"] = len(entries)


def _walkLsuV2(result, buf):
    """Walk OSPFv2 Link State Update body (offset 24+).

    Layout: 4-byte LSA count, then *lsaCount* LSAs each consisting of a
    20-byte header + a type-specific body.
    """
    if len(buf) < 28:
        return
    lsaCount = struct.unpack_from(">I", buf, 24)[0]
    result["LSA Count"] = lsaCount
    result["ospf.lsa_count"] = lsaCount
    result["network.ospf.lsa_count"] = lsaCount
    lsas = []
    off = 28
    for _ in range(lsaCount):
        entry, off = _parseLsaHeaderV2(buf, off)
        if entry is None:
            break
        bodyLen = entry["Length"] - LSA_HEADER_LEN_V2
        if bodyLen > 0:
            _parseLsaBodyV2(entry, buf, off, bodyLen)
            off += bodyLen
        lsas.append(entry)
    if lsas:
        result["LSAs"] = lsas


def _walkLsuV3(result, buf):
    """Walk OSPFv3 Link State Update body (offset 16+).

    Layout: 4-byte LSA count, then *lsaCount* LSAs each consisting of a
    20-byte header + a type-specific body.
    """
    if len(buf) < 20:
        return
    lsaCount = struct.unpack_from(">I", buf, 16)[0]
    result["LSA Count"] = lsaCount
    result["ospf.lsa_count"] = lsaCount
    result["network.ospf.lsa_count"] = lsaCount
    lsas = []
    off = 20
    for _ in range(lsaCount):
        entry, off = _parseLsaHeaderV3(buf, off)
        if entry is None:
            break
        bodyLen = entry["Length"] - LSA_HEADER_LEN_V3
        if bodyLen > 0:
            _parseLsaBodyV3(entry, buf, off, bodyLen)
            off += bodyLen
        lsas.append(entry)
    if lsas:
        result["LSAs"] = lsas


def _walkLsack(result, buf, off, version):
    """Walk Link State ACK body — a list of bare LSA headers."""
    headers = []
    if version == 2:
        while off + LSA_HEADER_LEN_V2 <= len(buf):
            entry, off = _parseLsaHeaderV2(buf, off)
            if entry is None:
                break
            headers.append(entry)
    else:
        while off + LSA_HEADER_LEN_V3 <= len(buf):
            entry, off = _parseLsaHeaderV3(buf, off)
            if entry is None:
                break
            headers.append(entry)
    if headers:
        result["LSA ACKs"] = headers
        result["ospf.lsack_count"] = len(headers)
        result["network.ospf.lsack_count"] = len(headers)


# ---------------------------------------------------------------------------
# OSPFv3 message-type walks
# ---------------------------------------------------------------------------

def _walkHelloV3(result, buf):
    """Walk OSPFv3 Hello body (offset 16+)."""
    if len(buf) < 36:
        return
    interfaceId = struct.unpack_from(">I", buf, 16)[0]
    priority = int(buf[20])
    options = struct.unpack_from(">I", buf, 21)[0] & 0x00FFFFFF
    helloInterval = struct.unpack_from(">H", buf, 24)[0]
    deadInterval = struct.unpack_from(">H", buf, 26)[0]
    dr = _formatIpv4(buf[28:32])
    bdr = _formatIpv4(buf[32:36])
    result.update(
        {
            "Interface ID": interfaceId,
            "ospf.interface_id": interfaceId,
            "network.ospf.interface_id": interfaceId,
            "Router Priority": priority,
            "ospf.router_priority": priority,
            "network.ospf.router_priority": priority,
            "Options": hex(options),
            "ospf.options": hex(options),
            "network.ospf.options": hex(options),
            "Hello Interval (s)": helloInterval,
            "ospf.hello_interval": helloInterval,
            "network.ospf.hello_interval": helloInterval,
            "Dead Interval (s)": deadInterval,
            "ospf.dead_interval": deadInterval,
            "network.ospf.dead_interval": deadInterval,
            "Designated Router": dr,
            "ospf.dr": dr,
            "network.ospf.dr": dr,
            "Backup Designated Router": bdr,
            "ospf.bdr": bdr,
            "network.ospf.bdr": bdr,
        }
    )
    neighbors = []
    off = 36
    while off + 4 <= len(buf):
        neighbors.append(_formatIpv4(buf[off:off + 4]))
        off += 4
    if neighbors:
        result["Active Neighbors"] = neighbors
        result["ospf.neighbors"] = neighbors
        result["network.ospf.neighbors"] = neighbors
        result["Neighbor Count"] = len(neighbors)
        result["ospf.neighbor_count"] = len(neighbors)
        result["network.ospf.neighbor_count"] = len(neighbors)


def _walkDbdV3(result, buf):
    """Walk OSPFv3 Database Description body (offset 16+).

    OSPFv3 DBD layout (after the 16-byte OSPF header):
      - Reserved     (1 byte, 0)
      - Options      (3 bytes)
      - Interface MTU (2 bytes)
      - Reserved     (1 byte, 0)
      - DD Flags     (1 byte: I/M/MS)
      - DD Sequence  (4 bytes)
    Then zero or more 20-byte LSA headers.
    """
    if len(buf) < 28:
        return
    options = (int(buf[17]) << 16) | (int(buf[18]) << 8) | int(buf[19])
    mtu = struct.unpack_from(">H", buf, 20)[0]
    flags = int(buf[23])
    seqNum = struct.unpack_from(">I", buf, 24)[0]
    flagNames = []
    if flags & 0x01:
        flagNames.append("MS (Master/Slave)")
    if flags & 0x02:
        flagNames.append("M (More)")
    if flags & 0x04:
        flagNames.append("I (Init)")
    result.update(
        {
            "Options": hex(options),
            "ospf.options": hex(options),
            "network.ospf.options": hex(options),
            "Interface MTU": mtu,
            "ospf.if_mtu": mtu,
            "network.ospf.if_mtu": mtu,
            "DD Flags": " | ".join(flagNames) if flagNames else "None",
            "ospf.dd_flags": hex(flags),
            "network.ospf.dd_flags": hex(flags),
            "DD Sequence": seqNum,
            "ospf.dd_seq": seqNum,
            "network.ospf.dd_seq": seqNum,
        }
    )
    # LSA headers follow the 12-byte DD body header (offset 28)
    headers = []
    off = 28
    while off + LSA_HEADER_LEN_V3 <= len(buf):
        entry, off = _parseLsaHeaderV3(buf, off)
        if entry is None:
            break
        headers.append(entry)
    if headers:
        result["LSA Headers"] = headers
        result["ospf.lsa_headers"] = len(headers)
        result["network.ospf.lsa_headers"] = len(headers)


# ---------------------------------------------------------------------------
# Topology extraction
# ---------------------------------------------------------------------------

def extractTopology(decodedPackets):
    """Build an area / neighbour topology map from decoded OSPF packets.

    *decodedPackets* is an iterable of dicts produced by :func:`decodeOSPF`.
    The return value is a dict with:

    - ``areas``: ``{ areaId: { "routers": set, "dr": str, "bdr": str } }``
    - ``adjacencies``: ``{ frozenset({r1, r2}): { "areas": set, "seen": int } }``
    - ``lsa_graph``: ``{ advRouter: [ { type, linkStateId, links [...] } ] }``
    - ``summary``: ``{ "areas": int, "routers": int, "adjacencies": int }``
    """
    areas = {}
    adjacencies = {}
    lsaGraph = {}

    for pkt in decodedPackets:
        if not isinstance(pkt, dict):
            continue
        routerId = pkt.get("Router ID")
        areaId = pkt.get("Area ID")
        if not routerId or not areaId:
            continue

        area = areas.setdefault(areaId, {"routers": set(), "dr": None, "bdr": None})
        area["routers"].add(routerId)

        pktType = pkt.get("Type")
        if pktType == "Hello":
            dr = pkt.get("Designated Router")
            bdr = pkt.get("Backup Designated Router")
            if dr and dr != "0.0.0.0":
                area["dr"] = dr
            if bdr and bdr != "0.0.0.0":
                area["bdr"] = bdr
            for nbr in pkt.get("Active Neighbors", []):
                if nbr == "0.0.0.0" or nbr == routerId:
                    continue
                key = frozenset((routerId, nbr))
                adj = adjacencies.setdefault(key, {"areas": set(), "seen": 0})
                adj["areas"].add(areaId)
                adj["seen"] += 1

        if pktType == "Link State Update":
            for lsa in pkt.get("LSAs", []):
                adv = lsa.get("Advertising Router")
                if not adv:
                    continue
                entry = {
                    "type": lsa.get("LS Type"),
                    "type_code": lsa.get("LS Type Code"),
                    "link_state_id": lsa.get("Link State ID"),
                    "area": areaId,
                }
                if "Links" in lsa:
                    entry["links"] = lsa["Links"]
                if "Attached Routers" in lsa:
                    entry["attached_routers"] = lsa["Attached Routers"]
                lsaGraph.setdefault(adv, []).append(entry)

    # Serialise sets for JSON-friendliness
    serialisedAreas = {}
    for aid, info in areas.items():
        serialisedAreas[aid] = {
            "routers": sorted(info["routers"]),
            "dr": info["dr"],
            "bdr": info["bdr"],
        }
    serialisedAdj = {}
    for pair, info in adjacencies.items():
        pairList = sorted(pair)
        serialisedAdj[" <-> ".join(pairList)] = {
            "routers": pairList,
            "areas": sorted(info["areas"]),
            "occurrences": info["seen"],
        }

    return {
        "areas": serialisedAreas,
        "adjacencies": serialisedAdj,
        "lsa_graph": lsaGraph,
        "summary": {
            "areas": len(serialisedAreas),
            "routers": len({r for a in serialisedAreas.values() for r in a["routers"]}),
            "adjacencies": len(serialisedAdj),
        },
    }


# ---------------------------------------------------------------------------
# Main decoder
# ---------------------------------------------------------------------------

def decodeOSPF(p, rawPayload):
    """Decode an OSPFv2/v3 packet from a scapy packet or raw IP payload.

    Prefers the scapy OSPF layer when present; otherwise parses the raw
    bytes. Returns a dict on success or ``None`` when the bytes do not
    match the OSPF wire format.
    """
    try:
        if rawPayload is None or len(rawPayload) < 16:
            return None

        version = int(rawPayload[0])
        if version not in (2, 3):
            return None

        msgType = int(rawPayload[1])
        typeName = OSPF_TYPES.get(msgType, f"Unknown ({msgType})")
        versionName = OSPF_VERSIONS.get(version, f"OSPFv{version}")

        if version == 2:
            if len(rawPayload) < 24:
                return None
            pktLen = struct.unpack_from(">H", rawPayload, 2)[0]
            routerId = _formatIpv4(rawPayload[4:8])
            areaId = _formatIpv4(rawPayload[8:12])
            checksum = struct.unpack_from(">H", rawPayload, 12)[0]
            authType = struct.unpack_from(">H", rawPayload, 14)[0]
            authTypeName = OSPF_AUTH_TYPES.get(authType, f"Unknown ({authType})")
            result = {
                "Version": versionName,
                "ospf.version": versionName,
                "network.ospf.version": versionName,
                "Type": typeName,
                "ospf.type": typeName,
                "network.ospf.type": typeName,
                "Packet Length": pktLen,
                "ospf.length": pktLen,
                "network.ospf.length": pktLen,
                "Router ID": routerId,
                "ospf.router_id": routerId,
                "network.ospf.router_id": routerId,
                "Area ID": areaId,
                "ospf.area_id": areaId,
                "network.ospf.area_id": areaId,
                "Checksum": hex(checksum),
                "ospf.chksum": hex(checksum),
                "network.ospf.chksum": hex(checksum),
                "Auth Type": authTypeName,
                "ospf.auth_type": authTypeName,
                "network.ospf.auth_type": authTypeName,
                "Auth Type Code": authType,
                "ospf.auth_type_code": authType,
                "network.ospf.auth_type_code": authType,
            }
            # Walk each message type
            if msgType == 1:
                _walkHelloV2(result, rawPayload)
            elif msgType == 2:
                _walkDbdV2(result, rawPayload)
            elif msgType == 3:
                _walkLsr(result, rawPayload, 24, 2)
            elif msgType == 4:
                _walkLsuV2(result, rawPayload)
            elif msgType == 5:
                _walkLsack(result, rawPayload, 24, 2)
        else:
            # OSPFv3 (16-byte header)
            if len(rawPayload) < 16:
                return None
            pktLen = struct.unpack_from(">H", rawPayload, 2)[0]
            routerId = _formatIpv4(rawPayload[4:8])
            areaId = _formatIpv4(rawPayload[8:12])
            checksum = struct.unpack_from(">H", rawPayload, 12)[0]
            instanceId = int(rawPayload[14])
            result = {
                "Version": versionName,
                "ospf.version": versionName,
                "network.ospf.version": versionName,
                "Type": typeName,
                "ospf.type": typeName,
                "network.ospf.type": typeName,
                "Packet Length": pktLen,
                "ospf.length": pktLen,
                "network.ospf.length": pktLen,
                "Router ID": routerId,
                "ospf.router_id": routerId,
                "network.ospf.router_id": routerId,
                "Area ID": areaId,
                "ospf.area_id": areaId,
                "network.ospf.area_id": areaId,
                "Checksum": hex(checksum),
                "ospf.chksum": hex(checksum),
                "network.ospf.chksum": hex(checksum),
                "Instance ID": instanceId,
                "ospf.instance_id": instanceId,
                "network.ospf.instance_id": instanceId,
            }
            # Walk each message type
            if msgType == 1:
                _walkHelloV3(result, rawPayload)
            elif msgType == 2:
                _walkDbdV3(result, rawPayload)
            elif msgType == 3:
                _walkLsr(result, rawPayload, 16, 3)
            elif msgType == 4:
                _walkLsuV3(result, rawPayload)
            elif msgType == 5:
                _walkLsack(result, rawPayload, 16, 3)

        result["Wire length"] = len(rawPayload)
        result["wire.len"] = len(rawPayload)
        result["network.ospf.wire.len"] = len(rawPayload)
        return result
    except Exception:
        return None