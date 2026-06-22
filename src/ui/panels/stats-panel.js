const threadName = "Stats";
function isProtocolLikeFieldName(fieldName, fieldValue) {
  if (fieldName.includes(".")) return false;
  if (!fieldValue || typeof fieldValue !== "object") return false;
  if (Array.isArray(fieldValue)) return false;
  // Exclude transport metadata objects such as "TCP Flag Data".
  if (!/^[A-Za-z][A-Za-z0-9]*$/.test(fieldName)) return false;
  return true;
}

function collectPacketDecodedProtocolNames(packetInfo) {
  const decodedNames = new Set();

  const packetDecoded =
    packetInfo?.["Decoded Protocols"] || packetInfo?.["packet.decoded_protocols"];
  if (Array.isArray(packetDecoded)) {
    packetDecoded.forEach((decodedProtocol) => {
      const name = normalizeStatsTextValue(decodedProtocol);
      if (name) decodedNames.add(name);
    });
  }

  const linkControlDecoded =
    packetInfo?.["Link Control"]?.["Detected Protocols"] ||
    packetInfo?.["Link Control"]?.["wan.detected"];
  if (Array.isArray(linkControlDecoded)) {
    linkControlDecoded.forEach((decodedProtocol) => {
      const name = normalizeStatsTextValue(decodedProtocol);
      if (name) decodedNames.add(name);
    });
  }

  const sectionNames = ["TCP", "UDP", "ICMP", "IGMP", "LINK", "IP"];
  sectionNames.forEach((sectionName) => {
    const section = packetInfo?.[sectionName];
    if (!section || typeof section !== "object") return;
    Object.entries(section).forEach(([fieldName, fieldValue]) => {
      if (isProtocolLikeFieldName(fieldName, fieldValue)) {
        const name = normalizeStatsTextValue(fieldName);
        if (name) decodedNames.add(name);
      }
    });
  });

  return [...decodedNames];
}

function normalizeStatsTextValue(value, options = {}) {
  if (value === null || value === undefined) return null;

  const { stripNonPrintable = false } = options;
  let normalized = typeof value === "string" ? value : String(value);

  if (stripNonPrintable) {
    normalized = normalized.replace(/[\x00-\x1F\x7F]/g, "");
  }

  normalized = normalized.trim();
  return normalized ? normalized : null;
}

function normalizeStatsPortValue(value) {
  if (value === null || value === undefined) return null;
  if (typeof value === "number") return Number.isFinite(value) ? value : null;
  const normalizedText = normalizeStatsTextValue(value);
  if (!normalizedText || !/^\d+$/.test(normalizedText)) return null;
  return Number(normalizedText);
}

function parseStatsPacketTimestampMs(packet) {
  const packetTimestamp = packet?.["Packet Info"]?.["Packet Timestamp"];
  if (typeof packetTimestamp !== "string" || !packetTimestamp.trim()) {
    return null;
  }
  const parsedTimestamp = Date.parse(packetTimestamp);
  return Number.isFinite(parsedTimestamp) ? parsedTimestamp : null;
}

function parseStatsPacketProcessedNumber(packet) {
  const processedRaw = Number(packet?.["Packet Info"]?.["Packet Processed"]);
  return Number.isFinite(processedRaw) ? processedRaw : null;
}

function parseStatsPacketIndexNumber(packet) {
  const packetIndexRaw = Number(packet?.["Packet Info"]?.["Index"]);
  return Number.isFinite(packetIndexRaw) ? packetIndexRaw : null;
}

function compareStatsPacketsChronologically(
  leftPacket,
  rightPacket,
  leftFallbackOrder = 0,
  rightFallbackOrder = 0,
) {
  const leftTimestamp = parseStatsPacketTimestampMs(leftPacket);
  const rightTimestamp = parseStatsPacketTimestampMs(rightPacket);
  if (leftTimestamp !== null && rightTimestamp !== null && leftTimestamp !== rightTimestamp) {
    return leftTimestamp - rightTimestamp;
  }
  if (leftTimestamp !== null && rightTimestamp === null) return -1;
  if (leftTimestamp === null && rightTimestamp !== null) return 1;

  const leftProcessed = parseStatsPacketProcessedNumber(leftPacket);
  const rightProcessed = parseStatsPacketProcessedNumber(rightPacket);
  if (leftProcessed !== null && rightProcessed !== null && leftProcessed !== rightProcessed) {
    return leftProcessed - rightProcessed;
  }
  if (leftProcessed !== null && rightProcessed === null) return -1;
  if (leftProcessed === null && rightProcessed !== null) return 1;

  const leftIndex = parseStatsPacketIndexNumber(leftPacket);
  const rightIndex = parseStatsPacketIndexNumber(rightPacket);
  if (leftIndex !== null && rightIndex !== null && leftIndex !== rightIndex) {
    return leftIndex - rightIndex;
  }
  if (leftIndex !== null && rightIndex === null) return -1;
  if (leftIndex === null && rightIndex !== null) return 1;

  return leftFallbackOrder - rightFallbackOrder;
}

function parseStatsTcpSequenceNumber(transportData) {
  const sequenceCandidates = [
    transportData?.["TCP Sequence Number"],
    transportData?.["tcp.seq"],
    transportData?.["Sequence Number"],
    transportData?.["Sequence"],
  ];
  for (const candidate of sequenceCandidates) {
    const parsed = Number(candidate);
    if (Number.isFinite(parsed)) return parsed;
  }
  return null;
}

function getStatsTcpSegmentLength(packetInfo, transportData) {
  const payloadLenRaw = Number(packetInfo?.["Raw data"]?.["Payload Length"]);
  const payloadLen = Number.isFinite(payloadLenRaw) && payloadLenRaw > 0
    ? payloadLenRaw
    : 0;

  const flagsText = String(transportData?.["TCP Flag Data"]?.["Flags"] || "").toUpperCase();
  const controlByteLength =
    (flagsText.includes("SYN") ? 1 : 0) + (flagsText.includes("FIN") ? 1 : 0);
  return payloadLen + controlByteLength;
}

function mergeStatsSequenceRange(ranges, start, end) {
  if (!Array.isArray(ranges) || !Number.isFinite(start) || !Number.isFinite(end) || end <= start) {
    return;
  }

  ranges.push({ start, end });
  ranges.sort((left, right) => left.start - right.start);

  const merged = [];
  for (const currentRange of ranges) {
    if (!merged.length) {
      merged.push({ ...currentRange });
      continue;
    }
    const lastRange = merged[merged.length - 1];
    if (currentRange.start <= lastRange.end) {
      lastRange.end = Math.max(lastRange.end, currentRange.end);
      continue;
    }
    merged.push({ ...currentRange });
  }

  ranges.length = 0;
  ranges.push(...merged);
}

function getStatsSequenceRangeOverlapLength(ranges, start, end) {
  if (!Array.isArray(ranges) || end <= start) return 0;
  let overlapLength = 0;
  for (const range of ranges) {
    if (range.end <= start) continue;
    if (range.start >= end) break;
    const overlapStart = Math.max(start, range.start);
    const overlapEnd = Math.min(end, range.end);
    if (overlapEnd > overlapStart) {
      overlapLength += overlapEnd - overlapStart;
    }
  }
  return overlapLength;
}

function computeTcpStreamAnomalyCounts(streamPacketsByKey) {
  let retransmissionCount = 0;
  let outOfOrderCount = 0;

  streamPacketsByKey.forEach((streamPackets) => {
    if (!Array.isArray(streamPackets) || streamPackets.length === 0) return;

    const sortedStreamPackets = streamPackets
      .map((packet, originalOrder) => ({ packet, originalOrder }))
      .sort((left, right) =>
        compareStatsPacketsChronologically(
          left.packet,
          right.packet,
          left.originalOrder,
          right.originalOrder,
        ),
      )
      .map((entry) => entry.packet);

    const streamStateByDirection = new Map();
    sortedStreamPackets.forEach((packet) => {
      const packetInfo = packet?.["Packet Info"] || {};
      const protocol = String(packetInfo["Protocol"] || "").toUpperCase();
      if (protocol !== "TCP") return;

      const transportData = packetInfo["TCP"] || {};
      const sourceIp = packetInfo?.["IP"]?.["Source IP"] || "";
      const destinationIp = packetInfo?.["IP"]?.["Destination IP"] || "";
      const sourcePort = transportData?.["Source port"] ?? "";
      const destinationPort = transportData?.["Destination port"] ?? "";
      const directionKey = `${sourceIp}:${sourcePort}>${destinationIp}:${destinationPort}`;
      const sequenceNumber = parseStatsTcpSequenceNumber(transportData);
      const segmentLength = getStatsTcpSegmentLength(packetInfo, transportData);

      const state = streamStateByDirection.get(directionKey) || {
        seenRanges: [],
        maxStartObserved: null,
      };

      if (sequenceNumber === null || segmentLength <= 0) {
        streamStateByDirection.set(directionKey, state);
        return;
      }

      const sequenceEnd = sequenceNumber + segmentLength;
      const overlapLength = getStatsSequenceRangeOverlapLength(
        state.seenRanges,
        sequenceNumber,
        sequenceEnd,
      );
      const isRetransmission = overlapLength > 0;
      const isOutOfOrder =
        Number.isFinite(state.maxStartObserved) && sequenceNumber < state.maxStartObserved;

      if (isRetransmission) retransmissionCount += 1;
      if (isOutOfOrder) outOfOrderCount += 1;

      mergeStatsSequenceRange(state.seenRanges, sequenceNumber, sequenceEnd);
      state.maxStartObserved = Number.isFinite(state.maxStartObserved)
        ? Math.max(state.maxStartObserved, sequenceNumber)
        : sequenceNumber;
      streamStateByDirection.set(directionKey, state);
    });
  });

  return {
    retransmissionCount,
    outOfOrderCount,
  };
}

function buildCaptureStats(capturedPackets, bookmarkCount = 0) {
  const protocols = new Set();
  const networkProtocols = new Set();
  const linkProtocols = new Set();
  const transportProtocols = new Set();
  const decodedProtocols = new Set();
  const arpOperations = new Set();
  const igmpMessageTypes = new Set();
  const hosts = new Set();
  const ports = new Set();
  const macVendors = new Set();
  const mimeTypes = new Set();
  const locations = new Map();
  const hostnames = new Set();
  const dataTypes = new Set();
  const streams = new Map();
  const tcpStreams = new Map();
  let encryptedCount = 0;
  let unencryptedCount = 0;
  let totalPackets = 0;
  if (!capturedPackets || !capturedPackets["Host"]) return null;

  const getStreamKey = (packetInfo) => {
    const transportName = packetInfo?.["Protocol"] || "Unknown";
    const transportData = packetInfo?.[transportName] || {};
    const sourceIp = packetInfo?.["IP"]?.["Source IP"] ?? "";
    const destinationIp = packetInfo?.["IP"]?.["Destination IP"] ?? "";
    const sourcePort = transportData?.["Source port"] ?? "";
    const destinationPort = transportData?.["Destination port"] ?? "";

    const endpointA = `${sourceIp}:${sourcePort}`;
    const endpointB = `${destinationIp}:${destinationPort}`;
    const [firstEndpoint, secondEndpoint] = [endpointA, endpointB].sort();
    return `${transportName}|${firstEndpoint}|${secondEndpoint}`;
  };

  for (const host of Object.keys(capturedPackets["Host"])) {
    const normalizedHostKey = normalizeStatsTextValue(host);
    if (normalizedHostKey) hosts.add(normalizedHostKey);
    const packets = capturedPackets["Host"][host];
    if (!Array.isArray(packets)) continue;

    for (const pkt of packets) {
      totalPackets++;
      const pi = pkt?.["Packet Info"];
      const ei = pkt?.["Extra Info"] || {};
      if (!pi) continue;

      const streamKey = getStreamKey(pi);
      if (!streams.has(streamKey)) {
        streams.set(streamKey, { count: 0 });
      }
      streams.get(streamKey).count++;

      const protocolUpper = String(pi?.["Protocol"] || "").toUpperCase();
      if (protocolUpper === "TCP") {
        if (!tcpStreams.has(streamKey)) {
          tcpStreams.set(streamKey, []);
        }
        tcpStreams.get(streamKey).push(pkt);
      }

      const tp = normalizeStatsTextValue(pi["Protocol"]);
      if (tp) transportProtocols.add(tp);
      const packetProto = normalizeStatsTextValue(pi?.["packet.proto"] || tp);
      if (packetProto) networkProtocols.add(packetProto);

      const linkData = pi?.["Link Control"];
      if (linkData) {
        const primaryLinkProtocol = normalizeStatsTextValue(
          linkData?.["Primary WAN Protocol"],
        );
        if (primaryLinkProtocol) linkProtocols.add(primaryLinkProtocol);

        const detectedLinkProtocols = linkData?.["Detected Protocols"];
        if (Array.isArray(detectedLinkProtocols)) {
          detectedLinkProtocols.forEach((linkProtocol) => {
            const normalizedLinkProtocol = normalizeStatsTextValue(linkProtocol);
            if (normalizedLinkProtocol) linkProtocols.add(normalizedLinkProtocol);
          });
        }
      }

      const inferredDecodedProtocols = collectPacketDecodedProtocolNames(pi);
      inferredDecodedProtocols.forEach((decodedProtocol) => {
        const normalizedDecodedProtocol = normalizeStatsTextValue(decodedProtocol);
        if (normalizedDecodedProtocol) decodedProtocols.add(normalizedDecodedProtocol);
      });

      if (tp === "ARP" || tp === "RARP") {
        const arpData = pi?.[tp] || {};
        const arpOp = normalizeStatsTextValue(arpData["Operation"]);
        if (arpOp) arpOperations.add(arpOp);
      }

      if (tp === "IGMP") {
        const igmpData = pi?.["IGMP"] || {};
        const igmpType = normalizeStatsTextValue(igmpData["Type"]);
        if (igmpType) igmpMessageTypes.add(igmpType);
      }

      const srcIp = normalizeStatsTextValue(pi?.["IP"]?.["Source IP"]);
      const dstIp = normalizeStatsTextValue(pi?.["IP"]?.["Destination IP"]);
      if (srcIp) hosts.add(srcIp);
      if (dstIp) hosts.add(dstIp);

      const ef = pi?.["Ethernet Frame"];
      if (ef) {
        const srcVendor = normalizeStatsTextValue(ef["MAC Source Vendor"]);
        const dstVendor = normalizeStatsTextValue(ef["MAC Destination Vendor"]);
        if (srcVendor) macVendors.add(srcVendor);
        if (dstVendor) macVendors.add(dstVendor);
      }

      const netData = ei?.["Traits"]?.["Network Data"];
      if (netData) {
        const protoName = normalizeStatsTextValue(
          netData["Port Protocol"] ?? netData["Port Protcol"],
        );
        if (protoName && protoName !== "Unknown") protocols.add(protoName);

        const tpData = tp ? pi[tp] : null;
        if (tpData) {
          const srcPort = normalizeStatsPortValue(tpData["Source port"]);
          const dstPort = normalizeStatsPortValue(tpData["Destination port"]);
          if (srcPort !== null) ports.add(srcPort);
          if (dstPort !== null) ports.add(dstPort);
        }

        const hn = netData?.["Hostnames"]?.["Hostnames"];
        if (Array.isArray(hn)) {
          hn.forEach((h) => {
            const normalizedHostname = normalizeStatsTextValue(h);
            if (normalizedHostname) hostnames.add(normalizedHostname);
          });
        }

        for (const side of ["Source IP", "Destination IP"]) {
          const loc = netData?.[side]?.["Location"];
          const city = normalizeStatsTextValue(loc?.["City"]);
          const country = normalizeStatsTextValue(loc?.["Country"]);
          if (city && country) {
            const key = `${city}, ${country}`;
            locations.set(key, (locations.get(key) || 0) + 1);
          }
        }
      }

      const mimeType = normalizeStatsTextValue(ei?.["MIME Type"]);
      if (mimeType) mimeTypes.add(mimeType);

      const dt = ei?.["Data Types"];
      if (Array.isArray(dt)) {
        dt.forEach((d) => {
          const normalizedDataType = normalizeStatsTextValue(d, {
            stripNonPrintable: true,
          });
          if (normalizedDataType) dataTypes.add(normalizedDataType);
        });
      }

      const encData = ei?.["Traits"]?.["Server Info"]?.["Encryption Data"];
      if (!encData || encData === "N/A") {
        unencryptedCount++;
      } else {
        encryptedCount++;
      }
    }
  }

  const streamStats = Array.from(streams.values()).map((s) => s.count);
  const maxStreamLength =
    streamStats.length > 1 ? Math.max(...streamStats) : 0;
  const minStreamLength =
    streamStats.length > 1 ? Math.min(...streamStats) : 0;
  const avgStreamLength =
    streamStats.length > 1
      ? (streamStats.reduce((a, b) => a + b, 0) / streamStats.length).toFixed(2)
      : 0;
  const tcpStreamAnomalyCounts = computeTcpStreamAnomalyCounts(tcpStreams);

  return {
    protocols: [...protocols].sort(),
    networkProtocols: [...networkProtocols].sort(),
    linkProtocols: [...linkProtocols].sort(),
    transportProtocols: [...transportProtocols].sort(),
    decodedProtocols: [...decodedProtocols].sort(),
    arpOperations: [...arpOperations].sort(),
    igmpMessageTypes: [...igmpMessageTypes].sort(),
    hosts: [...hosts].sort(),
    ports: [...ports].sort((a, b) => a - b),
    macVendors: [...macVendors].filter((v) => v !== "N/A").sort(),
    mimeTypes: [...mimeTypes].sort(),
    locations: [...locations.entries()].sort((a, b) => b[1] - a[1]),
    hostnames: [...hostnames].sort(),
    dataTypes: [...dataTypes].sort(),
    encryptedCount,
    unencryptedCount,
    totalPackets,
    totalStreams: streams.size,
    maxStreamLength,
    minStreamLength,
    avgStreamLength,
    retransmissionCount: tcpStreamAnomalyCounts.retransmissionCount,
    outOfOrderCount: tcpStreamAnomalyCounts.outOfOrderCount,
    bookmarkCount,
  };
}

function makeStatsSection({ documentRef, title, items, queryBuilder, onQuery }) {
  if (!items || items.length === 0) return null;
  const normalizedItems = Array.from(
    new Set(
      items.filter((item) => {
        if (item === null || item === undefined) return false;
        if (typeof item !== "string") return true;
        return normalizeStatsTextValue(item) !== null;
      }),
    ),
  );
  if (normalizedItems.length === 0) return null;

  const section = documentRef.createElement("div");
  section.className = "stats-section";

  const heading = documentRef.createElement("div");
  heading.className = "stats-section-title";
  heading.textContent = title;
  section.appendChild(heading);

  const tagList = documentRef.createElement("div");
  tagList.className = "stats-tag-list";

  normalizedItems.forEach((item) => {
    const tag = documentRef.createElement("span");
    tag.className = "stats-tag";
    tag.textContent = item;
    tag.title = "Click to filter packets by this value";
    if (queryBuilder) {
      tag.addEventListener("click", () => {
        const query = queryBuilder(item);
        if (query && typeof onQuery === "function") {
          onQuery(query);
        }
      });
    }
    tagList.appendChild(tag);
  });

  section.appendChild(tagList);
  return section;
}

function createStatsPanel(options) {
  const {
    documentRef,
    statusUpdate,
    writeLogEntry,
    setActiveMainTab,
    mainTabStats,
    getJsonCapture,
    getCapturedPackets,
    filterInputEl,
    syncFilterHighlight,
    runFilterQuery,
    getFilteredPackets,
    syncTargetHostFromPackets,
    setPacketsForHost,
    getBookmarkCount,
  } = options;

  async function applyStatsQuery(query) {
    filterInputEl.value = query;
    syncFilterHighlight();
    writeLogEntry(`[${threadName}] Stats tag clicked query="${query}"`);
    await runFilterQuery(query);
    const filteredPackets = getFilteredPackets();
    if (Array.isArray(filteredPackets) && filteredPackets.length > 0) {
      if (typeof syncTargetHostFromPackets === "function") {
        syncTargetHostFromPackets(filteredPackets);
      }
      setPacketsForHost(filteredPackets);
    }
  }

  function showStats() {
    setActiveMainTab(mainTabStats);
    if (getJsonCapture() === "") {
      statusUpdate("Status: No JSON file loaded, please upload a file first");
      return;
    }
    statusUpdate("Status: Displaying capture statistics");
    writeLogEntry(`[${threadName}] User opened capture stats view`);

    documentRef.getElementById("packetInfoPane").style.display = "none";
    documentRef.getElementById("packetPayloadPane").style.display = "none";
    documentRef.getElementById("prev-btn").style.display = "none";
    documentRef.getElementById("next-btn").style.display = "none";
    documentRef.getElementById("summary_box").style.display = "none";
    documentRef.getElementById("list_box").style.display = "none";
    documentRef.getElementById("notes_box").style.display = "none";
    documentRef.getElementById("data_tools_box").style.display = "none";
    documentRef.getElementById("crypt_box").style.display = "none";
    documentRef.getElementById("keystore_box").style.display = "none";
    documentRef.getElementById("stats_box").style.display = "block";
    documentRef.getElementById("rightside").style.display = "none";

    const content = documentRef.getElementById("stats_content");
    content.replaceChildren();

    const stats = buildCaptureStats(
      getCapturedPackets(),
      typeof getBookmarkCount === "function" ? getBookmarkCount() : 0,
    );
    if (!stats) {
      content.textContent = "No packet data available.";
      return;
    }

    const overview = documentRef.createElement("div");
    overview.className = "stats-section";
    const ovHead = documentRef.createElement("div");
    ovHead.className = "stats-section-title";
    ovHead.textContent = "Capture Overview";
    overview.appendChild(ovHead);
    [
      `Total Packets: ${stats.totalPackets}`,
      `Bookmarked Packets: ${stats.bookmarkCount}`,
      `Total Streams: ${stats.totalStreams}`,
      `Longest Stream: ${stats.maxStreamLength} packets`,
      `Shortest Stream: ${stats.minStreamLength} packets`,
      `Average Stream Length: ${stats.avgStreamLength} packets`,
      `Unique Hosts Targeted: ${stats.hosts.length}`,
      `Encrypted Packets: ${stats.encryptedCount}`,
      `Unencrypted Packets: ${stats.unencryptedCount}`,
      `TCP Retransmissions: ${stats.retransmissionCount}`,
      `TCP Out-of-Order: ${stats.outOfOrderCount}`,
      `Unique Protocols: ${stats.protocols.length}`,
      `Unique Locations: ${stats.locations.length}`,
    ].forEach((line) => {
      const kv = documentRef.createElement("div");
      kv.className = "stats-kv";
      kv.textContent = line;
      overview.appendChild(kv);
    });
    content.appendChild(overview);
    // make the application protocols uppercase to be congruent with the rest of the protos
    stats.protocols = stats.protocols.map((proto) => proto.toUpperCase());
    const protoSec = makeStatsSection({
      documentRef,
      title: "Application Protocols",
      items: stats.protocols,
      queryBuilder: (v) => `app.proto: ${v.toLowerCase()}`,
      onQuery: applyStatsQuery,
    });
    if (protoSec) content.appendChild(protoSec);

    const networkProtoSec = makeStatsSection({
      documentRef,
      title: "Network Protocols",
      items: stats.networkProtocols,
      queryBuilder: (v) => `wire.proto: ${v.toLowerCase()}`,
      onQuery: applyStatsQuery,
    });
    if (networkProtoSec) content.appendChild(networkProtoSec);

    const tpSec = makeStatsSection({
      documentRef,
      title: "Link Protocols",
      items: stats.linkProtocols,
      queryBuilder: (v) => `decoded.proto: ${v.toLowerCase()}`,
      onQuery: applyStatsQuery,
    });
    if (tpSec) content.appendChild(tpSec);

    const decodedProtoSec = makeStatsSection({
      documentRef,
      title: "Decoded Protocols",
      items: stats.decodedProtocols,
      queryBuilder: (v) => `decoded.proto: ${v.toLowerCase()}`,
      onQuery: applyStatsQuery,
    });
    if (decodedProtoSec) content.appendChild(decodedProtoSec);

    const arpOpSec = makeStatsSection({
      documentRef,
      title: "ARP/RARP Operations",
      items: stats.arpOperations,
      queryBuilder: (v) => `arp.op: ${v.toLowerCase()}`,
      onQuery: applyStatsQuery,
    });
    if (arpOpSec) content.appendChild(arpOpSec);

    const igmpTypeSec = makeStatsSection({
      documentRef,
      title: "IGMP Message Types",
      items: stats.igmpMessageTypes,
      queryBuilder: (v) => `igmp.type: ${v.toLowerCase()}`,
      onQuery: applyStatsQuery,
    });
    if (igmpTypeSec) content.appendChild(igmpTypeSec);

    const hostSec = makeStatsSection({
      documentRef,
      title: "All Hosts Addressed",
      items: stats.hosts,
      queryBuilder: (v) => `ip.src.addr: ${v} || ip.dst.addr: ${v}`,
      onQuery: applyStatsQuery,
    });
    if (hostSec) content.appendChild(hostSec);

    // make sure the ips here are not listed in stats.hosts, if they are, skip them
    const hostIpsSet = new Set(stats.hosts);
    const filteredHostnames = stats.hostnames.filter((hn) => {
      const hnAsIp = hn.replace(/^\[|\]$/g, ""); // Remove brackets from IPv6 addresses
      return !hostIpsSet.has(hnAsIp);
    });
    // also filter out any hostnames that have a "," comma in them, as they are likely
    // malformed and not useful for filtering
    const fullyFilteredHostnames = filteredHostnames.filter((hn) => !hn.includes(","));
    if (fullyFilteredHostnames.length > 0) {
      const filteredHnSec = makeStatsSection({
        documentRef,
        title: "Hostnames (DNS)",
        items: fullyFilteredHostnames,
        queryBuilder: (v) => `dns.qname: ${v}`,
        onQuery: applyStatsQuery,
      });
      if (filteredHnSec) content.appendChild(filteredHnSec);
    }
    //if (hnSec) content.appendChild(hnSec);

    if (stats.locations.length > 0) {
      const locItems = stats.locations.map(([place, count]) => `${place} (${count})`);
      const locSec = makeStatsSection({
        documentRef,
        title: "Physical Locations",
        items: locItems,
        queryBuilder: (v) => {
          // we should search by the city, which comes before a comma
          const city = v.split(" (")[0].split(",")[0].trim();
          return `loc.src.city: ${city} || loc.dst.city: ${city}`;
        },
        onQuery: applyStatsQuery,
      });
      if (locSec) content.appendChild(locSec);
    }

    const portSec = makeStatsSection({
      documentRef,
      title: "Ports Seen",
      items: stats.ports.map(String),
      queryBuilder: (v) => `(tcp.src.port: ${v} || tcp.dst.port: ${v}) || (udp.src.port: ${v} || udp.dst.port: ${v})`,
      onQuery: applyStatsQuery,
    });
    if (portSec) content.appendChild(portSec);

    const macSec = makeStatsSection({
      documentRef,
      title: "MAC Vendors",
      items: stats.macVendors,
      queryBuilder: (v) => `eth.src.vendor: ${v}`,
      onQuery: applyStatsQuery,
    });
    if (macSec) content.appendChild(macSec);

    const mimeSec = makeStatsSection({
      documentRef,
      title: "MIME Types",
      items: stats.mimeTypes,
      queryBuilder: (v) => `mime.type: ${v}`,
      onQuery: applyStatsQuery,
    });
    if (mimeSec) content.appendChild(mimeSec);

    const dtSec = makeStatsSection({
      documentRef,
      title: "Data Types",
      items: stats.dataTypes,
    });
    if (dtSec) content.appendChild(dtSec);
  }

  return {
    showStats,
  };
}

module.exports = {
  id: "stats",
  createStatsPanel,
};
