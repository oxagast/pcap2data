const threadName = "Stats";


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

function buildCaptureStats(capturedPackets) {
  const protocols = new Set();
  const transportProtocols = new Set();
  const decodedProtocols = new Set();
  const hosts = new Set();
  const ports = new Set();
  const macVendors = new Set();
  const mimeTypes = new Set();
  const locations = new Map();
  const hostnames = new Set();
  const dataTypes = new Set();
  const streams = new Map();
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
      const ei = pkt?.["Extra Info"];
      if (!pi || !ei) continue;

      const streamKey = getStreamKey(pi);
      if (!streams.has(streamKey)) {
        streams.set(streamKey, { count: 0 });
      }
      streams.get(streamKey).count++;

      const tp = normalizeStatsTextValue(pi["Protocol"]);
      if (tp) transportProtocols.add(tp);

      const packetDecodedProtocols = pi?.["Decoded Protocols"];
      if (Array.isArray(packetDecodedProtocols)) {
        packetDecodedProtocols.forEach((decodedProtocol) => {
          const normalizedDecodedProtocol = normalizeStatsTextValue(decodedProtocol);
          if (normalizedDecodedProtocol) decodedProtocols.add(normalizedDecodedProtocol);
        });
      }

      const linkControlDecodedProtocols = pi?.["Link Control"]?.["Detected Protocols"];
      if (Array.isArray(linkControlDecodedProtocols)) {
        linkControlDecodedProtocols.forEach((decodedProtocol) => {
          const normalizedDecodedProtocol = normalizeStatsTextValue(decodedProtocol);
          if (normalizedDecodedProtocol) decodedProtocols.add(normalizedDecodedProtocol);
        });
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
    streamStats.length > 0 ? Math.max(...streamStats) : 0;
  const minStreamLength =
    streamStats.length > 0 ? Math.min(...streamStats) : 0;
  const avgStreamLength =
    streamStats.length > 0
      ? (streamStats.reduce((a, b) => a + b, 0) / streamStats.length).toFixed(2)
      : 0;

  return {
    protocols: [...protocols].sort(),
    transportProtocols: [...transportProtocols].sort(),
    decodedProtocols: [...decodedProtocols].sort(),
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

    const stats = buildCaptureStats(getCapturedPackets());
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
      `Total Streams: ${stats.totalStreams}`,
      `Longest Stream: ${stats.maxStreamLength} packets`,
      `Shortest Stream: ${stats.minStreamLength} packets`,
      `Average Stream Length: ${stats.avgStreamLength} packets`,
      `Unique Hosts Targeted: ${stats.hosts.length}`,
      `Encrypted Packets: ${stats.encryptedCount}`,
      `Unencrypted Packets: ${stats.unencryptedCount}`,
      `Unique Protocols: ${stats.protocols.length}`,
      `Unique Locations: ${stats.locations.length}`,
    ].forEach((line) => {
      const kv = documentRef.createElement("div");
      kv.className = "stats-kv";
      kv.textContent = line;
      overview.appendChild(kv);
    });
    content.appendChild(overview);

    const protoSec = makeStatsSection({
      documentRef,
      title: "Application Protocols",
      items: stats.protocols,
      queryBuilder: (v) => `app.proto: ${v.toLowerCase()}`,
      onQuery: applyStatsQuery,
    });
    if (protoSec) content.appendChild(protoSec);

    const tpSec = makeStatsSection({
      documentRef,
      title: "Transport Protocols",
      items: stats.transportProtocols,
      queryBuilder: (v) => `wire.proto: ${v.toLowerCase()}`,
      onQuery: applyStatsQuery,
    });
    if (tpSec) content.appendChild(tpSec);

    const decodedProtoSec = makeStatsSection({
      documentRef,
      title: "Decoded Protocols",
      items: stats.decodedProtocols,
      queryBuilder: (v) => `decoded-proto: ${v.toLowerCase()}`,
      onQuery: applyStatsQuery,
    });
    if (decodedProtoSec) content.appendChild(decodedProtoSec);

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
