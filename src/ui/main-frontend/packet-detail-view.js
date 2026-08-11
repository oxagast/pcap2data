// Packet detail rendering — the Data workspace's per-packet info
// panel, the hex/ASCII grid, and the printable-character checks.
//
// Extracted from ``src/ui/main-frontend.js`` on the
// ``refactor/main-frontend-dead-code`` branch as part of the renderer
// refactor. The factory owns all the helpers that compose the
// "Data" tab's packet-detail UI: the small pure-utility functions
// (``isPrintable``, ``hexToAscii``, ``truncate``,
// ``clearGridHighlights``, ``popHexGrid``) plus the heavyweight
// ``infoPanel`` renderer.
//
// ``infoPanel`` reads and writes a small bag of session-level state
// (current packet index, filtered packet list, stream protocol, the
// live ``capturedPackets`` table) and calls a number of orchestrator
// helpers (status updates, error reporting, packet counters, the
// stats heatmap opener) and decoder-table renderers. All of those
// are passed in as factory options so the module can stay self
// contained.

const {
    createTable,
    renderDnsTable,
    renderIcmpTable,
    renderIgmpTable,
    renderArpTable,
    renderLinkControlTable,
    renderSnmpTable,
    renderDhcpTable,
    renderNtpTable,
    renderSipTable,
    renderHttpTable,
    renderFtpTable,
    renderSmtpTable,
    renderPop3Table,
    renderImapTable,
    renderTelnetTable,
    renderIrcTable,
    renderMtpTable,
    renderLdapTable,
    renderMysqlTable,
    renderPostgresqlTable,
    renderXmppTable,
    renderSmbTable,
    renderSmppTable,
    renderSoulseekTable,
    renderBitTorrentTable,
    renderMqttTable,
    renderRtspTable,
    renderTftpTable,
    renderBgpTable,
    renderHttp2Table,
    renderNntpTable,
    renderRadiusTable,
    renderWebSocketTable,
    renderNfsTable,
    renderKerberosTable,
    renderSshTable,
    renderSctpTable,
} = require("../decoders/main");

function createPacketDetailViewHelpers({
    state,
    hostFilterEl,
    statusUpdate,
    doError,
    updateCurrentPacketCounters,
    showStatsHeatmapLocation,
    escapeHtml,
    formatNetworkEndpointDisplay,
    getPacketKey,
    getPacketInfoPayloadLength,
    getTcpStreamArrivalStatusByPacketKey,
    buildBidirectionalStreamKey,
    sortPacketsByOwnStreamOrder,
    // ``warmStreamPacketHydrationCache`` is declared further down in
    // the orchestrator (it comes out of ``createStreamHelpers`` at
    // line ~5896). Because the orchestrator's factory call runs at
    // line ~4770, well before that declaration, we accept a thunk
    // that resolves the binding lazily at call time — by which point
    // the orchestrator has finished initializing. If the thunk is
    // ``null`` (e.g., the factory is smoke-tested in isolation), the
    // ``infoPanel`` path that uses this helper becomes a no-op.
    resolveWarmStreamPacketHydrationCache,
}) {
    // True when the given character code is printable ASCII (space
    // through ``~``). Used to decide whether a decoded byte is
    // safe to show in the ASCII column of the hex grid.
    function isPrintable(charCode) {
        return charCode >= 32 && charCode <= 126;
    }

    // Decodes a hex string to its ASCII representation. Non-printable
    // characters survive as control characters — the caller is
    // expected to gate on ``isPrintable`` when rendering.
    function hexToAscii(hex) {
        let decodedAscii = "";
        for (let i = 0; i < hex.length; i += 2) {
            decodedAscii += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
        }
        return decodedAscii;
    }

    // Returns ``str`` truncated to ``maxLength`` characters. Empty
    // inputs and inputs shorter than the cap pass through untouched.
    function truncate(str, maxLength) {
        if (str.length <= maxLength) return str;
        return str.slice(0, maxLength);
    }

    // Removes the "highlight" class from every ``.griditem`` element
    // in the hex grid. Called when the mouse leaves a cell so the
    // printable run stops being highlighted.
    function clearGridHighlights() {
        document
            .querySelectorAll(".griditem")
            .forEach((el) => el.classList.remove("highlight"));
    }

    // Populates the hex grid display (``#hexg``) and the ASCII
    // fade-in box (``#payloadascii``) for the given hex payload.
    // Each byte gets a ``.griditem`` div and a mouseenter handler
    // that shows the decoded ASCII run for that position.
    function popHexGrid(hex) {
        const safeHex = typeof hex === "string" ? hex : "";
        const payloadAsciiBox = document.getElementById("payloadascii");
        const hexGridContainer = document.getElementById("hexg");
        const hexOffsetDisplay = document.getElementById("asciiOffset");
        const asciiTextBox = document.getElementById("asciiText");
        if (payloadAsciiBox) {
            payloadAsciiBox.classList.remove("visible");
        }
        if (hexGridContainer) {
            hexGridContainer.textContent = "";
        }
        if (hexOffsetDisplay) {
            hexOffsetDisplay.textContent = "";
        }
        if (asciiTextBox) {
            asciiTextBox.textContent = "";
        }
        window.currentPrintableSequence = "";
        if (!safeHex) {
            return;
        }

        const decodedAscii = hexToAscii(safeHex);
        const hexPairs = safeHex.toUpperCase().match(/.{1,2}/g) || [];
        hexPairs.forEach((hexPair, byteIndex) => {
            const item = document.createElement("div");
            item.classList.add("griditem");
            item.textContent = hexPair;
            item.dataset.byteIndex = String(byteIndex);
            hexGridContainer.appendChild(item);
        });
        function getPrintableSequence(startIndex) {
            let result = "";
            for (let i = startIndex; i < decodedAscii.length; i++) {
                if (!isPrintable(decodedAscii.charCodeAt(i))) break;
                result += String.fromCharCode(decodedAscii.charCodeAt(i));
            }
            return result;
        }
        // Attach event listeners to each grid item
        document.querySelectorAll(".griditem").forEach((item, idx) => {
            item.addEventListener("mouseenter", (e) => {
                // box fade in
                payloadAsciiBox.style.top = e.clientY + 18 + "px";
                payloadAsciiBox.style.left = e.clientX + 18 + "px";
                payloadAsciiBox.classList.add("visible");
                asciiTextBox.innerHTML = "";
                const printable = getPrintableSequence(idx);
                window.currentPrintableSequence = printable;
                // adds only consecutive printable characters to the
                // decodedAscii box
                asciiTextBox.textContent += truncate(printable, 32);
                for (let i = 0; i < truncate(printable, 32).length; i++) {
                    const highlightedCell = document.querySelectorAll(".griditem")[idx + i];
                    highlightedCell.classList.add("highlight");
                }
                const hexLen = parseInt(truncate(printable, 32).length, 10)
                    .toString(16)
                    .padStart(2, "0")
                    .toUpperCase();
                const hexOffset = idx.toString(16).padStart(4, "0").toUpperCase();
                if (printable.length == 0) {
                    asciiTextBox.textContent = "0x" + item.textContent;
                }
                hexOffsetDisplay.textContent = "0x" + hexOffset + ":" + hexLen;
            });
        });
        // this fades the box back out and calls the grid clear func
        document.querySelectorAll(".griditem").forEach((item) => {
            item.addEventListener("mouseleave", () => {
                payloadAsciiBox.classList.remove("visible");
                clearGridHighlights();
            });
        });
    }

    // Renders the per-packet info panel (the "Data" workspace's main
    // surface). Pops the IP, protocol, and checksum tables; iterates
    // the captured-packet host map to find the TCP/UDP stream the
    // packet belongs to and warms the stream-packet hydration cache;
    // and opens the stats heatmap at the packet's source/destination
    // coordinates when the user clicks a location table cell.
    //
    // The factory accepts ``state`` (``index``, ``filteredPackets``,
    // ``streamProtocol``, ``capturedPackets``) and a handful of
    // orchestrator helpers so the function body can run without
    // closure access to the orchestrator. The body is unchanged
    // from the original orchestrator function other than the
    // ``state.`` prefix on module-level state reads/writes.
    function infoPanel(pk) {
        const infoPaneEl = document.getElementById("packetInfoPane");
        document.getElementById("rightside").style.display = "block";
        document.getElementById("leftside").style.display = "block";
        infoPaneEl.style.display = "block";
        if (!Array.isArray(pk) || pk.length === 0) {
            statusUpdate("Status: No packet information found for this host");
            doError("No packet information found for this host!");
            return;
        }
        const p = pk[state.index];
        if (!p || !p["packet.info"]) {
            statusUpdate("Status: Packet data is unavailable for this entry");
            doError("Packet data is unavailable for this entry!");
            return;
        }
        updateCurrentPacketCounters(pk, {
            isFilteredView: Array.isArray(state.filteredPackets) && pk === state.filteredPackets,
        });
        let packetInfoData = p["packet.info"] || {};
        let extraInfoData = p["extra.info"] || {};
        const ipData = packetInfoData["IP"] || {};
        const traitsData = extraInfoData["Traits"] || {};
        const networkData = traitsData["Network Data"] || {};
        const serverInfo = traitsData["Server Info"] || {};
        const srcLocation = networkData?.["ip.src"]?.["Location"] || networkData?.["Source IP"]?.["Location"] || {};
        const dstLocation = networkData?.["ip.dst"]?.["Location"] || networkData?.["Destination IP"]?.["Location"] || {};
        // MAC address + vendor + network class for the source and
        // destination side panels in the "Network Information" box.
        // The factory was previously surfacing location fields
        // (City/Country/Lat/Long) in these side panels, but the
        // HTML's "Network Information" header implies network-layer
        // data (MAC/vendor/class) and the location belongs in the
        // "Location" sidebar (sideloctable). Restore the original
        // orchestrator's data so the panels read correctly.
        const etherFrame =
            typeof packetInfoData["Ethernet Frame"] === "object" &&
                packetInfoData["Ethernet Frame"] !== null
                ? packetInfoData["Ethernet Frame"]
                : {};
        const srcMac = etherFrame["ether.src.mac.addr"] ?? etherFrame["MAC Source"] ?? "N/A";
        const dstMac = etherFrame["ether.dst.mac.addr"] ?? etherFrame["MAC Destination"] ?? "N/A";
        const srcMacVendor = etherFrame["ether.src.mac.vendor"] ?? etherFrame["MAC Source Vendor"] ?? "N/A";
        const dstMacVendor = etherFrame["ether.dst.mac.vendor"] ?? etherFrame["MAC Destination Vendor"] ?? "N/A";
        const srcNetClass = networkData?.["ip.src"]?.["Class"] ?? networkData?.["Source IP"]?.["Class"] ?? "N/A";
        const dstNetClass = networkData?.["ip.dst"]?.["Class"] ?? networkData?.["Destination IP"]?.["Class"] ?? "N/A";
        const parseLocationCoordinate = (value, min, max) => {
            const numericValue = Number(value);
            if (!Number.isFinite(numericValue)) return null;
            if (numericValue < min || numericValue > max) return null;
            return numericValue;
        };
        const bindLocationTableToHeatmap = (locationData, locationSideLabel) => {
            const latitude = parseLocationCoordinate(locationData?.["Latitude"], -90, 90);
            const longitude = parseLocationCoordinate(locationData?.["Longitude"], -180, 180);
            if (latitude === null || longitude === null) return;

            const locationContainer = document.getElementById("sideloctable");
            const locationTable = locationContainer?.querySelector("table:last-of-type");
            if (!locationTable) return;

            const city = String(locationData?.["City"] || "").trim();
            const country = String(locationData?.["Country"] || "").trim();
            const locationLabel = [city, country].filter(Boolean).join(", ") || locationSideLabel;

            const openHeatmapAtLocation = () => {
                showStatsHeatmapLocation({
                    latitude,
                    longitude,
                    label: locationLabel,
                });
            };

            locationTable.addEventListener("click", openHeatmapAtLocation);
            locationTable.style.cursor = "pointer";
            locationTable.title = `Open heatmap at ${locationLabel}`;
        };

        const layer = packetInfoData["Protocols"]?.["Protocol Tree"] || {};
        const protocol = layer?.["ip.proto"]?.["ip.proto"] || layer?.["sctp.proto"]?.["sctp.proto"] || "Unknown";
        const transport = layer?.["tcp.proto"]?.["tcp.proto"] || layer?.["udp.proto"]?.["udp.proto"] || layer?.["sctp.proto"]?.["sctp.proto"] || "Unknown";
        const appProto = layer?.["http.proto"]?.["http.proto"] || layer?.["tls.proto"]?.["tls.proto"] || layer?.["dns.proto"]?.["dns.proto"] || layer?.["ssh.proto"]?.["ssh.proto"] || "Unknown";
        const ipSrc = ipData?.["ip.src.addr"] || ipData?.["Source IP"] || "Unknown";
        const ipDst = ipData?.["ip.dst.addr"] || ipData?.["Destination IP"] || "Unknown";
        const srcDisplay = formatNetworkEndpointDisplay(
            ipData?.["ip.src"] || ipSrc,
            ipData?.["tcp.srcport"] || ipData?.["udp.srcport"] || ipData?.["sctp.srcport"] || "",
        );
        const dstDisplay = formatNetworkEndpointDisplay(
            ipData?.["ip.dst"] || ipDst,
            ipData?.["tcp.dstport"] || ipData?.["udp.dstport"] || ipData?.["sctp.dstport"] || "",
        );

        const ipChecksum = ipData?.["ip.checksum"] || "Unknown";
        const transportChecksum = layer?.["tcp.proto"]?.["tcp.checksum"] || layer?.["udp.proto"]?.["udp.checksum"] || layer?.["sctp.proto"]?.["sctp.checksum"] || "Unknown";
        const tcpFlags = layer?.["tcp.proto"]?.["tcp.flags"] || "N/A";
        const ipLayerLen = ipData?.["ip.len"] || "Unknown";
        const transportLayerLen = layer?.["tcp.proto"]?.["tcp.len"] || layer?.["udp.proto"]?.["udp.length"] || layer?.["sctp.proto"]?.["sctp.chunk_length"] || "Unknown";
        const wireLen = packetInfoData?.["frame.len"] || packetInfoData?.["Frame Length"] || "Unknown";
        const payloadLen = getPacketInfoPayloadLength(packetInfoData);

        const transportData = { ...layer, ...traitsData, "Server Info": serverInfo };
        const srcIp = ipData["ip.src.addr"] ?? ipData["Source IP"] ?? hostFilterEl.value ?? "Unknown";
        const dstIp = ipData["ip.dst.addr"] ?? ipData["Destination IP"] ?? hostFilterEl.value ?? "Unknown";

        const currentStreamKey = buildBidirectionalStreamKey(packetInfoData);
        const streamPacketRefs = [];
        const streamPackets = [];
        if (state.capturedPackets && state.capturedPackets["host"]) {
            for (const host of Object.keys(state.capturedPackets["host"])) {
                const hostPackets = state.capturedPackets["host"][host];
                if (!Array.isArray(hostPackets)) continue;
                for (let packetIndex = 0; packetIndex < hostPackets.length; packetIndex += 1) {
                    const pkt = hostPackets[packetIndex];
                    const pi = pkt?.["packet.info"];
                    if (pi && buildBidirectionalStreamKey(pi) === currentStreamKey) {
                        streamPacketRefs.push({
                            packet: pkt,
                            host,
                            packetIndex,
                        });
                        streamPackets.push(pkt);
                        // check and see if they all have the same application protocol,
                        // if not, we will use the first packet's application protocol
                        //  for the stream, for consistency
                        const pktProtoName =
                            pi?.["extra.info"]?.["Traits"]?.["Network Data"]?.["tcp.proto"] ||
                            pi?.["extra.info"]?.["Traits"]?.["Network Data"]?.["sctp.proto"] ||
                            pi?.["extra.info"]?.["Traits"]?.["Network Data"]?.["udp.proto"] ||
                            "Unknown";
                        if (streamPackets.length === 1) {
                            // first packet in the stream, set the stream protocol
                            state.streamProtocol = pktProtoName;
                        } else if (pktProtoName !== state.streamProtocol) {
                            // different protocol found, log a warning and continue using the first packet's protocol
                            console.warn(`Inconsistent application protocol in stream: expected ${state.streamProtocol}, but found ${pktProtoName} `);
                        }
                    }
                }
            }
        }

        const warmStreamPacketHydrationCache =
            typeof resolveWarmStreamPacketHydrationCache === "function"
                ? resolveWarmStreamPacketHydrationCache()
                : null;
        if (typeof warmStreamPacketHydrationCache === "function") {
            void warmStreamPacketHydrationCache(currentStreamKey, streamPacketRefs);
        }

        const sortedStreamPackets = sortPacketsByOwnStreamOrder(streamPackets);
        const tcpArrivalStatusByPacketKey = getTcpStreamArrivalStatusByPacketKey(
            sortedStreamPackets,
        );
        const currentTcpArrivalStatus = tcpArrivalStatusByPacketKey.get(getPacketKey(p));
        const tcpStreamStatusText =
            protocol === "TCP"
                ? currentTcpArrivalStatus?.label || "In-order TCP segment"
                : "N/A";

        const checksumData = [
            { name: "IP Checksum", value: ipChecksum },
            { name: protocol + " Checksum", value: transportChecksum },
            { name: "Flags", value: tcpFlags },
            { name: "TCP Stream Status", value: tcpStreamStatusText },
            { name: "IP Length", value: ipLayerLen },
            { name: protocol + " Length", value: transportLayerLen },
            { name: "Wire Length", value: wireLen },
            { name: "Payload Length", value: payloadLen },
        ];
        const checksumHeaders = ["Protocol data", "Details"];
        // ``createTable`` uses ``appendChild`` under the hood, so
        // every call to ``infoPanel`` would otherwise stack a fresh
        // checksum table on top of the previous packet's. Clear
        // ``sidedatatable`` first to keep it single-render, matching
        // the original orchestrator behaviour.
        const sidedataTableEl = document.getElementById("sidedatatable");
        if (sidedataTableEl) sidedataTableEl.textContent = "";
        createTable(checksumData, checksumHeaders, "sidedatatable");

        // DNS info table (shown for UDP/DNS packets)
        renderDnsTable(transportData);

        // ICMP info table (shown for ICMP packets)
        renderIcmpTable(protocol, transportData);

        // IGMP info table (shown for IGMP packets)
        renderIgmpTable(protocol, transportData);

        // ARP/RARP info table (shown for ARP and RARP packets)
        renderArpTable(protocol, transportData);

        // WAN/link control info table (shown when ATM/PPP/Frame Relay style link layers are present)
        renderLinkControlTable(packetInfoData);

        // SNMP info table (shown for SNMP packets on port 161/162)
        renderSnmpTable(transportData);

        // DHCP info table (shown for DHCP packets on port 67/68)
        renderDhcpTable(transportData);

        // NTP info table (shown for NTP packets on port 123)
        renderNtpTable(transportData);

        // SIP info table (shown for SIP packets on port 5060/5061)
        renderSipTable(transportData);

        // HTTP info table (shown for HTTP request/response packets)
        renderHttpTable(transportData);

        // HTTP/2 info table (shown for HTTP/2 frames on any TCP port)
        renderHttp2Table(transportData);

        // FTP info table (shown for FTP packets on port 20/21)
        renderFtpTable(transportData);

        // SMTP info table (shown for SMTP packets on port 25/587/465)
        renderSmtpTable(transportData);

        // POP3 info table (shown for POP3 packets on port 110/995)
        renderPop3Table(transportData);

        // IMAP info table (shown for IMAP packets on port 143/993)
        renderImapTable(transportData);

        // Telnet info table (shown for Telnet packets on port 23)
        renderTelnetTable(transportData);

        // IRC info table (shown for IRC packets)
        renderIrcTable(transportData);

        // MTP info table (shown for MTP messages)
        renderMtpTable(transportData);

        // LDAP info table (shown for LDAP packets)
        renderLdapTable(transportData);

        // MySQL info table (shown for MySQL packets)
        renderMysqlTable(transportData);

        // PostgreSQL info table (shown for PostgreSQL packets)
        renderPostgresqlTable(transportData);

        // XMPP info table (shown for XMPP/Jabber packets)
        renderXmppTable(transportData);

        // SMB info table (shown for SMB/CIFS packets)
        renderSmbTable(transportData);

        // SMPP info table (shown for SMPP packets)
        renderSmppTable(transportData);

        // Soulseek info table (shown for Soulseek packets)
        renderSoulseekTable(transportData);

        // BitTorrent info table (shown for BitTorrent peer wire packets)
        renderBitTorrentTable(transportData);

        // MQTT info table (shown for MQTT packets)
        renderMqttTable(transportData);

        // RTSP info table (shown for RTSP packets)
        renderRtspTable(transportData);

        // TFTP info table (shown for TFTP packets)
        renderTftpTable(transportData);

        // BGP info table (shown for BGP packets)
        renderBgpTable(transportData);

        // NNTP info table (shown for NNTP packets)
        renderNntpTable(transportData);

        // RADIUS info table (shown for RADIUS packets)
        renderRadiusTable(transportData);

        // WebSocket info table (shown for WebSocket frames)
        renderWebSocketTable(transportData);

        // NFS info table (shown for NFS packets)
        renderNfsTable(transportData);

        // Kerberos info table (shown for Kerberos packets)
        renderKerberosTable(transportData);

        // SSH info table (shown for SSH packets)
        renderSshTable(transportData);

        // SCTP info table (shown for SCTP packets)
        renderSctpTable(transportData);

        // IP-level address & length summary
        const ipTableData = [
            { name: "Source IP", value: srcDisplay },
            { name: "Destination IP", value: dstDisplay },
            { name: "IP Header Length", value: ipData?.["ip.hdr_len"] || "Unknown" },
            { name: "IP Total Length", value: ipData?.["ip.len"] || "Unknown" },
            { name: "IP Time to Live", value: ipData?.["ip.ttl"] || "Unknown" },
            { name: "IP Version", value: ipData?.["ip.version"] || "Unknown" },
            { name: "Source Port", value: layer?.["tcp.proto"]?.["tcp.srcport"] || layer?.["udp.proto"]?.["udp.srcport"] || layer?.["sctp.proto"]?.["sctp.srcport"] || "N/A" },
            { name: "Destination Port", value: layer?.["tcp.proto"]?.["tcp.dstport"] || layer?.["udp.proto"]?.["udp.dstport"] || layer?.["sctp.proto"]?.["sctp.dstport"] || "N/A" },
            { name: "Sequence Number", value: layer?.["tcp.proto"]?.["tcp.seq"] || "N/A" },
            { name: "Acknowledgment Number", value: layer?.["tcp.proto"]?.["tcp.ack"] || "N/A" },
            { name: "Window Size", value: layer?.["tcp.proto"]?.["tcp.window_size_value"] || "N/A" },
            { name: "Urgent Pointer", value: layer?.["tcp.proto"]?.["tcp.urgent_pointer"] || "N/A" },
        ];
        const ipTableHeaders = ["IP layer data", "Details"];
        // The HTML exposes ``protoInfoSrc`` and ``protoInfoDest``
        // as the real container divs for source/destination IP
        // side panels. ``protoInfo`` itself is the parent wrapper
        // div — writing a table into it would interleave the new
        // table with the child containers. The IP summary is
        // surfaced via the protoInfoSrc/protoInfoDest tables
        // below; no need to write to ``protoInfo`` directly.
        // (The previous factory version wrote here, which produced
        // visibly duplicated IP-layer rows that stacked on every
        // prev/next click — see packet_detail_view_accumulation.md.)

        // Source/destination IP side panels (rendered into
        // ``protoInfoSrc`` / ``protoInfoDest`` which live inside the
        // "Network Information" box in the HTML). These show
        // network-layer details: IP:Port, MAC, MAC vendor, and
        // network class. Location details are rendered separately
        // into ``sideloctable`` below.
        const srcIpPort = formatNetworkEndpointDisplay(
            ipData?.["ip.src.addr"] ?? ipData?.["Source IP"] ?? hostFilterEl.value ?? "Unknown",
            transportData["tcp.src.port"] ?? transportData["udp.src.port"] ?? transportData["sctp.src.port"] ?? transportData["Source port"] ?? "?",
        );
        const dstIpPort = formatNetworkEndpointDisplay(
            ipData?.["ip.dst.addr"] ?? ipData?.["Destination IP"] ?? hostFilterEl.value ?? "Unknown",
            transportData["tcp.dst.port"] ?? transportData["udp.dst.port"] ?? transportData["sctp.dst.port"] ?? transportData["Destination port"] ?? "?",
        );
        const ipTableHeadersSide = ["Packet", "Data"];
        const srcIpData = [
            { name: "IP:Port", value: srcIpPort },
            { name: "MAC", value: srcMac },
            { name: "MAC Vendor", value: srcMacVendor },
            { name: "Network Class", value: srcNetClass },
        ];
        // ``createTable`` appends rather than replacing, so each
        // ``infoPanel`` invocation must reset the destination before
        // appending the new table — otherwise every prev/next click
        // stacks a fresh source-IP table on top of the previous
        // one. The original orchestrator wrote a "Source" placeholder
        // here, which clears the container while preserving the
        // label that shows when the side panel is empty.
        document.getElementById("protoInfoSrc").textContent = "Source";
        createTable(srcIpData, ipTableHeadersSide, "protoInfoSrc");

        const dstIpData = [
            { name: "IP:Port", value: dstIpPort },
            { name: "MAC", value: dstMac },
            { name: "MAC Vendor", value: dstMacVendor },
            { name: "Network Class", value: dstNetClass },
        ];
        document.getElementById("protoInfoDest").textContent = "Destination";
        createTable(dstIpData, ipTableHeadersSide, "protoInfoDest");

        // Local network table (CIDR derivation from the source/destination IPs)
        const localnetData = [
            { name: "Source", value: srcIp },
            { name: "Destination", value: dstIp },
            { name: "Application Protocol", value: appProto },
            { name: "Transport Protocol", value: transport },
        ];
        const localnetHeaders = ["Local network data", "Details"];
        // ``localnetData`` is not a real HTML container — the
        // local-network summary historically lives in
        // ``sideloctable`` alongside the location data, so render it
        // there. (The original orchestrator did this too.)

        // ``bindLocationTableToHeatmap`` is invoked AFTER the new
        // location tables are appended to ``sideloctable`` so the
        // click handler lands on the freshly created tables rather
        // than on tables from the previous packet (which were stale
        // references and would have caused listeners to accumulate
        // on detached DOM nodes — see packet_detail_view_accumulation.md).

        // Source/destination location side panels
        const srcLocData = [
            { name: "Source Address", value: srcIp },
            { name: "City", value: srcLocation?.["City"] || "Unknown" },
            { name: "Country", value: srcLocation?.["Country"] || "Unknown" },
        ];
        const srcLocHeaders = ["Source location", "Details"];
        // ``sideloctable`` is the only real container in the HTML
        // for side location data — ``srcloctable`` is a vestige that
        // no longer exists. Clear ``sideloctable`` first so the
        // previous packet's location table does not stack under the
        // new one.
        const sideLocTableEl = document.getElementById("sideloctable");
        if (sideLocTableEl) sideLocTableEl.textContent = "";
        if (srcLocation?.["City"] || srcLocation?.["Country"]) {
            createTable(srcLocData, srcLocHeaders, "sideloctable");
        }

        const dstLocData = [
            { name: "Destination Address", value: dstIp },
            { name: "City", value: dstLocation?.["City"] || "Unknown" },
            { name: "Country", value: dstLocation?.["Country"] || "Unknown" },
        ];
        const dstLocHeaders = ["Destination location", "Details"];
        if (dstLocation?.["City"] || dstLocation?.["Country"]) {
            createTable(dstLocData, dstLocHeaders, "sideloctable");
        }

        // Now that ``sideloctable`` holds the freshly created
        // tables, attach the heatmap click handlers to them. The
        // original orchestrator called ``bindLocationTableToHeatmap``
        // inline (which attached to the previous packet's table);
        // moving the call after ``createTable`` is the bug fix.
        bindLocationTableToHeatmap(srcLocation, "Source location");
        bindLocationTableToHeatmap(dstLocation, "Destination location");
    }

    return {
        isPrintable,
        hexToAscii,
        truncate,
        clearGridHighlights,
        popHexGrid,
        infoPanel,
    };
}

module.exports = {
    createPacketDetailViewHelpers,
};
