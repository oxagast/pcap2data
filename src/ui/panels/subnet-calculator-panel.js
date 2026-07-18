// Controls the Conv subnet workspace UI and network lookup tools.

const IPV4_HOST_BITS = 32;
const IPV6_HOST_BITS = 128;

function createSubnetCalculatorPanel({
    statusUpdate = () => { },
    writeLogEntry = () => { },
    getBackendTransportOptions = () => ({}),
    getCurrentSettings = () => ({}),
    getCapturePackets = () => ({}),
    openHeatmapLocation = () => { },
    getCurrentPacketIps = () => ({ src: "", dst: "" }),
} = {}) {
    let lookupRequestToken = 0;
    let nmapScanToken = 0;

    const inputEl = document.getElementById("subnet-calc-input");
    const statusEl = document.getElementById("subnet-calc-status");
    const nmapScanBtnEl = document.getElementById("subnet-calc-nmap-scan-btn");
    const captureTargetsEl = document.getElementById("subnet-calc-capture-targets");
    const nmapEl = document.getElementById("subnet-calc-nmap");
    const threatIntelTypeEl = document.getElementById("subnet-ti-type");
    const threatIntelInputEl = document.getElementById("subnet-ti-input");
    const threatIntelLookupBtnEl = document.getElementById("subnet-ti-lookup-btn");
    const threatIntelUseAnalyzedIpBtnEl = document.getElementById("subnet-ti-use-analyzed-ip-btn");
    const summaryEl = document.getElementById("subnet-calc-summary");
    const rangeEl = document.getElementById("subnet-calc-range");
    const binaryEl = document.getElementById("subnet-calc-binary");
    const whoisEl = document.getElementById("subnet-calc-whois");
    const reputationIpsumEl = document.getElementById("subnet-calc-reputation-ipsum");
    const reputationVirustotalEl = document.getElementById("subnet-calc-reputation-virustotal");
    const reputationTorEl = document.getElementById("subnet-calc-reputation-tor");
    const geoEl = document.getElementById("subnet-calc-geo");
    const shodanEl = document.getElementById("subnet-calc-shodan");
    let threatIntelState = {
        ipsum: null,
        tor: null,
        virustotal: null,
    };
    let whoisCacheByIp = Object.create(null);
    let shodanCacheByIp = Object.create(null);
    const nmapScanState = {
        inFlight: false,
        lastRequestedTargetsKey: "",
        lastCompletedTargetsKey: "",
        lastKickoffAt: 0,
        lastInstallCheckAt: 0,
        installStatus: null,
        latestScanResponse: null,
        inFlightPromise: null,
        currentInspectedIp: "",
    };
    const NMAP_AUTO_SCAN_MIN_INTERVAL_MS = 15000;
    const NMAP_INSTALL_CHECK_TTL_MS = 60000;

    function clonePlainData(value, fallbackValue = null) {
        if (value === undefined) return fallbackValue;
        try {
            return JSON.parse(JSON.stringify(value));
        } catch (_error) {
            return fallbackValue;
        }
    }

    function normalizeLookupIp(value) {
        return String(value || "").trim();
    }

    function normalizeThreatIntelQueryType(value) {
        const normalized = String(value || "auto").trim().toLowerCase();
        if (normalized === "auto") return "auto";
        if (normalized === "url") return "url";
        if (normalized === "hash") return "hash";
        return "ip";
    }

    function getVirusTotalApiKey() {
        return String(getCurrentSettings()?.backend?.virusTotalApiKey || "").trim();
    }

    function getThreatIntelQueryInputValue() {
        return String(threatIntelInputEl?.value || "").trim();
    }

    function getThreatIntelQueryTypeValue() {
        return normalizeThreatIntelQueryType(threatIntelTypeEl?.value || "ip");
    }

    function setCachedWhoisResult(ipAddress, result) {
        const normalizedIp = normalizeLookupIp(ipAddress);
        if (!normalizedIp) return;
        whoisCacheByIp[normalizedIp] = clonePlainData(result, null);
    }

    function getCachedWhoisResult(ipAddress) {
        const normalizedIp = normalizeLookupIp(ipAddress);
        if (!normalizedIp) return null;
        return clonePlainData(whoisCacheByIp[normalizedIp], null);
    }

    function setCachedShodanResult(ipAddress, result) {
        const normalizedIp = normalizeLookupIp(ipAddress);
        if (!normalizedIp) return;
        shodanCacheByIp[normalizedIp] = clonePlainData(result, null);
    }

    function getCachedShodanResult(ipAddress) {
        const normalizedIp = normalizeLookupIp(ipAddress);
        if (!normalizedIp) return null;
        return clonePlainData(shodanCacheByIp[normalizedIp], null);
    }

    function getSessionState() {
        return {
            analyzedIp: String(nmapScanState.currentInspectedIp || "").trim(),
            whoisByIp: clonePlainData(whoisCacheByIp, {}),
            shodanByIp: clonePlainData(shodanCacheByIp, {}),
            nmap: {
                currentInspectedIp: String(nmapScanState.currentInspectedIp || "").trim(),
                lastCompletedTargetsKey: String(nmapScanState.lastCompletedTargetsKey || "").trim(),
                latestScanResponse: clonePlainData(nmapScanState.latestScanResponse, null),
            },
            threatIntel: {
                input: getThreatIntelQueryInputValue(),
                type: getThreatIntelQueryTypeValue(),
                state: clonePlainData(threatIntelState, null),
            },
        };
    }

    function restoreSessionState(restoredState = {}) {
        const normalizedState = restoredState && typeof restoredState === "object"
            ? restoredState
            : {};

        whoisCacheByIp = clonePlainData(normalizedState.whoisByIp, {}) || {};
        shodanCacheByIp = clonePlainData(normalizedState.shodanByIp, {}) || {};
        const restoredTiState = normalizedState.threatIntel && typeof normalizedState.threatIntel === "object"
            ? normalizedState.threatIntel
            : {};
        if (restoredTiState.state) {
            threatIntelState = clonePlainData(restoredTiState.state, null) || { ipsum: null, tor: null, virustotal: null };
        }
        if (restoredTiState.type && threatIntelTypeEl) {
            threatIntelTypeEl.value = normalizeThreatIntelQueryType(String(restoredTiState.type));
        }
        if (restoredTiState.input && threatIntelInputEl) {
            threatIntelInputEl.value = String(restoredTiState.input);
        }

        const restoredNmap = normalizedState.nmap && typeof normalizedState.nmap === "object"
            ? normalizedState.nmap
            : {};
        nmapScanState.latestScanResponse = clonePlainData(restoredNmap.latestScanResponse, null);
        nmapScanState.lastCompletedTargetsKey = String(restoredNmap.lastCompletedTargetsKey || "").trim();
        nmapScanState.currentInspectedIp = String(restoredNmap.currentInspectedIp || "").trim();
        nmapScanState.inFlight = false;
        nmapScanState.inFlightPromise = null;

        const inputValue = String(inputEl?.value || "").trim();
        let restoredAnalysis = null;
        if (inputValue) {
            try {
                restoredAnalysis = analyzeSubnetInput(inputValue);
            } catch (_error) {
                restoredAnalysis = null;
            }
        }

        if (restoredAnalysis) {
            const lookupIp = normalizeLookupIp(restoredAnalysis.lookupTargetIp || restoredAnalysis.address);
            if (lookupIp) {
                nmapScanState.currentInspectedIp = lookupIp;
                const cachedWhois = getCachedWhoisResult(lookupIp);
                if (cachedWhois) {
                    renderWhoisResult(restoredAnalysis, cachedWhois);
                }
                const cachedShodan = getCachedShodanResult(lookupIp);
                if (cachedShodan) {
                    renderShodanResult(restoredAnalysis, cachedShodan);
                }
            }
        }

        renderCaptureTargets(getCaptureInternetTargets(), getCurrentInspectedIp());
        if (nmapScanState.latestScanResponse) {
            renderNmapResults(nmapScanState.latestScanResponse, getCurrentInspectedIp());
        } else {
            setPlaceholder(nmapEl, "Nmap scan status for the selected host will appear here.");
        }
    }

    function resetSessionCacheState() {
        whoisCacheByIp = Object.create(null);
        shodanCacheByIp = Object.create(null);
        resetCaptureNmapState();
    }

    function setPanelStatus(message, isError = false) {
        if (!statusEl) return;
        statusEl.textContent = message;
        statusEl.classList.toggle("is-error", Boolean(isError));
    }

    function setPlaceholder(container, message) {
        if (!container) return;
        container.innerHTML = "";
        const placeholder = document.createElement("div");
        placeholder.className = "data-tools-proto-none";
        placeholder.textContent = message;
        container.appendChild(placeholder);
    }

    function appendRowValue(container, row) {
        if (!container) return;
        if (row?.valueElement instanceof Node) {
            container.appendChild(row.valueElement);
            return;
        }
        container.textContent = row?.value ?? "";
    }

    function renderKeyValueTable(container, title, rows) {
        if (!container) return;
        container.innerHTML = "";
        const titleEl = document.createElement("div");
        titleEl.className = "data-tools-output-label subnet-calc-section-title";
        titleEl.textContent = title;
        //container.appendChild(titleEl);

        if (!Array.isArray(rows) || rows.length === 0) {
            setPlaceholder(container, "No data available.");
            return;
        }

        const table = document.createElement("table");
        table.className = "data-tools-proto-table";

        const headerRow = document.createElement("tr");
        const fieldHeader = document.createElement("th");
        fieldHeader.textContent = "Field";
        const valueHeader = document.createElement("th");
        valueHeader.textContent = "Value";
        headerRow.appendChild(fieldHeader);
        headerRow.appendChild(valueHeader);
        table.appendChild(headerRow);

        rows.forEach((row) => {
            const tr = document.createElement("tr");
            const tdName = document.createElement("td");
            tdName.textContent = row.name;
            const tdValue = document.createElement("td");
            appendRowValue(tdValue, row);
            tr.appendChild(tdName);
            tr.appendChild(tdValue);
            table.appendChild(tr);
        });

        container.appendChild(table);
    }

    function renderBinaryTable(container, title, rows) {
        if (!container) return;
        container.innerHTML = "";
        const titleEl = document.createElement("div");
        titleEl.className = "data-tools-output-label subnet-calc-section-title";
        titleEl.textContent = title;
        container.appendChild(titleEl);

        if (!Array.isArray(rows) || rows.length === 0) {
            setPlaceholder(container, "No binary output available.");
            return;
        }

        rows.forEach((row) => {
            const rowWrap = document.createElement("div");
            rowWrap.className = "subnet-calc-binary-row";
            const labelEl = document.createElement("div");
            labelEl.className = "subnet-calc-binary-label";
            labelEl.textContent = row.name;
            const preEl = document.createElement("pre");
            preEl.className = "subnet-calc-binary-pre";
            preEl.textContent = row.value;
            rowWrap.appendChild(labelEl);
            rowWrap.appendChild(preEl);
            container.appendChild(rowWrap);
        });
    }

    function isNmapServiceScanEnabled() {
        return Boolean(getCurrentSettings()?.general?.nmapServiceScanEnabled);
    }

    function updateNmapScanButtonState() {
        if (!nmapScanBtnEl) return;
        const enabled = isNmapServiceScanEnabled();
        nmapScanBtnEl.disabled = !enabled;
        nmapScanBtnEl.title = enabled
            ? "Run nmap -sV on internet hosts/ports seen in this capture"
            : "Enable this in Settings > Frontend";
    }

    function parsePortNumber(rawValue) {
        const parsed = Number.parseInt(String(rawValue ?? "").trim(), 10);
        if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) {
            return null;
        }
        return parsed;
    }

    function buildTargetsSignature(targets) {
        if (!Array.isArray(targets) || !targets.length) return "";
        return targets
            .map((entry) => {
                const ip = String(entry?.ip || "").trim();
                const ports = Array.isArray(entry?.ports)
                    ? entry.ports
                        .map((portValue) => Number.parseInt(String(portValue), 10))
                        .filter((portValue) => Number.isInteger(portValue) && portValue >= 1 && portValue <= 65535)
                        .sort((a, b) => a - b)
                    : [];
                return `${ip}:${ports.join(",")}`;
            })
            .filter(Boolean)
            .sort((a, b) => a.localeCompare(b, undefined, { numeric: true }))
            .join("|");
    }

    function getPacketTransportName(packetInfo) {
        if (packetInfo?.TCP && typeof packetInfo.TCP === "object") return "TCP";
        if (packetInfo?.UDP && typeof packetInfo.UDP === "object") return "UDP";
        if (packetInfo?.SCTP && typeof packetInfo.SCTP === "object") return "SCTP";
        return "TCP";
    }

    function getTransportDataForPacketInfo(packetInfo, protocolName = "") {
        if (!packetInfo || typeof packetInfo !== "object") return {};
        const normalizedProtocol = String(protocolName || "").trim();
        const candidates = [
            normalizedProtocol,
            normalizedProtocol.toUpperCase(),
            normalizedProtocol.toLowerCase(),
            "TCP",
            "UDP",
            "SCTP",
        ].filter(Boolean);

        for (const candidate of candidates) {
            const transportData = packetInfo[candidate];
            if (transportData && typeof transportData === "object") {
                return transportData;
            }
        }
        return {};
    }

    function getCaptureInternetTargets() {
        const captureData = getCapturePackets() || {};
        const hostBuckets = captureData?.host;
        const targetsByIp = new Map();

        if (!hostBuckets || typeof hostBuckets !== "object") {
            return [];
        }

        for (const hostPackets of Object.values(hostBuckets)) {
            if (!Array.isArray(hostPackets)) continue;
            for (const packet of hostPackets) {
                const packetInfo = packet?.["packet.info"] || {};
                const ipInfo = packetInfo.IP || {};
                const srcIp = String(ipInfo["ip.src.addr"] ?? ipInfo["Source IP"] ?? "").trim();
                const dstIp = String(ipInfo["ip.dst.addr"] ?? ipInfo["Destination IP"] ?? "").trim();
                const protocol = getPacketTransportName(packetInfo);
                if (protocol !== "TCP") {
                    continue;
                }
                const transportData = getTransportDataForPacketInfo(packetInfo, protocol);
                const srcPort = parsePortNumber(
                    transportData["tcp.src.port"]
                    ?? transportData["udp.src.port"]
                    ?? transportData["sctp.src.port"]
                    ?? transportData["Source port"],
                );
                const dstPort = parsePortNumber(
                    transportData["tcp.dst.port"]
                    ?? transportData["udp.dst.port"]
                    ?? transportData["sctp.dst.port"]
                    ?? transportData["Destination port"],
                );

                const captureCandidate = (ipAddress, port) => {
                    if (!ipAddress || !port) return;
                    let analysis;
                    try {
                        analysis = analyzeSubnetInput(ipAddress);
                    } catch (_error) {
                        return;
                    }
                    if (analysis.exposure !== "Public") return;
                    if (!targetsByIp.has(ipAddress)) {
                        targetsByIp.set(ipAddress, {
                            ip: ipAddress,
                            ports: new Set(),
                            packetCount: 0,
                        });
                    }
                    const target = targetsByIp.get(ipAddress);
                    target.packetCount += 1;
                    target.ports.add(port);
                };

                captureCandidate(srcIp, srcPort);
                captureCandidate(dstIp, dstPort);
            }
        }

        return Array.from(targetsByIp.values())
            .map((entry) => ({
                ip: entry.ip,
                packetCount: entry.packetCount,
                ports: Array.from(entry.ports).sort((a, b) => a - b),
            }))
            .filter((entry) => entry.ports.length > 0)
            .sort((a, b) => a.ip.localeCompare(b.ip, undefined, { numeric: true }));
    }

    function getCurrentInspectedIp() {
        return String(nmapScanState.currentInspectedIp || "").trim();
    }

    function resolveManualScanInspectedIp(targets) {
        let inspectedIp = getCurrentInspectedIp();
        if (inspectedIp) {
            return inspectedIp;
        }

        const rawInput = String(inputEl?.value || "").trim();
        if (rawInput) {
            try {
                const analysis = analyzeSubnetInput(rawInput);
                inspectedIp = String(analysis.lookupTargetIp || analysis.address || "").trim();
                if (inspectedIp) {
                    return inspectedIp;
                }
            } catch (_error) {
                // Ignore parse errors and continue with packet-based fallback.
            }
        }

        const packetIps = getCurrentPacketIps() || {};
        const srcIp = String(packetIps.src || "").trim();
        const dstIp = String(packetIps.dst || "").trim();
        const targetIps = new Set((Array.isArray(targets) ? targets : []).map((entry) => String(entry?.ip || "").trim()));
        if (srcIp && targetIps.has(srcIp)) {
            return srcIp;
        }
        if (dstIp && targetIps.has(dstIp)) {
            return dstIp;
        }
        if (srcIp) return srcIp;
        if (dstIp) return dstIp;
        return "";
    }

    function renderCaptureTargets(targets, inspectedIp = "") {
        if (!captureTargetsEl) return;
        captureTargetsEl.innerHTML = "";
        const titleEl = document.createElement("div");
        titleEl.className = "data-tools-output-label subnet-calc-section-title";
        titleEl.textContent = "Capture Internet Targets (TCP)";
        captureTargetsEl.appendChild(titleEl);

        const latestScanResponse = nmapScanState.latestScanResponse;

        const scanByIp = new Map();
        const scanErrorsByIp = new Map();
        if (latestScanResponse && Array.isArray(latestScanResponse.results)) {
            latestScanResponse.results.forEach((scanResult) => {
                const resultIp = String(scanResult?.ip || "").trim();
                if (!resultIp) return;

                if (!scanResult?.success) {
                    scanErrorsByIp.set(resultIp, String(scanResult?.error || "nmap scan failed").trim());
                    return;
                }

                const parsedFindings = parseNmapXmlFindings(scanResult.xml, resultIp);
                parsedFindings.forEach((hostFinding) => {
                    const hostIp = String(hostFinding?.ipAddress || resultIp).trim();
                    if (!hostIp) return;

                    if (!scanByIp.has(hostIp)) {
                        scanByIp.set(hostIp, new Map());
                    }
                    const servicesByPort = scanByIp.get(hostIp);
                    (hostFinding.openPorts || []).forEach((openPort) => {
                        const portId = String(openPort?.portId || "").trim();
                        if (!portId) return;
                        const serviceName = String(openPort?.serviceName || "unknown").trim() || "unknown";
                        const software = String(openPort?.software || "").trim();
                        const label = software ? `${serviceName} (${software})` : serviceName;
                        servicesByPort.set(portId, label);
                    });
                });
            });
        }

        if (!isNmapServiceScanEnabled()) {
            setPlaceholder(
                captureTargetsEl,
                "Enable Conv Subnet internet-host Nmap scans in Settings > Frontend to run service scans.",
            );
            return;
        }

        if (!Array.isArray(targets) || targets.length === 0) {
            setPlaceholder(captureTargetsEl, "No internet IP + TCP port targets found in loaded capture.");
            return;
        }

        const normalizedInspectedIp = String(inspectedIp || getCurrentInspectedIp()).trim();
        if (!normalizedInspectedIp) {
            setPlaceholder(captureTargetsEl, "Analyze or select a specific IP to view only that host's observed ports.");
            return;
        }

        const filteredTargets = targets.filter((entry) => String(entry?.ip || "").trim() === normalizedInspectedIp);
        if (!filteredTargets.length) {
            setPlaceholder(
                captureTargetsEl,
                `No observed TCP ports in capture for inspected IP ${normalizedInspectedIp}.`,
            );
            return;
        }

        const table = document.createElement("table");
        table.className = "data-tools-proto-table";
        const headerRow = document.createElement("tr");
        ["Internet IP", "Observed Ports", "Observed Packets", "Nmap Service/Version"].forEach((title) => {
            const th = document.createElement("th");
            th.textContent = title;
            headerRow.appendChild(th);
        });
        table.appendChild(headerRow);

        filteredTargets.forEach((target) => {
            const tr = document.createElement("tr");
            const ipTd = document.createElement("td");
            ipTd.textContent = target.ip;
            const portsTd = document.createElement("td");
            portsTd.textContent = target.ports.join(", ");
            const packetCountTd = document.createElement("td");
            packetCountTd.textContent = String(target.packetCount);
            const nmapTd = document.createElement("td");
            const targetScanError = scanErrorsByIp.get(String(target.ip || "").trim());
            const serviceByPort = scanByIp.get(String(target.ip || "").trim()) || new Map();
            const lines = target.ports.map((portValue) => {
                const portText = String(portValue);
                const serviceLabel = serviceByPort.get(portText);
                if (serviceLabel) return `${serviceLabel}`;
                if (targetScanError) return `error (${targetScanError})`;
                if (!latestScanResponse) return `scan not run`;
                return `${portText}: unknown`;
            });
            nmapTd.textContent = lines.join(" | ");
            tr.appendChild(ipTd);
            tr.appendChild(portsTd);
            tr.appendChild(packetCountTd);
            tr.appendChild(nmapTd);
            table.appendChild(tr);
        });

        captureTargetsEl.appendChild(table);

        const actionRow = document.createElement("div");
        actionRow.className = "data-tools-actions subnet-calc-map-actions";
        const addLinkButton = (label, url) => {
            const button = document.createElement("button");
            button.type = "button";
            button.textContent = label;
            button.addEventListener("click", async () => {
                if (typeof window.browserapi?.openExternalUrl !== "function") {
                    return;
                }
                await window.browserapi.openExternalUrl(String(url));
            });
            actionRow.appendChild(button);
        };
        addLinkButton("NMap Project", "https://nmap.org");
        captureTargetsEl.appendChild(actionRow);
    }

    function parseNmapXmlFindings(xmlText, fallbackIp = "") {
        if (!xmlText || typeof xmlText !== "string") return [];
        const parser = new DOMParser();
        const xmlDoc = parser.parseFromString(xmlText, "application/xml");
        if (xmlDoc.querySelector("parsererror")) {
            return [];
        }

        const hosts = Array.from(xmlDoc.getElementsByTagName("host"));
        const findings = [];
        hosts.forEach((hostNode) => {
            const addressNode = hostNode.querySelector("address[addrtype='ipv4'], address[addrtype='ipv6']");
            const ipAddress = addressNode?.getAttribute("addr") || fallbackIp || "Unknown";
            const hostnameNode = hostNode.querySelector("hostnames > hostname");
            const hostname = hostnameNode?.getAttribute("name") || "";
            const openPorts = Array.from(hostNode.querySelectorAll("ports > port"))
                .map((portNode) => {
                    const state = portNode.querySelector("state")?.getAttribute("state") || "unknown";
                    const portId = portNode.getAttribute("portid") || "";
                    const serviceNode = portNode.querySelector("service");
                    const serviceName = serviceNode?.getAttribute("name") || "unknown";
                    const product = serviceNode?.getAttribute("product") || "";
                    const version = serviceNode?.getAttribute("version") || "";
                    const extra = serviceNode?.getAttribute("extrainfo") || "";
                    const software = [product, version, extra].filter(Boolean).join(" ").trim();
                    return {
                        portId,
                        state,
                        serviceName,
                        software,
                    };
                })
                .filter((entry) => entry.state === "open");

            findings.push({
                ipAddress,
                hostname,
                openPorts,
            });
        });
        return findings;
    }

    function renderNmapResults(scanResponse, inspectedIp = "") {
        if (!nmapEl) return;
        nmapEl.innerHTML = "";
        const titleEl = document.createElement("div");
        titleEl.className = "data-tools-output-label subnet-calc-section-title";
        titleEl.textContent = "Nmap Scan Status";
        nmapEl.appendChild(titleEl);

        renderCaptureTargets(getCaptureInternetTargets(), inspectedIp);

        if (!scanResponse || !Array.isArray(scanResponse.results) || scanResponse.results.length === 0) {
            setPlaceholder(nmapEl, "No nmap scan findings yet. Results appear in the table above.");
            return;
        }

        const normalizedInspectedIp = String(inspectedIp || getCurrentInspectedIp()).trim();
        if (!normalizedInspectedIp) {
            setPlaceholder(nmapEl, "Analyze or select a specific IP before running nmap scans.");
            return;
        }

        const filteredResults = scanResponse.results.filter(
            (scanResult) => String(scanResult?.ip || "").trim() === normalizedInspectedIp,
        );
        if (!filteredResults.length) {
            setPlaceholder(nmapEl, `No nmap findings are available yet for inspected IP ${normalizedInspectedIp}.`);
            return;
        }

        const summary = document.createElement("div");
        summary.className = "subnet-calc-binary-label";
        const successful = filteredResults.filter((entry) => entry?.success).length;
        summary.textContent = `Inspected IP ${normalizedInspectedIp}: ${successful}/${filteredResults.length} nmap job(s) succeeded. Service/version output is shown in the table above.`;
        nmapEl.appendChild(summary);
    }

    async function ensureNmapInstalledCached() {
        const now = Date.now();
        if (
            nmapScanState.installStatus
            && now - nmapScanState.lastInstallCheckAt < NMAP_INSTALL_CHECK_TTL_MS
        ) {
            return nmapScanState.installStatus;
        }
        if (!window.snitchapi || typeof window.snitchapi.checkNmapInstalled !== "function") {
            const unavailable = {
                installed: false,
                error: "Nmap scan API is unavailable.",
            };
            nmapScanState.installStatus = unavailable;
            nmapScanState.lastInstallCheckAt = now;
            return unavailable;
        }
        const installStatus = await window.snitchapi.checkNmapInstalled();
        nmapScanState.installStatus = installStatus;
        nmapScanState.lastInstallCheckAt = now;
        return installStatus;
    }

    function parseIpv4Octets(value) {
        const parts = String(value || "").trim().split(".");
        if (parts.length !== 4) {
            throw new Error("IPv4 addresses must contain four octets.");
        }
        return parts.map((part) => {
            if (!/^\d+$/.test(part)) {
                throw new Error("IPv4 octets must be decimal numbers.");
            }
            const numericValue = Number(part);
            if (!Number.isInteger(numericValue) || numericValue < 0 || numericValue > 255) {
                throw new Error("IPv4 octets must be between 0 and 255.");
            }
            return numericValue;
        });
    }

    function ipv4OctetsToInt(octets) {
        return (
            ((octets[0] << 24) >>> 0)
            | (octets[1] << 16)
            | (octets[2] << 8)
            | octets[3]
        ) >>> 0;
    }

    function ipv4IntToString(value) {
        return [
            (value >>> 24) & 255,
            (value >>> 16) & 255,
            (value >>> 8) & 255,
            value & 255,
        ].join(".");
    }

    function ipv4IntToBinary(value) {
        return [24, 16, 8, 0]
            .map((shift) => ((value >>> shift) & 255).toString(2).padStart(8, "0"))
            .join(" ");
    }

    function parseIpv4MaskPrefix(maskText) {
        const octets = parseIpv4Octets(maskText);
        const maskValue = ipv4OctetsToInt(octets);
        let prefix = 0;
        let seenZero = false;
        for (let bitIndex = 31; bitIndex >= 0; bitIndex -= 1) {
            const bit = (maskValue >>> bitIndex) & 1;
            if (bit === 1) {
                if (seenZero) {
                    throw new Error("IPv4 netmasks must have contiguous 1 bits.");
                }
                prefix += 1;
            } else {
                seenZero = true;
            }
        }
        return prefix;
    }

    function parseIpv6Address(value) {
        const rawValue = String(value || "").trim();
        if (!rawValue) {
            throw new Error("IPv6 address is empty.");
        }

        const normalized = rawValue.toLowerCase().split("%")[0];
        if (!normalized) {
            throw new Error("IPv6 address is empty.");
        }
        if (normalized.indexOf("::") !== normalized.lastIndexOf("::")) {
            throw new Error("IPv6 addresses may only contain one '::' compression token.");
        }

        const parseIpv6Part = (partText) => {
            if (!partText) return [];
            return partText.split(":").flatMap((token) => {
                if (!token) {
                    throw new Error("Invalid IPv6 address syntax.");
                }
                if (token.includes(".")) {
                    const ipv4Octets = parseIpv4Octets(token);
                    return [
                        (ipv4Octets[0] << 8) | ipv4Octets[1],
                        (ipv4Octets[2] << 8) | ipv4Octets[3],
                    ];
                }
                if (!/^[0-9a-f]{1,4}$/i.test(token)) {
                    throw new Error("IPv6 groups must be 1 to 4 hexadecimal digits.");
                }
                return [Number.parseInt(token, 16)];
            });
        };

        let groups;
        if (normalized.includes("::")) {
            const [leftText, rightText] = normalized.split("::");
            const leftGroups = parseIpv6Part(leftText);
            const rightGroups = parseIpv6Part(rightText);
            const zeroCount = 8 - (leftGroups.length + rightGroups.length);
            if (zeroCount < 1) {
                throw new Error("Invalid IPv6 compression length.");
            }
            groups = [
                ...leftGroups,
                ...new Array(zeroCount).fill(0),
                ...rightGroups,
            ];
        } else {
            groups = parseIpv6Part(normalized);
            if (groups.length !== 8) {
                throw new Error("IPv6 addresses must expand to eight 16-bit groups.");
            }
        }

        if (groups.length !== 8) {
            throw new Error("IPv6 addresses must expand to eight 16-bit groups.");
        }

        return groups;
    }

    function ipv6GroupsToBigInt(groups) {
        return groups.reduce(
            (total, groupValue) => (total << 16n) + BigInt(groupValue),
            0n,
        );
    }

    function ipv6BigIntToGroups(value) {
        const groups = new Array(8);
        let remainder = value;
        for (let index = 7; index >= 0; index -= 1) {
            groups[index] = Number(remainder & 0xffffn);
            remainder >>= 16n;
        }
        return groups;
    }

    function formatIpv6Expanded(groups) {
        return groups.map((groupValue) => groupValue.toString(16).padStart(4, "0")).join(":");
    }

    function formatIpv6Compressed(groups) {
        const hexGroups = groups.map((groupValue) => groupValue.toString(16));
        let bestStart = -1;
        let bestLength = 0;
        let currentStart = -1;
        let currentLength = 0;

        groups.forEach((groupValue, index) => {
            if (groupValue === 0) {
                if (currentStart === -1) currentStart = index;
                currentLength += 1;
                if (currentLength > bestLength) {
                    bestStart = currentStart;
                    bestLength = currentLength;
                }
            } else {
                currentStart = -1;
                currentLength = 0;
            }
        });

        if (bestLength < 2) {
            return hexGroups.join(":");
        }

        const left = hexGroups.slice(0, bestStart).join(":");
        const right = hexGroups.slice(bestStart + bestLength).join(":");
        if (!left && !right) return "::";
        if (!left) return `::${right}`;
        if (!right) return `${left}::`;
        return `${left}::${right}`;
    }

    function ipv6BigIntToBinary(value) {
        return ipv6BigIntToGroups(value)
            .map((groupValue) => groupValue.toString(2).padStart(16, "0"))
            .join(" ");
    }

    function parseSubnetInput(rawInput) {
        const trimmed = String(rawInput || "").trim();
        if (!trimmed) {
            throw new Error("Enter an IPv4 or IPv6 address/network first.");
        }

        let addressText = trimmed;
        let prefixText = "";
        const slashIndex = trimmed.indexOf("/");
        if (slashIndex >= 0) {
            addressText = trimmed.slice(0, slashIndex).trim();
            prefixText = trimmed.slice(slashIndex + 1).trim();
        } else {
            const maskMatch = trimmed.match(/^(\S+)\s+(\S+)$/);
            if (maskMatch) {
                addressText = maskMatch[1].trim();
                prefixText = maskMatch[2].trim();
            }
        }

        if (/^\[[^\]]+\]$/.test(addressText)) {
            addressText = addressText.slice(1, -1);
        }

        const version = addressText.includes(":") ? 6 : 4;
        if (version === 4) {
            const octets = parseIpv4Octets(addressText);
            const addressInt = ipv4OctetsToInt(octets);
            let prefix = IPV4_HOST_BITS;
            if (prefixText) {
                prefix = prefixText.includes(".")
                    ? parseIpv4MaskPrefix(prefixText)
                    : Number.parseInt(prefixText, 10);
            }
            if (!Number.isInteger(prefix) || prefix < 0 || prefix > IPV4_HOST_BITS) {
                throw new Error("IPv4 prefixes must be between 0 and 32.");
            }
            return {
                version,
                addressText,
                addressInt,
                prefix,
                explicitPrefix: Boolean(prefixText),
            };
        }

        const groups = parseIpv6Address(addressText);
        const addressBigInt = ipv6GroupsToBigInt(groups);
        const prefix = prefixText ? Number.parseInt(prefixText, 10) : IPV6_HOST_BITS;
        if (!Number.isInteger(prefix) || prefix < 0 || prefix > IPV6_HOST_BITS) {
            throw new Error("IPv6 prefixes must be between 0 and 128.");
        }
        return {
            version,
            addressText,
            addressBigInt,
            groups,
            prefix,
            explicitPrefix: Boolean(prefixText),
        };
    }

    function classifyIpv4Address(addressInt) {
        const firstOctet = (addressInt >>> 24) & 255;
        const inRange = (start, end) => addressInt >= start && addressInt <= end;
        const cidrRange = (base, prefix) => {
            const shift = BigInt(IPV4_HOST_BITS - prefix);
            const mask = prefix === 0 ? 0 : (0xffffffff << (IPV4_HOST_BITS - prefix)) >>> 0;
            return (addressInt & mask) === base;
        };

        let networkClass = "Class E";
        let classfulPrefix = 32;
        let classfulMask = "255.255.255.255";
        if (firstOctet <= 127) {
            networkClass = "Class A";
            classfulPrefix = 8;
            classfulMask = "255.0.0.0";
        } else if (firstOctet <= 191) {
            networkClass = "Class B";
            classfulPrefix = 16;
            classfulMask = "255.255.0.0";
        } else if (firstOctet <= 223) {
            networkClass = "Class C";
            classfulPrefix = 24;
            classfulMask = "255.255.255.0";
        } else if (firstOctet <= 239) {
            networkClass = "Class D";
            classfulPrefix = null;
            classfulMask = "N/A";
        }

        let exposure = "Public";
        let scope = "Global unicast";
        if (cidrRange(0x0a000000, 8) || cidrRange(0xac100000, 12) || cidrRange(0xc0a80000, 16)) {
            exposure = "Private";
            scope = "RFC1918 private use";
        } else if (cidrRange(0x7f000000, 8)) {
            exposure = "Private";
            scope = "Loopback";
        } else if (cidrRange(0xa9fe0000, 16)) {
            exposure = "Private";
            scope = "Link-local";
        } else if (cidrRange(0x64400000, 10)) {
            exposure = "Special use";
            scope = "Carrier-grade NAT";
        } else if (cidrRange(0xc6120000, 15)) {
            exposure = "Special use";
            scope = "Benchmark testing";
        } else if (cidrRange(0xc0000200, 24) || cidrRange(0xc6336400, 24) || cidrRange(0xcb007100, 24)) {
            exposure = "Special use";
            scope = "Documentation range";
        } else if (cidrRange(0xe0000000, 4)) {
            exposure = "Special use";
            scope = "Multicast";
        } else if (cidrRange(0xf0000000, 4)) {
            exposure = "Special use";
            scope = "Reserved / experimental";
        } else if (firstOctet === 0) {
            exposure = "Special use";
            scope = "This network";
        }

        return {
            networkClass,
            classfulPrefix,
            classfulMask,
            exposure,
            scope,
        };
    }

    function classifyIpv6Address(groups, addressBigInt) {
        const firstGroup = groups[0];
        const secondGroup = groups[1];
        let exposure = "Public";
        let scope = "Global unicast";

        if (addressBigInt === 0n) {
            exposure = "Special use";
            scope = "Unspecified";
        } else if (addressBigInt === 1n) {
            exposure = "Private";
            scope = "Loopback";
        } else if ((firstGroup & 0xfe00) === 0xfc00) {
            exposure = "Private";
            scope = "Unique local";
        } else if ((firstGroup & 0xffc0) === 0xfe80) {
            exposure = "Private";
            scope = "Link-local";
        } else if ((firstGroup & 0xff00) === 0xff00) {
            exposure = "Special use";
            scope = "Multicast";
        } else if (firstGroup === 0x2001 && secondGroup === 0x0db8) {
            exposure = "Special use";
            scope = "Documentation range";
        }

        return {
            networkClass: "IPv6",
            classfulPrefix: null,
            classfulMask: "N/A",
            exposure,
            scope,
        };
    }

    function analyzeIpv4(parsed) {
        const hostBits = IPV4_HOST_BITS - parsed.prefix;
        const maskInt = parsed.prefix === 0
            ? 0
            : (0xffffffff << hostBits) >>> 0;
        const wildcardInt = (~maskInt) >>> 0;
        const networkInt = parsed.addressInt & maskInt;
        const broadcastInt = (networkInt | wildcardInt) >>> 0;
        const totalAddresses = 1n << BigInt(hostBits);
        const usableHosts = parsed.prefix === 32
            ? 1n
            : parsed.prefix === 31
                ? 2n
                : totalAddresses - 2n;
        const firstUsable = parsed.prefix >= 31 ? networkInt : (networkInt + 1) >>> 0;
        const lastUsable = parsed.prefix >= 31 ? broadcastInt : (broadcastInt - 1) >>> 0;
        const classification = classifyIpv4Address(parsed.addressInt);
        const inputAddress = ipv4IntToString(parsed.addressInt);

        return {
            version: 4,
            normalizedInput: `${inputAddress}/${parsed.prefix}`,
            address: inputAddress,
            prefix: parsed.prefix,
            addressRole: !parsed.explicitPrefix
                ? "Single host"
                : parsed.addressInt === networkInt
                    ? "Network / subnet"
                    : "Host inside subnet",
            network: ipv4IntToString(networkInt),
            broadcast: ipv4IntToString(broadcastInt),
            firstUsable: ipv4IntToString(firstUsable),
            lastUsable: ipv4IntToString(lastUsable),
            subnetMask: ipv4IntToString(maskInt),
            wildcardMask: ipv4IntToString(wildcardInt),
            totalAddresses: totalAddresses.toString(),
            usableHosts: usableHosts.toString(),
            networkClass: classification.networkClass,
            classfulPrefix: classification.classfulPrefix,
            classfulMask: classification.classfulMask,
            exposure: classification.exposure,
            scope: classification.scope,
            binaryAddress: ipv4IntToBinary(parsed.addressInt),
            binaryNetwork: ipv4IntToBinary(networkInt),
            binaryMask: ipv4IntToBinary(maskInt),
            lookupTargetIp: inputAddress,
        };
    }

    function analyzeIpv6(parsed) {
        const hostBits = IPV6_HOST_BITS - parsed.prefix;
        const fullMask = (1n << 128n) - 1n;
        const maskBigInt = parsed.prefix === 0
            ? 0n
            : (fullMask << BigInt(hostBits)) & fullMask;
        const wildcardBigInt = fullMask ^ maskBigInt;
        const networkBigInt = parsed.addressBigInt & maskBigInt;
        const lastAddressBigInt = networkBigInt | wildcardBigInt;
        const totalAddresses = 1n << BigInt(hostBits);
        const classification = classifyIpv6Address(parsed.groups, parsed.addressBigInt);
        const addressGroups = ipv6BigIntToGroups(parsed.addressBigInt);
        const networkGroups = ipv6BigIntToGroups(networkBigInt);
        const maskGroups = ipv6BigIntToGroups(maskBigInt);
        const wildcardGroups = ipv6BigIntToGroups(wildcardBigInt);
        const inputAddress = formatIpv6Compressed(addressGroups);

        return {
            version: 6,
            normalizedInput: `${inputAddress}/${parsed.prefix}`,
            address: inputAddress,
            prefix: parsed.prefix,
            addressRole: !parsed.explicitPrefix
                ? "Single host"
                : parsed.addressBigInt === networkBigInt
                    ? "Network / subnet"
                    : "Host inside subnet",
            network: formatIpv6Compressed(networkGroups),
            broadcast: "N/A",
            firstUsable: formatIpv6Compressed(networkGroups),
            lastUsable: formatIpv6Compressed(ipv6BigIntToGroups(lastAddressBigInt)),
            subnetMask: formatIpv6Compressed(maskGroups),
            wildcardMask: formatIpv6Compressed(wildcardGroups),
            totalAddresses: totalAddresses.toString(),
            usableHosts: totalAddresses.toString(),
            networkClass: classification.networkClass,
            classfulPrefix: classification.classfulPrefix,
            classfulMask: classification.classfulMask,
            exposure: classification.exposure,
            scope: classification.scope,
            binaryAddress: ipv6BigIntToBinary(parsed.addressBigInt),
            binaryNetwork: ipv6BigIntToBinary(networkBigInt),
            binaryMask: ipv6BigIntToBinary(maskBigInt),
            lookupTargetIp: inputAddress,
            expandedAddress: formatIpv6Expanded(addressGroups),
            expandedNetwork: formatIpv6Expanded(networkGroups),
        };
    }

    function analyzeSubnetInput(rawInput) {
        const parsed = parseSubnetInput(rawInput);
        return parsed.version === 4 ? analyzeIpv4(parsed) : analyzeIpv6(parsed);
    }

    function renderAnalysisResults(analysis) {
        const summaryRows = [
            { name: "Normalized", value: analysis.normalizedInput },
            { name: "IP Version", value: `IPv${analysis.version}` },
            { name: "Prefix Length", value: `/${analysis.prefix}` },
            { name: "Address Role", value: analysis.addressRole },
            { name: "Public / Private", value: analysis.exposure },
            { name: "Scope", value: analysis.scope },
            { name: "Network Class", value: analysis.networkClass },
        ];
        if (analysis.version === 4 && analysis.classfulPrefix !== null) {
            summaryRows.push(
                { name: "Classful Default Prefix", value: `/${analysis.classfulPrefix}` },
                { name: "Classful Default Mask", value: analysis.classfulMask },
            );
        }
        if (analysis.version === 6) {
            summaryRows.push({ name: "Expanded Address", value: analysis.expandedAddress });
        }

        const rangeRows = [
            { name: "Address", value: analysis.address },
            { name: "Network", value: analysis.network },
            { name: "Subnet Mask", value: analysis.subnetMask },
            { name: "Wildcard Mask", value: analysis.wildcardMask },
            { name: "First Usable", value: analysis.firstUsable },
            { name: "Last Usable", value: analysis.lastUsable },
            { name: "Total Addresses", value: analysis.totalAddresses },
            { name: analysis.version === 4 ? "Usable Hosts" : "Usable Addresses", value: analysis.usableHosts },
        ];
        if (analysis.version === 4) {
            rangeRows.splice(4, 0, { name: "Broadcast", value: analysis.broadcast });
        } else {
            rangeRows.splice(2, 0, { name: "Expanded Network", value: analysis.expandedNetwork });
        }

        const binaryRows = [
            { name: "Address", value: analysis.binaryAddress },
            { name: "Network", value: analysis.binaryNetwork },
            { name: "Mask", value: analysis.binaryMask },
        ];

        renderKeyValueTable(summaryEl, "Summary", summaryRows);
        renderKeyValueTable(rangeEl, "Range", rangeRows);
        renderBinaryTable(binaryEl, "Binary Notation", binaryRows);
        setPlaceholder(whoisEl, "Looking up WHOIS / RDAP data...");
        setPlaceholder(geoEl, "Looking up GeoIP data...");
        setPlaceholder(shodanEl, "Looking up Shodan InternetDB data...");
        // Threat intelligence results now live in a dedicated subtab, so the
        // Analyze Subnet panel no longer renders them here.  The Threat Intel
        // subtab renders them via renderThreatIntelResult when it is shown.
    }

    function renderShodanResult(analysis, shodanResult) {
        if (!shodanEl) return;
        shodanEl.innerHTML = "";
        const titleEl = document.createElement("div");
        titleEl.className = "data-tools-output-label subnet-calc-section-title";
        titleEl.textContent = "Shodan InternetDB";
        shodanEl.appendChild(titleEl);

        if (!shodanResult || shodanResult.success === false) {
            const message = shodanResult?.error || "Shodan InternetDB lookup failed.";
            setPlaceholder(shodanEl, message);
            return;
        }

        const arrayToText = (value) => {
            if (!Array.isArray(value) || value.length === 0) return "None";
            return value.map((entry) => String(entry)).join(", ");
        };

        const rows = [
            { name: "Lookup Target", value: analysis.lookupTargetIp },
            { name: "Returned IP", value: String(shodanResult.ip || "Unknown") },
            { name: "Ports", value: arrayToText(shodanResult.ports) },
            { name: "Hostnames", value: arrayToText(shodanResult.hostnames) },
            { name: "CPEs", value: arrayToText(shodanResult.cpes) },
            { name: "Tags", value: arrayToText(shodanResult.tags) },
            { name: "Vulns", value: arrayToText(shodanResult.vulns) },
        ];
        renderKeyValueTable(shodanEl, "Shodan InternetDB", rows);

        const actionRow = document.createElement("div");
        actionRow.className = "data-tools-actions subnet-calc-map-actions";
        const docButton = document.createElement("button");
        docButton.type = "button";
        docButton.textContent = "Open Shodan InternetDB";
        docButton.addEventListener("click", async () => {
            if (typeof window.browserapi?.openExternalUrl !== "function") {
                return;
            }
            await window.browserapi.openExternalUrl("https://internetdb.shodan.io");
        });
        actionRow.appendChild(docButton);
        shodanEl.appendChild(actionRow);
    }

    function clearThreatIntelCards() {
        [reputationIpsumEl, reputationVirustotalEl, reputationTorEl].forEach((el) => {
            if (el) {
                el.innerHTML = "";
            }
        });
    }

    function renderThreatIntelCard(container, title, projectLabel, projectUrl, renderFn) {
        if (!container) return;
        container.innerHTML = "";
        const titleEl = document.createElement("div");
        titleEl.className = "data-tools-output-label subnet-calc-section-title";
        titleEl.textContent = title;
        container.appendChild(titleEl);
        renderFn(container);
        const actionRow = document.createElement("div");
        actionRow.className = "data-tools-actions subnet-calc-map-actions";
        const button = document.createElement("button");
        button.type = "button";
        button.textContent = projectLabel;
        button.addEventListener("click", async () => {
            if (typeof window.browserapi?.openExternalUrl !== "function") {
                return;
            }
            await window.browserapi.openExternalUrl(String(projectUrl));
        });
        actionRow.appendChild(button);
        container.appendChild(actionRow);
    }

    function renderThreatIntelResult(analysis) {
        clearThreatIntelCards();

        const ipsumResult = threatIntelState.ipsum;
        const torResult = threatIntelState.tor;
        const virustotalResult = threatIntelState.virustotal;
        if (!ipsumResult && !torResult && !virustotalResult) {
            renderThreatIntelCard(
                reputationIpsumEl,
                "IPSum",
                "Open IPSum project",
                "https://github.com/stamparm/ipsum",
                (container) => setPlaceholder(container, "Threat intelligence data will appear here."),
            );
            renderThreatIntelCard(
                reputationVirustotalEl,
                "VirusTotal",
                "Open VirusTotal",
                "https://www.virustotal.com/",
                (container) => setPlaceholder(container, "Threat intelligence data will appear here."),
            );
            renderThreatIntelCard(
                reputationTorEl,
                "Tor",
                "Open Tor Project",
                "https://www.torproject.org/",
                (container) => setPlaceholder(container, "Threat intelligence data will appear here."),
            );
            return;
        }

        if (ipsumResult) {
            renderThreatIntelCard(
                reputationIpsumEl,
                "IPSum",
                "Open IPSum project",
                "https://github.com/stamparm/ipsum",
                (container) => {
                    const section = document.createElement("div");
                    if (ipsumResult.success === false) {
                        setPlaceholder(section, ipsumResult.error || "IP reputation lookup failed.");
                    } else {
                        const gradeBadge = document.createElement("span");
                        const normalizedGrade = String(ipsumResult.grade || "Unknown").trim().toUpperCase();
                        gradeBadge.className = `subnet-calc-grade-badge subnet-calc-grade-${normalizedGrade.toLowerCase()}`;
                        gradeBadge.textContent = ipsumResult.grade && ipsumResult.gradeLabel
                            ? `${ipsumResult.grade} ${ipsumResult.gradeLabel}`
                            : String(ipsumResult.gradeLabel || "Unknown");

                        const rows = [
                            { name: "Lookup Target", value: ipsumResult.ip || analysis.lookupTargetIp },
                            {
                                name: "Grade",
                                valueElement: gradeBadge,
                            },
                            {
                                name: "Threat Intelligence Hits",
                                value: Number.isFinite(Number(ipsumResult.hitCount))
                                    ? String(ipsumResult.hitCount)
                                    : "Unknown",
                            },
                            { name: "Listed", value: ipsumResult.listed ? "Yes" : "No" },
                            { name: "Dataset Fetch Date", value: String(ipsumResult.fetchedDate || "Unknown") },
                        ];

                        if (ipsumResult.supported === false) {
                            rows.push({
                                name: "Status",
                                value: String(ipsumResult.message || "Unsupported"),
                            });
                        }
                        if (ipsumResult.isLocalnet) {
                            rows.push({
                                name: "Status",
                                value: "Local / special-use IPs are not part of internet threat lists.",
                            });
                        }

                        renderKeyValueTable(section, "IPSum", rows);
                    }
                    container.appendChild(section);
                },
            );
        } else {
            renderThreatIntelCard(
                reputationIpsumEl,
                "IPSum",
                "Open IPSum project",
                "https://github.com/stamparm/ipsum",
                (container) => setPlaceholder(container, "Threat intelligence data will appear here."),
            );
        }

        if (virustotalResult) {
            renderThreatIntelCard(
                reputationVirustotalEl,
                "VirusTotal",
                "Open VirusTotal",
                "https://www.virustotal.com/",
                (container) => {
                    const section = document.createElement("div");
                    if (virustotalResult.success === false) {
                        setPlaceholder(section, virustotalResult.error || "VirusTotal lookup failed.");
                    } else {
                        const vtAnalysis = virustotalResult.analysis && typeof virustotalResult.analysis === "object"
                            ? virustotalResult.analysis
                            : {};
                        const makeCountBadge = (count, kind) => {
                            const value = Number.isFinite(Number(count)) ? Number(count) : 0;
                            const badge = document.createElement("span");
                            badge.className = `subnet-calc-grade-badge subnet-calc-vt-${kind}-${value > 0 ? "positive" : "zero"}`;
                            badge.textContent = String(value);
                            return badge;
                        };

                        const makeReputationBadge = (reputation) => {
                            const value = Number.isFinite(Number(reputation)) ? Number(reputation) : 0;
                            const badge = document.createElement("span");
                            if (value > 0) {
                                badge.className = "subnet-calc-grade-badge subnet-calc-vt-reputation-positive";
                            } else if (value < 0) {
                                badge.className = "subnet-calc-grade-badge subnet-calc-vt-reputation-negative";
                            } else {
                                badge.className = "subnet-calc-grade-badge subnet-calc-vt-reputation-zero";
                            }
                            badge.textContent = String(value);
                            return badge;
                        };

                        const rows = [
                            { name: "Query Type", value: String(virustotalResult.lookupType || "Unknown") },
                            {
                                name: "Lookup Target",
                                value: String(
                                    virustotalResult.lookupValue
                                    || analysis.lookupTargetIp
                                    || getThreatIntelQueryInputValue()
                                    || "Unknown",
                                ),
                            },
                            { name: "Record ID", value: String(virustotalResult.recordId || "Unknown") },
                            { name: "Malicious", valueElement: makeCountBadge(vtAnalysis.malicious, "malicious") },
                            { name: "Suspicious", valueElement: makeCountBadge(vtAnalysis.suspicious, "suspicious") },
                            {
                                name: "Harmless",
                                valueElement: makeCountBadge(
                                    vtAnalysis.harmless,
                                    typeof vtAnalysis.harmless === "number" && vtAnalysis.harmless === 0
                                        ? "harmless-zero"
                                        : "harmless",
                                ),
                            },
                            { name: "Undetected", value: String(vtAnalysis.undetected ?? 0) },
                        ];

                        if (Number.isFinite(Number(virustotalResult.reputation))) {
                            rows.push({
                                name: "Reputation",
                                valueElement: makeReputationBadge(virustotalResult.reputation),
                            });
                        }

                        const vtAttributes = virustotalResult.attributes && typeof virustotalResult.attributes === "object"
                            ? virustotalResult.attributes
                            : {};
                        const recordName = virustotalResult.recordName
                            || vtAttributes.meaningful_name
                            || vtAnalysis.meaningful_name;
                        const recordDescription = virustotalResult.recordDescription
                            || (Array.isArray(vtAttributes.names) && vtAttributes.names.length > 0
                                ? vtAttributes.names.join(", ")
                                : "")
                            || (Array.isArray(vtAnalysis.names) && vtAnalysis.names.length > 0
                                ? vtAnalysis.names.join(", ")
                                : "");
                        if (recordName) {
                            rows.push({ name: "Record Name", value: String(recordName) });
                        }
                        if (recordDescription) {
                            rows.push({ name: "Record Description", value: String(recordDescription) });
                        }

                        if (virustotalResult.lastAnalysisDate) {
                            let analysisDate = virustotalResult.lastAnalysisDate;
                            if (typeof analysisDate === "number" || /^\d+$/.test(String(analysisDate))) {
                                const epoch = Number(analysisDate);
                                // VirusTotal returns epoch seconds; epoch ms would be > year 50000
                                const dateObj = epoch > 1e12 ? new Date(epoch) : new Date(epoch * 1000);
                                analysisDate = dateObj.toISOString().replace("T", " ").slice(0, 19) + " UTC";
                            }
                            rows.push({ name: "Last Analysis Date", value: String(analysisDate) });
                        }

                        renderKeyValueTable(section, "VirusTotal", rows);

                        if (virustotalResult.guiUrl) {
                            const virustotalActionRow = document.createElement("div");
                            virustotalActionRow.className = "data-tools-actions subnet-calc-map-actions";
                            const guiButton = document.createElement("button");
                            guiButton.type = "button";
                            guiButton.textContent = "Open VirusTotal Record";
                            guiButton.addEventListener("click", async () => {
                                if (typeof window.browserapi?.openExternalUrl !== "function") {
                                    return;
                                }
                                await window.browserapi.openExternalUrl(String(virustotalResult.guiUrl));
                            });
                            virustotalActionRow.appendChild(guiButton);
                            section.appendChild(virustotalActionRow);
                        }
                    }
                    container.appendChild(section);
                },
            );
        } else {
            renderThreatIntelCard(
                reputationVirustotalEl,
                "VirusTotal",
                "Open VirusTotal",
                "https://www.virustotal.com/",
                (container) => setPlaceholder(container, "Threat intelligence data will appear here."),
            );
        }

        if (torResult) {
            renderThreatIntelCard(
                reputationTorEl,
                "Tor",
                "Open Tor Project",
                "https://www.torproject.org/",
                (container) => {
                    const section = document.createElement("div");
                    if (torResult.success === false) {
                        setPlaceholder(section, torResult.error || "Tor lookup failed.");
                    } else {
                        const exitNodeBadge = document.createElement("span");
                        exitNodeBadge.className = torResult.isExitNode
                            ? "subnet-calc-grade-badge subnet-calc-bool-yes"
                            : "subnet-calc-grade-badge subnet-calc-bool-no";
                        exitNodeBadge.textContent = torResult.isExitNode ? "Yes" : "No";

                        const rows = [
                            { name: "Lookup Target", value: torResult.ip || analysis.lookupTargetIp },
                            { name: "Exit Node", valueElement: exitNodeBadge },
                            { name: "Total Node Match", value: String(torResult.nodeCount || 0) },
                            { name: "Dataset Fetch Date", value: String(torResult.fetchedDate || "Unknown") },
                        ];

                        if (Array.isArray(torResult.nodes) && torResult.nodes.length > 0) {
                            // now just use the first node, because the others will be dupes
                            // the same node with different exit ports
                            const firstNode = torResult.nodes[0];
                            rows.push({ name: "Node Nickname", value: String(firstNode.nickname || "Unknown") });
                            rows.push({ name: "Node Platform", value: String(firstNode.platform || "Unknown") });
                        }

                        renderKeyValueTable(section, "Tor", rows);
                    }
                    container.appendChild(section);
                },
            );
        } else {
            renderThreatIntelCard(
                reputationTorEl,
                "Tor",
                "Open Tor Project",
                "https://www.torproject.org/",
                (container) => setPlaceholder(container, "Threat intelligence data will appear here."),
            );
        }
    }

    function renderIpsumResult(analysis, reputationResult) {
        threatIntelState.ipsum = reputationResult;
        renderThreatIntelResult(analysis);
    }

    function renderTorResult(analysis, torResult) {
        threatIntelState.tor = torResult;
        renderThreatIntelResult(analysis);
    }

    function renderVirusTotalResult(analysis, virustotalResult) {
        threatIntelState.virustotal = virustotalResult;
        renderThreatIntelResult(analysis);
    }

    function renderWhoisResult(analysis, whoisResult) {
        if (!whoisEl) return;
        whoisEl.innerHTML = "";
        const titleEl = document.createElement("div");
        titleEl.className = "data-tools-output-label subnet-calc-section-title";
        titleEl.textContent = "WHOIS / RDAP";
        whoisEl.appendChild(titleEl);

        if (!whoisResult || whoisResult.success === false) {
            const message = whoisResult?.error || "WHOIS lookup failed.";
            setPlaceholder(whoisEl, message);
            return;
        }

        const whois = whoisResult.whois && typeof whoisResult.whois === "object"
            ? whoisResult.whois
            : {};
        const rows = [
            { name: "Lookup Target", value: whoisResult.ip || analysis.lookupTargetIp },
            { name: "ISP", value: String(whois.isp || "Unknown") },
            { name: "NetName", value: String(whois.netName || "Unknown") },
            { name: "Net Type", value: String(whois.netType || "Unknown") },
            { name: "Parent", value: String(whois.parent || "Unknown") },
            { name: "Registration Date", value: String(whois.registrationDate || "Unknown") },
            { name: "Updated Date", value: String(whois.updatedDate || "Unknown") },
            { name: "Range Start", value: String(whois.rangeStart || "Unknown") },
            { name: "Range End", value: String(whois.rangeEnd || "Unknown") },
            { name: "CIDR", value: String(whois.cidr || "Unknown") },
            { name: "RIR", value: String(whois.rirHost || "Unknown") },
        ];
        renderKeyValueTable(whoisEl, "WHOIS / RDAP", rows);
    }

    function renderGeoipResult(analysis, geoResult) {
        if (!geoEl) return;
        geoEl.innerHTML = "";
        const titleEl = document.createElement("div");
        titleEl.className = "data-tools-output-label subnet-calc-section-title";
        titleEl.textContent = "GeoIP";
        geoEl.appendChild(titleEl);

        if (!geoResult || geoResult.success === false) {
            const message = geoResult?.error || "GeoIP lookup failed.";
            setPlaceholder(geoEl, message);
            return;
        }

        const location = geoResult.location && typeof geoResult.location === "object"
            ? geoResult.location
            : {};
        const rows = [
            { name: "Lookup Target", value: geoResult.ip || analysis.lookupTargetIp },
            { name: "Status", value: geoResult.isLocalnet ? "Localnet" : geoResult.isError ? "Error" : "Resolved" },
            { name: "Country", value: String(location.Country || "Unknown") },
            { name: "City", value: String(location.City || "Unknown") },
            { name: "Postal Code", value: String(location["Postal Code"] || "Unknown") },
            { name: "Time Zone", value: String(location["Time Zone"] || "Unknown") },
            {
                name: "Coordinates",
                value: geoResult.mapPoint
                    ? `${geoResult.mapPoint.latitude}, ${geoResult.mapPoint.longitude}`
                    : "Unavailable",
            },
        ];
        renderKeyValueTable(geoEl, "GeoIP", rows);

        if (geoResult.mapPoint && typeof geoResult.mapPoint.latitude === "number" && typeof geoResult.mapPoint.longitude === "number") {
            const actionRow = document.createElement("div");
            actionRow.className = "data-tools-actions subnet-calc-map-actions";
            const mapButton = document.createElement("button");
            mapButton.type = "button";
            mapButton.textContent = "Open in Stats map";
            mapButton.addEventListener("click", () => {
                openHeatmapLocation({
                    latitude: geoResult.mapPoint.latitude,
                    longitude: geoResult.mapPoint.longitude,
                    label: [location.City, location.Country].filter(Boolean).join(", ") || geoResult.ip || analysis.lookupTargetIp,
                });
            });
            actionRow.appendChild(mapButton);
            geoEl.appendChild(actionRow);
        }
    }

    async function lookupGeoip(analysis, requestToken) {
        const currentToken = requestToken;
        if (!window.snitchapi || typeof window.snitchapi.lookupGeoip !== "function") {
            renderGeoipResult(analysis, {
                success: false,
                error: "Backend GeoIP lookup API is unavailable.",
            });
            return;
        }

        try {
            const result = await window.snitchapi.lookupGeoip(analysis.lookupTargetIp, {
                backendOptions: getBackendTransportOptions(),
                side: "src",
            });
            if (currentToken !== lookupRequestToken) return;
            renderGeoipResult(analysis, result);
            if (result?.success === false) {
                setPanelStatus(result.error || "GeoIP lookup failed.", true);
                return;
            }
        } catch (error) {
            if (currentToken !== lookupRequestToken) return;
            renderGeoipResult(analysis, {
                success: false,
                error: error?.message || "GeoIP lookup failed.",
            });
            setPanelStatus(error?.message || "GeoIP lookup failed.", true);
        }
    }

    async function lookupWhois(analysis, requestToken) {
        const currentToken = requestToken;
        const cachedResult = getCachedWhoisResult(analysis.lookupTargetIp);
        if (cachedResult) {
            renderWhoisResult(analysis, cachedResult);
            return;
        }

        if (!window.snitchapi || typeof window.snitchapi.lookupWhois !== "function") {
            const unavailableResult = {
                success: false,
                error: "Backend WHOIS lookup API is unavailable.",
            };
            setCachedWhoisResult(analysis.lookupTargetIp, unavailableResult);
            renderWhoisResult(analysis, unavailableResult);
            return;
        }

        try {
            const result = await window.snitchapi.lookupWhois(analysis.lookupTargetIp, {
                backendOptions: getBackendTransportOptions(),
            });
            if (currentToken !== lookupRequestToken) return;
            setCachedWhoisResult(analysis.lookupTargetIp, result);
            renderWhoisResult(analysis, result);
            if (result?.success === false) {
                setPanelStatus(result.error || "WHOIS lookup failed.", true);
            }
        } catch (error) {
            if (currentToken !== lookupRequestToken) return;
            const errorResult = {
                success: false,
                error: error?.message || "WHOIS lookup failed.",
            };
            setCachedWhoisResult(analysis.lookupTargetIp, errorResult);
            renderWhoisResult(analysis, errorResult);
            setPanelStatus(error?.message || "WHOIS lookup failed.", true);
        }
    }

    async function lookupIpsum(analysis, requestToken) {
        const currentToken = requestToken;
        if (!window.snitchapi || typeof window.snitchapi.lookupIpsum !== "function") {
            renderIpsumResult(analysis, {
                success: false,
                error: "Backend IPSum lookup API is unavailable.",
            });
            return;
        }

        try {
            const result = await window.snitchapi.lookupIpsum(analysis.lookupTargetIp, {
                backendOptions: getBackendTransportOptions(),
            });
            if (currentToken !== lookupRequestToken) return;
            renderIpsumResult(analysis, result);
            if (result?.success === false) {
                setPanelStatus(result.error || "IP reputation lookup failed.", true);
            }
        } catch (error) {
            if (currentToken !== lookupRequestToken) return;
            renderIpsumResult(analysis, {
                success: false,
                error: error?.message || "IP reputation lookup failed.",
            });
            setPanelStatus(error?.message || "IP reputation lookup failed.", true);
        }
    }

    async function lookupTor(analysis, requestToken) {
        const currentToken = requestToken;
        if (!window.snitchapi || typeof window.snitchapi.lookupTor !== "function") {
            renderTorResult(analysis, {
                success: false,
                error: "Backend Tor lookup API is unavailable.",
            });
            return;
        }

        try {
            const result = await window.snitchapi.lookupTor(analysis.lookupTargetIp, {
                backendOptions: getBackendTransportOptions(),
            });
            if (currentToken !== lookupRequestToken) return;
            renderTorResult(analysis, result);
            if (result?.success === false) {
                setPanelStatus(result.error || "Tor lookup failed.", true);
            }
        } catch (error) {
            if (currentToken !== lookupRequestToken) return;
            renderTorResult(analysis, {
                success: false,
                error: error?.message || "Tor lookup failed.",
            });
            setPanelStatus(error?.message || "Tor lookup failed.", true);
        }
    }

    async function lookupVirusTotalForInput(analysis, requestToken, explicitInput = "", explicitType = "") {
        const currentToken = requestToken;
        if (!window.snitchapi || typeof window.snitchapi.lookupVirusTotal !== "function") {
            renderVirusTotalResult(analysis, {
                success: false,
                error: "Backend VirusTotal lookup API is unavailable.",
            });
            return;
        }

        const lookupType = normalizeThreatIntelQueryType(explicitType || getThreatIntelQueryTypeValue());
        const lookupValue = String(explicitInput || getThreatIntelQueryInputValue()).trim();
        if (!lookupValue) {
            renderVirusTotalResult(analysis, {
                success: false,
                error: "Enter an IP, URL, or hash for VirusTotal lookup.",
            });
            return;
        }

        const apiKey = getVirusTotalApiKey();
        if (!apiKey) {
            renderVirusTotalResult(analysis, {
                success: false,
                error: "VirusTotal API key is missing. Add it in Settings > Backend.",
            });
            return;
        }

        try {
            const response = await window.snitchapi.lookupVirusTotal(lookupValue, {
                lookupType,
                apiKey,
                backendOptions: getBackendTransportOptions(),
            });
            if (currentToken !== lookupRequestToken) return;
            renderVirusTotalResult(analysis, response);
            if (response?.success === false) {
                setPanelStatus(response.error || "VirusTotal lookup failed.", true);
            }
        } catch (error) {
            if (currentToken !== lookupRequestToken) return;
            renderVirusTotalResult(analysis, {
                success: false,
                error: error?.message || "VirusTotal lookup failed.",
            });
            setPanelStatus(error?.message || "VirusTotal lookup failed.", true);
        }
    }

    async function lookupShodanInternetDb(analysis, requestToken) {
        const currentToken = requestToken;
        const cachedResult = getCachedShodanResult(analysis.lookupTargetIp);
        if (cachedResult) {
            renderShodanResult(analysis, cachedResult);
            return;
        }

        if (analysis.exposure !== "Public") {
            const unsupportedResult = {
                success: false,
                error: "Local / special-use IPs are not indexed by Shodan InternetDB.",
            };
            setCachedShodanResult(analysis.lookupTargetIp, unsupportedResult);
            renderShodanResult(analysis, unsupportedResult);
            return;
        }

        if (!window.snitchapi || typeof window.snitchapi.lookupShodan !== "function") {
            const unavailableResult = {
                success: false,
                error: "Backend Shodan lookup API is unavailable.",
            };
            setCachedShodanResult(analysis.lookupTargetIp, unavailableResult);
            renderShodanResult(analysis, unavailableResult);
            return;
        }

        const lookupIp = String(analysis.lookupTargetIp || "").trim();
        if (!lookupIp) {
            const missingIpResult = {
                success: false,
                error: "No lookup IP is available for Shodan InternetDB.",
            };
            setCachedShodanResult(analysis.lookupTargetIp, missingIpResult);
            renderShodanResult(analysis, missingIpResult);
            return;
        }

        try {
            const response = await window.snitchapi.lookupShodan(lookupIp, {
                backendOptions: getBackendTransportOptions(),
            });
            if (currentToken !== lookupRequestToken) return;

            setCachedShodanResult(lookupIp, response);
            renderShodanResult(analysis, response);
        } catch (error) {
            if (currentToken !== lookupRequestToken) return;
            const errorResult = {
                success: false,
                error: error?.message || "Shodan InternetDB lookup failed.",
            };
            setCachedShodanResult(lookupIp, errorResult);
            renderShodanResult(analysis, errorResult);
        }
    }

    async function runCaptureNmapScan({ auto = false, reason = "manual", force = false } = {}) {
        updateNmapScanButtonState();
        if (nmapScanState.inFlight) {
            let nmapRuntimeStatus = { running: true };
            if (window.snitchapi && typeof window.snitchapi.getNmapScanStatus === "function") {
                try {
                    nmapRuntimeStatus = await window.snitchapi.getNmapScanStatus();
                } catch (_error) {
                    nmapRuntimeStatus = { running: true };
                }
            }

            if (!nmapRuntimeStatus?.running) {
                nmapScanState.inFlight = false;
                nmapScanState.inFlightPromise = null;
            }
        }

        if (nmapScanState.inFlight) {
            if (!auto) {
                setPanelStatus("Nmap scan already running. Waiting for current scan to finish...");
                setPlaceholder(nmapEl, "Nmap scan already in progress. Waiting for existing results...");
            }
            if (nmapScanState.inFlightPromise) {
                await nmapScanState.inFlightPromise;
            }
            if (!auto && nmapScanState.latestScanResponse) {
                renderNmapResults(nmapScanState.latestScanResponse, getCurrentInspectedIp());
            }
            return;
        }

        if (!isNmapServiceScanEnabled()) {
            setPanelStatus("Enable Conv Subnet internet-host Nmap scans in Settings > Frontend.", true);
            renderCaptureTargets([], getCurrentInspectedIp());
            setPlaceholder(nmapEl, "Nmap scans are disabled in settings.");
            return;
        }

        const targets = getCaptureInternetTargets();
        const inspectedIp = auto ? getCurrentInspectedIp() : resolveManualScanInspectedIp(targets);
        if (!auto && inspectedIp) {
            nmapScanState.currentInspectedIp = inspectedIp;
            if (inputEl && !String(inputEl.value || "").trim()) {
                inputEl.value = inspectedIp;
            }
        }
        const scopedTargets = auto
            ? targets
            : targets.filter((entry) => String(entry?.ip || "").trim() === inspectedIp);
        const targetsKey = buildTargetsSignature(scopedTargets);
        renderCaptureTargets(targets, inspectedIp);

        if (!auto && !inspectedIp) {
            setPanelStatus("Analyze/select an IP in Subnet/IP first, then rescan that host.", true);
            setPlaceholder(nmapEl, "No inspected IP selected for host rescan.");
            return;
        }

        if (!scopedTargets.length) {
            if (!auto) {
                setPanelStatus(`No nmap targets available for inspected host ${inspectedIp}.`, true);
                setPlaceholder(nmapEl, `No observed TCP ports for inspected host ${inspectedIp}.`);
            }
            return;
        }

        const now = Date.now();
        if (!force && auto) {
            if (nmapScanState.inFlight && targetsKey === nmapScanState.lastRequestedTargetsKey) {
                return;
            }
            if (targetsKey === nmapScanState.lastCompletedTargetsKey) {
                return;
            }
            if (now - nmapScanState.lastKickoffAt < NMAP_AUTO_SCAN_MIN_INTERVAL_MS) {
                return;
            }
        }

        const currentToken = ++nmapScanToken;
        nmapScanState.inFlight = true;
        nmapScanState.lastRequestedTargetsKey = targetsKey;
        nmapScanState.lastKickoffAt = now;
        let resolveInFlightPromise = () => { };
        nmapScanState.inFlightPromise = new Promise((resolve) => {
            resolveInFlightPromise = resolve;
        });
        let finalizedInFlight = false;
        const finalizeInFlightState = () => {
            if (finalizedInFlight) return;
            finalizedInFlight = true;
            nmapScanState.inFlight = false;
            nmapScanState.inFlightPromise = null;
            resolveInFlightPromise();
        };
        if (!auto) {
            setPanelStatus(`Checking nmap installation for host ${inspectedIp}...`);
            setPlaceholder(nmapEl, "Checking nmap installation...");
        }

        let installStatus;
        try {
            installStatus = await ensureNmapInstalledCached();
        } catch (error) {
            if (currentToken !== nmapScanToken) {
                finalizeInFlightState();
                return;
            }
            finalizeInFlightState();
            if (!auto) {
                setPanelStatus(error?.message || "Unable to check nmap installation.", true);
                setPlaceholder(nmapEl, error?.message || "Unable to check nmap installation.");
            }
            return;
        }
        if (currentToken !== nmapScanToken) {
            finalizeInFlightState();
            return;
        }

        if (!installStatus?.installed) {
            const installError = installStatus?.error || "nmap is not installed or not in PATH.";
            finalizeInFlightState();
            if (!auto) {
                setPanelStatus(installError, true);
                setPlaceholder(nmapEl, installError);
                statusUpdate(`Status: ${installError}`);
            }
            writeLogEntry(`Conv subnet nmap pre-check failed error=${JSON.stringify(installError)}`);
            return;
        }

        if (!auto) {
            setPanelStatus(`Running nmap -sV on inspected host ${inspectedIp}...`);
            setPlaceholder(nmapEl, "Running nmap service scans. This may take a while...");
        } else {
            writeLogEntry(
                `Conv subnet nmap auto-scan started reason=${JSON.stringify(reason)} targets=${scopedTargets.length}`,
            );
        }

        const requestTargets = scopedTargets.map((entry) => ({
            ip: entry.ip,
            ports: entry.ports,
        }));

        const scanPromise = (async () => {
            try {
                const scanResponse = await window.snitchapi.runNmapServiceScan(requestTargets, {
                    timeoutMs: 120000,
                });
                if (currentToken !== nmapScanToken) return;
                nmapScanState.latestScanResponse = scanResponse;
                if (scanResponse?.success) {
                    nmapScanState.lastCompletedTargetsKey = targetsKey;
                }
                renderNmapResults(scanResponse, getCurrentInspectedIp());

                if (!scanResponse?.success) {
                    const errorMessage = scanResponse?.error || "Nmap scan did not return findings.";
                    if (!auto) {
                        setPanelStatus(errorMessage, true);
                        statusUpdate(`Status: ${errorMessage}`);
                    }
                    writeLogEntry(`Conv subnet nmap scan failed error=${JSON.stringify(errorMessage)}`);
                    return;
                }

                const scannedHosts = Array.isArray(scanResponse.results)
                    ? scanResponse.results.filter((entry) => entry?.success).length
                    : 0;
                const outputPaths = Array.isArray(scanResponse.results)
                    ? scanResponse.results
                        .map((entry) => String(entry?.xmlPath || "").trim())
                        .filter(Boolean)
                    : [];
                if (!auto) {
                    setPanelStatus(`Nmap service scan complete. Scanned ${scannedHosts}/${requestTargets.length} hosts.`);
                    statusUpdate(`Status: Nmap service scan complete (${scannedHosts}/${requestTargets.length} hosts)`);
                }
                writeLogEntry(
                    `Conv subnet nmap scan complete auto=${auto} scanned=${scannedHosts}/${requestTargets.length} xml=${JSON.stringify(outputPaths)}`,
                );
            } catch (error) {
                if (currentToken !== nmapScanToken) return;
                const message = error?.message || "Nmap scan failed.";
                if (!auto) {
                    setPanelStatus(message, true);
                    statusUpdate(`Status: ${message}`);
                    setPlaceholder(nmapEl, message);
                }
                writeLogEntry(`Conv subnet nmap scan threw error=${JSON.stringify(message)}`);
            } finally {
                finalizeInFlightState();
            }
        })();

        await scanPromise;
    }

    function maybeAutoStartCaptureNmapScan(progressInfo = {}) {
        if (!isNmapServiceScanEnabled()) {
            return;
        }
        const processedPackets = Number(progressInfo?.processedPackets) || 0;
        const complete = Boolean(progressInfo?.complete);
        if (!complete && processedPackets <= 0) {
            return;
        }
        void runCaptureNmapScan({
            auto: true,
            reason: progressInfo?.reason || "backend-progress",
            force: false,
        });
    }

    function maybeKickoffNmapOnTabOpen() {
        if (!isNmapServiceScanEnabled()) {
            return;
        }
        if (nmapScanState.inFlight) {
            return;
        }

        const targets = getCaptureInternetTargets();
        if (!targets.length) {
            return;
        }

        const inspectedIp = getCurrentInspectedIp() || resolveManualScanInspectedIp(targets);
        if (inspectedIp) {
            nmapScanState.currentInspectedIp = inspectedIp;
        }

        const latestResults = Array.isArray(nmapScanState.latestScanResponse?.results)
            ? nmapScanState.latestScanResponse.results
            : [];
        const hasAnyOutput = latestResults.length > 0;
        const hasInspectedOutput = inspectedIp
            ? latestResults.some((entry) => String(entry?.ip || "").trim() === inspectedIp)
            : hasAnyOutput;

        if (hasAnyOutput && hasInspectedOutput) {
            renderCaptureTargets(targets, inspectedIp);
            renderNmapResults(nmapScanState.latestScanResponse, inspectedIp);
            return;
        }

        void runCaptureNmapScan({
            auto: true,
            reason: "subnet-tab-open",
            force: false,
        });
    }

    function maybeKickoffThreatIntelOnTabOpen() {
        const saved = getSessionState();
        const inspectedIp = String(nmapScanState.currentInspectedIp || saved?.analyzedIp || "").trim();
        const cachedInput = String(threatIntelInputEl?.value || saved?.threatIntel?.input || "").trim();

        if (cachedInput) {
            // A prior query is available: refresh the display with cached results.
            renderThreatIntelResult({ lookupTargetIp: nmapScanState.currentInspectedIp });
            return;
        }

        if (inspectedIp && !threatIntelInputEl?.value) {
            // No explicit TI query yet, but an analyzed IP exists; seed the input.
            if (threatIntelTypeEl) threatIntelTypeEl.value = "ip";
            if (threatIntelInputEl) threatIntelInputEl.value = inspectedIp;
            return;
        }

        // Fall back to rendering whatever cached state we have (may be empty placeholder).
        renderThreatIntelResult({ lookupTargetIp: nmapScanState.currentInspectedIp });
    }

    function resetCaptureNmapState() {
        nmapScanToken += 1;
        nmapScanState.inFlight = false;
        nmapScanState.lastRequestedTargetsKey = "";
        nmapScanState.lastCompletedTargetsKey = "";
        nmapScanState.lastKickoffAt = 0;
        nmapScanState.latestScanResponse = null;
        nmapScanState.installStatus = null;
        nmapScanState.lastInstallCheckAt = 0;
        nmapScanState.inFlightPromise = null;
        nmapScanState.currentInspectedIp = "";
        updateNmapScanButtonState();
        renderCaptureTargets(getCaptureInternetTargets(), "");
        setPlaceholder(nmapEl, "Nmap scan status for the selected host will appear here.");
    }

    async function analyzeCurrentInput() {
        try {
            const analysis = analyzeSubnetInput(inputEl?.value || "");
            nmapScanState.currentInspectedIp = String(analysis.lookupTargetIp || analysis.address || "").trim();
            const requestToken = ++lookupRequestToken;
            threatIntelState = { ipsum: null, tor: null, virustotal: null };
            if (threatIntelTypeEl) {
                threatIntelTypeEl.value = "ip";
            }
            if (threatIntelInputEl) {
                threatIntelInputEl.value = String(analysis.lookupTargetIp || analysis.address || "");
            }
            renderAnalysisResults(analysis);
            renderCaptureTargets(getCaptureInternetTargets(), nmapScanState.currentInspectedIp);
            if (nmapScanState.latestScanResponse) {
                renderNmapResults(nmapScanState.latestScanResponse, nmapScanState.currentInspectedIp);
            } else {
                setPlaceholder(nmapEl, `Nmap scan status for ${nmapScanState.currentInspectedIp} will appear here.`);
            }
            setPanelStatus(`Analyzing ${analysis.normalizedInput}...`);
            statusUpdate(`Status: Calculated subnet data for ${analysis.address}`);
            writeLogEntry(`Conv subnet calculator analyzed ${JSON.stringify(analysis.normalizedInput)}`);
            await Promise.all([
                lookupGeoip(analysis, requestToken),
                lookupWhois(analysis, requestToken),
                lookupIpsum(analysis, requestToken),
                lookupTor(analysis, requestToken),
                lookupVirusTotalForInput(
                    analysis,
                    requestToken,
                    String(analysis.lookupTargetIp || analysis.address || ""),
                    "ip",
                ),
                lookupShodanInternetDb(analysis, requestToken),
            ]);
            if (requestToken !== lookupRequestToken) return;
            setPanelStatus(`Analyzed ${analysis.normalizedInput}`);
        } catch (error) {
            renderEmptyState();
            const message = error?.message || String(error);
            setPanelStatus(message, true);
            statusUpdate(`Status: ${message}`);
        }
    }

    function loadCurrentPacketAddress(side) {
        const packetIps = getCurrentPacketIps() || {};
        const value = side === "dst" ? packetIps.dst : packetIps.src;
        if (!value) {
            const message = `No current packet ${side === "dst" ? "destination" : "source"} IP is available.`;
            setPanelStatus(message, true);
            statusUpdate(`Status: ${message}`);
            return;
        }
        if (inputEl) {
            inputEl.value = value;
        }
        nmapScanState.currentInspectedIp = String(value || "").trim();
        renderCaptureTargets(getCaptureInternetTargets(), nmapScanState.currentInspectedIp);
        if (nmapScanState.latestScanResponse) {
            renderNmapResults(nmapScanState.latestScanResponse, nmapScanState.currentInspectedIp);
        }
        setPanelStatus(`Loaded current packet ${side === "dst" ? "destination" : "source"} IP.`);
        void analyzeCurrentInput();
    }

    function clear() {
        lookupRequestToken += 1;
        nmapScanToken += 1;
        threatIntelState = { ipsum: null, tor: null, virustotal: null };
        nmapScanState.currentInspectedIp = "";
        if (inputEl) {
            inputEl.value = "";
        }
        if (threatIntelInputEl) {
            threatIntelInputEl.value = "";
        }
        if (threatIntelTypeEl) {
            threatIntelTypeEl.value = "ip";
        }
        renderEmptyState();
        setPanelStatus("Enter an IPv4 or IPv6 address/network to analyze.");
    }

    function lookupThreatIntelFromManualInput() {
        const lookupValue = getThreatIntelQueryInputValue();
        if (!lookupValue) {
            setPanelStatus("Enter an IP, URL, or hash for Threat Intel lookup.", true);
            return;
        }
        const requestToken = ++lookupRequestToken;
        const analysis = {
            lookupTargetIp: String(nmapScanState.currentInspectedIp || "").trim() || lookupValue,
        };
        void lookupVirusTotalForInput(
            analysis,
            requestToken,
            lookupValue,
            getThreatIntelQueryTypeValue(),
        );
    }

    function runThreatIntelHashLookup(hashValue) {
        const trimmedValue = String(hashValue || "").trim();
        if (!trimmedValue) {
            setPanelStatus("Enter a hash value to cross-reference.", true);
            return;
        }
        if (threatIntelTypeEl) {
            threatIntelTypeEl.value = "hash";
        }
        if (threatIntelInputEl) {
            threatIntelInputEl.value = trimmedValue;
        }
        const requestToken = ++lookupRequestToken;
        const analysis = {
            lookupTargetIp: trimmedValue,
        };
        void lookupVirusTotalForInput(analysis, requestToken, trimmedValue, "hash");
    }

    function renderEmptyState() {
        updateNmapScanButtonState();
        setPlaceholder(summaryEl, "Enter an IP address, host/prefix, or subnet to inspect.");
        setPlaceholder(rangeEl, "Range details will appear here.");
        setPlaceholder(binaryEl, "Binary notation will appear here.");
        setPlaceholder(whoisEl, "WHOIS / RDAP data will appear here.");
        setPlaceholder(geoEl, "GeoIP data will appear here.");
        setPlaceholder(shodanEl, "Shodan InternetDB data will appear here.");
        renderCaptureTargets(getCaptureInternetTargets(), getCurrentInspectedIp());
        if (nmapScanState.latestScanResponse) {
            renderNmapResults(nmapScanState.latestScanResponse, getCurrentInspectedIp());
        } else {
            setPlaceholder(nmapEl, "Nmap scan status for the selected host will appear here.");
        }
    }

    document.getElementById("subnet-calc-analyze-btn")?.addEventListener("click", () => {
        void analyzeCurrentInput();
    });
    document.getElementById("subnet-calc-clear-btn")?.addEventListener("click", clear);
    document.getElementById("subnet-calc-use-src-btn")?.addEventListener("click", () => {
        loadCurrentPacketAddress("src");
    });
    document.getElementById("subnet-calc-use-dst-btn")?.addEventListener("click", () => {
        loadCurrentPacketAddress("dst");
    });
    threatIntelUseAnalyzedIpBtnEl?.addEventListener("click", () => {
        const inspectedIp = String(nmapScanState.currentInspectedIp || "").trim()
            || String(inputEl?.value || "").trim();
        if (!inspectedIp) {
            setPanelStatus("Analyze an IP first to use analyzed target.", true);
            return;
        }
        if (threatIntelTypeEl) {
            threatIntelTypeEl.value = "ip";
        }
        if (threatIntelInputEl) {
            threatIntelInputEl.value = inspectedIp;
        }
        setPanelStatus(`Threat Intel query target set to ${inspectedIp}`);
    });
    threatIntelLookupBtnEl?.addEventListener("click", () => {
        lookupThreatIntelFromManualInput();
    });
    nmapScanBtnEl?.addEventListener("click", () => {
        void runCaptureNmapScan({ auto: false, reason: "manual-button", force: true });
    });
    inputEl?.addEventListener("keydown", (event) => {
        if (event.key === "Enter") {
            event.preventDefault();
            void analyzeCurrentInput();
        }
    });
    threatIntelInputEl?.addEventListener("keydown", (event) => {
        if (event.key === "Enter") {
            event.preventDefault();
            lookupThreatIntelFromManualInput();
        }
    });

    renderEmptyState();
    setPanelStatus("Enter an IPv4 or IPv6 address/network to analyze.");

    return {
        analyzeCurrentInput,
        clear,
        getSessionState,
        loadCurrentPacketAddress,
        maybeAutoStartCaptureNmapScan,
        maybeKickoffNmapOnTabOpen,
        maybeKickoffThreatIntelOnTabOpen,
        resetSessionCacheState,
        resetCaptureNmapState,
        restoreSessionState,
        runThreatIntelHashLookup,
    };
}

module.exports = {
    createSubnetCalculatorPanel,
};