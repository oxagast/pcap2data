const IPV4_HOST_BITS = 32;
const IPV6_HOST_BITS = 128;

function createSubnetCalculatorPanel({
    statusUpdate = () => { },
    writeLogEntry = () => { },
    getBackendTransportOptions = () => ({}),
    openHeatmapLocation = () => { },
    getCurrentPacketIps = () => ({ src: "", dst: "" }),
} = {}) {
    let lookupRequestToken = 0;

    const inputEl = document.getElementById("subnet-calc-input");
    const statusEl = document.getElementById("subnet-calc-status");
    const summaryEl = document.getElementById("subnet-calc-summary");
    const rangeEl = document.getElementById("subnet-calc-range");
    const binaryEl = document.getElementById("subnet-calc-binary");
    const whoisEl = document.getElementById("subnet-calc-whois");
    const reputationEl = document.getElementById("subnet-calc-reputation");
    const geoEl = document.getElementById("subnet-calc-geo");
    let threatIntelState = {
        ipsum: null,
        tor: null,
    };

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
        container.appendChild(titleEl);

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
        setPlaceholder(reputationEl, "Looking up Threat Intelligence data...");
        setPlaceholder(geoEl, "Looking up GeoIP data...");
    }

    function renderThreatIntelResult(analysis) {
        if (!reputationEl) return;
        reputationEl.innerHTML = "";
        const titleEl = document.createElement("div");
        titleEl.className = "data-tools-output-label subnet-calc-section-title";
        titleEl.textContent = "Threat Intelligence";
        reputationEl.appendChild(titleEl);

        const ipsumResult = threatIntelState.ipsum;
        const torResult = threatIntelState.tor;
        if (!ipsumResult && !torResult) {
            setPlaceholder(reputationEl, "Threat intelligence data will appear here.");
            return;
        }

        if (ipsumResult) {
            const ipsumSection = document.createElement("div");
            if (ipsumResult.success === false) {
                setPlaceholder(ipsumSection, ipsumResult.error || "IP reputation lookup failed.");
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

                renderKeyValueTable(ipsumSection, "IPSum", rows);
            }
            reputationEl.appendChild(ipsumSection);
        }

        if (torResult) {
            const torSection = document.createElement("div");
            if (torResult.success === false) {
                setPlaceholder(torSection, torResult.error || "Tor lookup failed.");
            } else {
                const rows = [
                    { name: "Lookup Target", value: torResult.ip || analysis.lookupTargetIp },
                    { name: "Exit Node", value: torResult.isExitNode ? "Yes" : "No" },
                    { name: "Matched Nodes", value: String(torResult.nodeCount || 0) },
                    { name: "Dataset Fetch Date", value: String(torResult.fetchedDate || "Unknown") },
                ];

                if (Array.isArray(torResult.nodes) && torResult.nodes.length > 0) {
                    torResult.nodes.forEach((node, index) => {
                        rows.push({ name: `Node ${index + 1} Nickname`, value: String(node.nickname || "Unknown") });
                        rows.push({ name: `Node ${index + 1} Platform`, value: String(node.platform || "Unknown") });
                    });
                }

                renderKeyValueTable(torSection, "Tor", rows);
            }
            reputationEl.appendChild(torSection);
        }

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
        addLinkButton("Open IPSum project", "https://github.com/stamparm/ipsum");
        addLinkButton("Open Tor Project", "https://www.torproject.org/");
        reputationEl.appendChild(actionRow);
    }

    function renderIpsumResult(analysis, reputationResult) {
        threatIntelState.ipsum = reputationResult;
        renderThreatIntelResult(analysis);
    }

    function renderTorResult(analysis, torResult) {
        threatIntelState.tor = torResult;
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
        if (!window.snitchapi || typeof window.snitchapi.lookupWhois !== "function") {
            renderWhoisResult(analysis, {
                success: false,
                error: "Backend WHOIS lookup API is unavailable.",
            });
            return;
        }

        try {
            const result = await window.snitchapi.lookupWhois(analysis.lookupTargetIp, {
                backendOptions: getBackendTransportOptions(),
            });
            if (currentToken !== lookupRequestToken) return;
            renderWhoisResult(analysis, result);
            if (result?.success === false) {
                setPanelStatus(result.error || "WHOIS lookup failed.", true);
            }
        } catch (error) {
            if (currentToken !== lookupRequestToken) return;
            renderWhoisResult(analysis, {
                success: false,
                error: error?.message || "WHOIS lookup failed.",
            });
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

    async function analyzeCurrentInput() {
        try {
            const analysis = analyzeSubnetInput(inputEl?.value || "");
            const requestToken = ++lookupRequestToken;
            threatIntelState = { ipsum: null, tor: null };
            renderAnalysisResults(analysis);
            setPanelStatus(`Analyzing ${analysis.normalizedInput}...`);
            statusUpdate(`Status: Calculated subnet data for ${analysis.address}`);
            writeLogEntry(`Conv subnet calculator analyzed ${JSON.stringify(analysis.normalizedInput)}`);
            await Promise.all([
                lookupGeoip(analysis, requestToken),
                lookupWhois(analysis, requestToken),
                lookupIpsum(analysis, requestToken),
                lookupTor(analysis, requestToken),
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
        setPanelStatus(`Loaded current packet ${side === "dst" ? "destination" : "source"} IP.`);
        void analyzeCurrentInput();
    }

    function clear() {
        lookupRequestToken += 1;
        if (inputEl) {
            inputEl.value = "";
        }
        renderEmptyState();
        setPanelStatus("Enter an IPv4 or IPv6 address/network to analyze.");
    }

    function renderEmptyState() {
        setPlaceholder(summaryEl, "Enter an IP address, host/prefix, or subnet to inspect.");
        setPlaceholder(rangeEl, "Range details will appear here.");
        setPlaceholder(binaryEl, "Binary notation will appear here.");
        setPlaceholder(whoisEl, "WHOIS / RDAP data will appear here.");
        setPlaceholder(reputationEl, "Threat intelligence data will appear here.");
        setPlaceholder(geoEl, "GeoIP data will appear here.");
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
    inputEl?.addEventListener("keydown", (event) => {
        if (event.key === "Enter") {
            event.preventDefault();
            void analyzeCurrentInput();
        }
    });

    renderEmptyState();
    setPanelStatus("Enter an IPv4 or IPv6 address/network to analyze.");

    return {
        analyzeCurrentInput,
        clear,
        loadCurrentPacketAddress,
    };
}

module.exports = {
    createSubnetCalculatorPanel,
};