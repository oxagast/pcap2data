// Lightweight background LLM summarization for the Conv/Data Tools workspace.
// This module is designed to be imported by both data-tools-panel.js and
// main-frontend.js so the same summarization behavior can be driven from the
// panel or from global UI actions.

const SUMMARY_MAX_INPUT_CHARS = 12000;
const SUMMARY_MAX_OUTPUT_CHARS = 6000;

let _callLlmFn = null;
let _isLlmRuntimeEnabledFn = null;
let _isBackgroundEnabledFn = null;
let _statusUpdateFn = null;
let _writeLogEntryFn = null;
let _appendAnalysisBlubFn = null;

let lastSummaryInputHash = "";
let lastSummaryText = "";

// Up to two LLM summary requests may be in flight at once. New requests that
// would exceed the limit are queued and started when a slot frees up.
const MAX_IN_FLIGHT_SUMMARIES = 2;
const inFlightSummaryControllers = new Map();
let pendingSummaryQueue = [];
let summarySequence = 0;

// Initialize the summarizer with required callbacks.
function initDataToolsLlmSummarizer({
    callLargeLanguageModel,
    isLlmRuntimeEnabled,
    isBackgroundSummaryGenerationEnabled,
    statusUpdate,
    writeLogEntry,
    appendAnalysisBlub,
}) {
    _callLlmFn = callLargeLanguageModel;
    _isLlmRuntimeEnabledFn = isLlmRuntimeEnabled;
    _isBackgroundEnabledFn = isBackgroundSummaryGenerationEnabled;
    _statusUpdateFn = statusUpdate;
    _writeLogEntryFn = writeLogEntry;
    _appendAnalysisBlubFn = appendAnalysisBlub || null;
}

function _isEnabled() {
    return (
        typeof _isBackgroundEnabledFn === "function" &&
        _isBackgroundEnabledFn() &&
        typeof _isLlmRuntimeEnabledFn === "function" &&
        _isLlmRuntimeEnabledFn()
    );
}

function _hashInput(input) {
    // Fast, collision-resistant-enough hash for debounce comparison.
    let h = 0;
    for (let i = 0; i < input.length; i += 1) {
        h = (h << 5) - h + input.charCodeAt(i);
        h |= 0;
    }
    return String(h);
}

function _hashSummaryContext(context) {
    return _hashInput(JSON.stringify(context || {}));
}

function getCurrentSummaryContext(activeSubtab) {
    return _collectSummaryContext(activeSubtab);
}

function getCurrentSummaryContextHash(activeSubtab) {
    return _hashSummaryContext(_collectSummaryContext(activeSubtab));
}

function _truncate(str, maxLength) {
    if (str.length <= maxLength) return str;
    return str.slice(0, maxLength) + "\n\n[TRUNCATED]";
}

function _setInsightStatus(status) {
    const statusEl = document.getElementById("data-tools-llm-status");
    if (statusEl) statusEl.textContent = `Status: ${status}`;
}

function _setInsightSummary(text) {
    const summaryEl = document.getElementById("data-tools-llm-summary");
    const sectionEl = document.getElementById("data-tools-llm-insights");
    if (summaryEl) {
        summaryEl.textContent = text || "No summary yet.";
    }
    if (sectionEl) {
        sectionEl.hidden = !text;
    }
}

function _showError(message) {
    _setInsightStatus(`error — ${message}`);
    if (typeof _writeLogEntryFn === "function") {
        _writeLogEntryFn(`[DataToolsLLM] Summary failed: ${message}`);
    }
}

function _buildDataToolsSummaryPrompt(context) {
    return [
        "You are PacketSnitch, a network-data analysis assistant.",
        "Summarize the current Conv/Data Tools workspace data for an analyst.",
        "Use only the provided input and outputs. Do not invent values.",
        "Return clean Markdown. Keep the response concise (2-4 short paragraphs or bullet lists) and include each key fact only once.",
        "Do not repeat or rephrase the same observation; prefer omitting redundant wording over padding the summary.",
        "",
        "SQUELCH NO-OP DATA: do NOT report entries that produced no usable output. If a decoder was opened but failed, returned an error, decoded to nothing, or only produced placeholder/empty content, omit it entirely instead of describing what it did not find. The same applies to empty hash fields, blank conversions, no-op extraction results, and failed subnet/whois/geoip lookups. Only describe operations that actually surfaced data. Silence is preferable to a paragraph that just says 'nothing was found'.",
        "",
        "Workspace context (JSON):",
        JSON.stringify({ ...context, timestamp: new Date().toISOString() }, null, 2),
    ].join("\n");
}

function _collectConversionContext() {
    const inputEl = document.getElementById("data-tools-input");
    const formatEl = document.getElementById("data-tools-format");
    return {
        subtab: "conversions",
        format: formatEl?.value || "unknown",
        inputPreview: _truncate(String(inputEl?.value || "").replace(/\s+/g, " "), 4000),
        hex: _truncate(String(document.getElementById("data-tools-hex-output")?.value || ""), 2000),
        ascii: _truncate(String(document.getElementById("data-tools-ascii-output")?.value || ""), 2000),
        base64: _truncate(String(document.getElementById("data-tools-base64-output")?.value || ""), 1500),
        byteLength: document.getElementById("data-tools-byte-length")?.textContent || "Byte Length: 0",
        mimeType: document.getElementById("data-tools-mime-type")?.textContent || "MIME Type: Unknown",
        entropy: document.getElementById("data-tools-entropy")?.textContent || "Shannon Entropy: 0.00 (Low)",
        dataTypeGuesses: document.getElementById("data-tools-data-type-guesses")?.textContent || "None",
    };
}

function _collectHashesContext() {
    return {
        subtab: "hashes",
        md5: document.getElementById("data-tools-md5-output")?.value || "",
        sha1: document.getElementById("data-tools-sha1-output")?.value || "",
        sha256: document.getElementById("data-tools-sha256-output")?.value || "",
        sha512: document.getElementById("data-tools-sha512-output")?.value || "",
    };
}

function _tableToText(tableEl) {
    if (!tableEl) return "";
    const rows = [];
    tableEl.querySelectorAll("tr").forEach((tr) => {
        const cells = Array.from(tr.querySelectorAll("td, th"))
            .map((cell) => cell.textContent.trim())
            .filter((text) => text.length > 0);
        if (cells.length) rows.push(cells.join(": "));
    });
    return rows.join("\n");
}

function _collectProtoDecoderContext() {
    const protoOutput = document.getElementById("data-tools-proto-output");
    const selectedProtocol =
        document.getElementById("data-tools-proto-select")?.value || "auto";
    let decodedText = "";
    let tableText = "";
    let structuredTreeText = "";
    if (protoOutput) {
        decodedText = protoOutput.innerText || "";
        const table = protoOutput.querySelector("table.data-tools-proto-table");
        tableText = _tableToText(table);
        const structuredTree = protoOutput.querySelector(".data-tools-structured-tree");
        if (structuredTree) {
            structuredTreeText = _truncate(structuredTree.innerText || "", 4000);
        }
    }
    return {
        subtab: "decodes",
        selectedProtocol,
        decodedPreview: _truncate(decodedText, 6000),
        decodedTable: _truncate(tableText, 4000),
        structuredTree: structuredTreeText,
    };
}

function _collectExtractionContext() {
    const inputEl = document.getElementById("data-tools-input");
    const formatEl = document.getElementById("data-tools-format");
    const detectEl = document.getElementById("data-tools-extraction-detect-value");
    const tree = document.getElementById("data-tools-extraction-tree");
    const preview = document.getElementById("data-tools-extraction-preview");
    const outputText = document.getElementById("data-tools-extraction-output-text");
    const outputHex = document.getElementById("data-tools-extraction-output-hex");
    const error = document.getElementById("data-tools-extraction-error");
    let archiveText = "";
    if (tree) {
        const items = tree.querySelectorAll(".data-tools-extraction-tree-item");
        archiveText = Array.from(items)
            .map((item) => item.innerText.trim())
            .join("\n");
    }
    return {
        subtab: "extraction",
        format: formatEl?.value || "unknown",
        inputPreview: _truncate(String(inputEl?.value || "").replace(/\s+/g, " "), 2000),
        detectedFormat: detectEl?.textContent || "None / unknown",
        archiveTree: _truncate(archiveText, 4000),
        previewText: _truncate(preview?.innerText || "", 2000),
        outputText: _truncate(outputText?.value || "", 2000),
        outputHex: _truncate(outputHex?.textContent || "", 1500),
        error: _truncate(error?.textContent || "", 1000),
    };
}

function _collectSubnetContext() {
    const inputEl = document.getElementById("subnet-calc-input");
    const summary = document.getElementById("subnet-calc-summary");
    const range = document.getElementById("subnet-calc-range");
    const binary = document.getElementById("subnet-calc-binary");
    const whois = document.getElementById("subnet-calc-whois");
    const geo = document.getElementById("subnet-calc-geo");
    const shodan = document.getElementById("subnet-calc-shodan");
    const nmap = document.getElementById("subnet-calc-nmap");
    return {
        subtab: "subnet",
        input: _truncate(String(inputEl?.value || "").replace(/\s+/g, " "), 2000),
        summary: _truncate(_tableToText(summary?.querySelector("table")) || (summary?.innerText || ""), 3000),
        range: _truncate(_tableToText(range?.querySelector("table")) || (range?.innerText || ""), 3000),
        binary: _truncate(_tableToText(binary?.querySelector("table")) || (binary?.innerText || ""), 2000),
        whois: _truncate(_tableToText(whois?.querySelector("table")) || (whois?.innerText || ""), 3000),
        geoip: _truncate(_tableToText(geo?.querySelector("table")) || (geo?.innerText || ""), 3000),
        shodan: _truncate(_tableToText(shodan?.querySelector("table")) || (shodan?.innerText || ""), 3000),
        nmap: _truncate(nmap?.innerText || "", 3000),
    };
}

function _collectThreatIntelContext() {
    const typeEl = document.getElementById("subnet-ti-type");
    const inputEl = document.getElementById("subnet-ti-input");
    const ipsum = document.getElementById("subnet-calc-reputation-ipsum");
    const virustotal = document.getElementById("subnet-calc-reputation-virustotal");
    const tor = document.getElementById("subnet-calc-reputation-tor");
    return {
        subtab: "threat-intel",
        queryType: typeEl?.value || "ip",
        input: _truncate(String(inputEl?.value || "").replace(/\s+/g, " "), 2000),
        ipsum: _truncate(_tableToText(ipsum?.querySelector("table")) || (ipsum?.innerText || ""), 3000),
        virustotal: _truncate(_tableToText(virustotal?.querySelector("table")) || (virustotal?.innerText || ""), 3000),
        tor: _truncate(_tableToText(tor?.querySelector("table")) || (tor?.innerText || ""), 3000),
    };
}

function _collectPacketJsonContext() {
    const inputEl = document.getElementById("data-tools-input");
    const formatEl = document.getElementById("data-tools-format");
    const currentPacket = document.getElementById("data-tools-packet-json-current-packet");
    const output = document.getElementById("data-tools-packet-json-output");
    return {
        subtab: "packet-json",
        format: formatEl?.value || "unknown",
        inputPreview: _truncate(String(inputEl?.value || "").replace(/\s+/g, " "), 2000),
        currentPacket: _truncate(currentPacket?.textContent || "", 500),
        packetJson: _truncate(output?.innerText || "", 8000),
    };
}

function _collectSummaryContext(activeSubtab) {
    // Note: the hash used for duplicate suppression is computed from this
    // object, so only include stable workspace data here. Do not add
    // timestamps or other volatile fields.
    switch (activeSubtab) {
        case "conversions":
            return { activeSubtab, ..._collectConversionContext() };
        case "extraction":
            return { activeSubtab, ..._collectExtractionContext() };
        case "packet-json":
            return { activeSubtab, ..._collectPacketJsonContext() };
        case "hashes":
            return { activeSubtab, ..._collectHashesContext() };
        case "decodes":
            return { activeSubtab, ..._collectProtoDecoderContext() };
        case "subnet":
            return { activeSubtab, ..._collectSubnetContext() };
        case "threat-intel":
            return { activeSubtab, ..._collectThreatIntelContext() };
        default:
            return { activeSubtab, ..._collectConversionContext(), subtab: activeSubtab };
    }
}

async function _runSummaryRequest(activeSubtab, sequence, signal) {
    if (!_isEnabled()) {
        _setInsightStatus("disabled");
        return;
    }
    if (typeof _callLlmFn !== "function") {
        _showError("LLM callback is not configured");
        return;
    }

    const context = _collectSummaryContext(activeSubtab);
    const prompt = _truncate(
        _buildDataToolsSummaryPrompt(context),
        SUMMARY_MAX_INPUT_CHARS,
    );

    _setInsightStatus("summarizing...");
    if (typeof _statusUpdateFn === "function") {
        _statusUpdateFn("Status: PacketSnitch is analyzing Data Tools data...");
    }
    if (typeof _writeLogEntryFn === "function") {
        _writeLogEntryFn(`[DataToolsLLM] Summary requested for subtab=${activeSubtab} seq=${sequence}`);
    }

    try {
        const response = await _callLlmFn(prompt, { signal });
        if (signal?.aborted) return;
        const text = String(response?.response || "").trim();
        if (!text) {
            _setInsightStatus("no summary returned");
            if (typeof _writeLogEntryFn === "function") {
                _writeLogEntryFn(`[DataToolsLLM] No summary returned for subtab=${activeSubtab}`);
            }
            return;
        }
        lastSummaryText = _truncate(text, SUMMARY_MAX_OUTPUT_CHARS);
        _setInsightSummary(lastSummaryText);
        _setInsightStatus("ready");
        if (typeof _statusUpdateFn === "function") {
            _statusUpdateFn("Status: Data Tools LLM insight ready.");
        }
        if (typeof _writeLogEntryFn === "function") {
            _writeLogEntryFn(
                `[DataToolsLLM] Summary complete subtab=${activeSubtab} seq=${sequence} chars=${lastSummaryText.length}`,
            );
        }
        if (typeof _appendAnalysisBlubFn === "function" && lastSummaryText) {
            _appendAnalysisBlubFn(lastSummaryText);
        }
    } catch (error) {
        if (signal?.aborted) return;
        const message = error?.message || String(error);
        _showError(message);
        _setInsightSummary("");
    }
}

function _startNextQueuedSummary() {
    while (inFlightSummaryControllers.size < MAX_IN_FLIGHT_SUMMARIES && pendingSummaryQueue.length > 0) {
        const next = pendingSummaryQueue.shift();
        if (!next) continue;
        const controller = new AbortController();
        const id = next.sequence;
        inFlightSummaryControllers.set(id, controller);
        next.controller = controller;
        void _runSummaryRequest(next.activeSubtab, id, controller.signal).finally(() => {
            inFlightSummaryControllers.delete(id);
            _startNextQueuedSummary();
        });
    }
}

// Request a background summary for the given active Conv subtab.
// Requests are sent immediately (no debounce), but duplicate context is
// suppressed via the input-hash cache. At most two LLM requests are kept in
// flight; additional requests queue until a slot frees up.
function requestDataToolsBackgroundSummary(activeSubtab = "conversions") {
    if (!_isEnabled()) {
        _setInsightStatus("disabled");
        _setInsightSummary("");
        return;
    }

    const context = _collectSummaryContext(activeSubtab);
    const inputHash = _hashInput(JSON.stringify(context));
    if (inputHash === lastSummaryInputHash && lastSummaryText) {
        _setInsightStatus("ready (cached)");
        _setInsightSummary(lastSummaryText);
        return;
    }

    lastSummaryInputHash = inputHash;
    const sequence = ++summarySequence;
    pendingSummaryQueue.push({ activeSubtab, sequence });
    _startNextQueuedSummary();
}

function _abortInFlightSummaries() {
    for (const controller of inFlightSummaryControllers.values()) {
        try {
            controller.abort();
        } catch (_error) {
            // ignore
        }
    }
    inFlightSummaryControllers.clear();
    pendingSummaryQueue = [];
}

function clearDataToolsSummary() {
    _abortInFlightSummaries();
    lastSummaryInputHash = "";
    lastSummaryText = "";
    _setInsightStatus("idle");
    _setInsightSummary("");
}

module.exports = {
    initDataToolsLlmSummarizer,
    requestDataToolsBackgroundSummary,
    clearDataToolsSummary,
    getCurrentSummaryContext,
    getCurrentSummaryContextHash,
};
