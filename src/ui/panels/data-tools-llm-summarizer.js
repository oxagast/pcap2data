// Lightweight background LLM summarization for the Conv/Data Tools workspace.
// This module is designed to be imported by both data-tools-panel.js and
// main-frontend.js so the same summarization behavior can be driven from the
// panel or from global UI actions.

const SUMMARY_MAX_INPUT_CHARS = 12000;
const SUMMARY_MAX_OUTPUT_CHARS = 6000;
const SUMMARY_DEBOUNCE_MS = 900;

let _callLlmFn = null;
let _isLlmRuntimeEnabledFn = null;
let _isBackgroundEnabledFn = null;
let _statusUpdateFn = null;
let _writeLogEntryFn = null;

let pendingSummaryTimeout = null;
let lastSummaryInputHash = "";
let lastSummaryText = "";
let activeSummaryController = null;

// Initialize the summarizer with required callbacks.
function initDataToolsLlmSummarizer({
    callLargeLanguageModel,
    isLlmRuntimeEnabled,
    isBackgroundSummaryGenerationEnabled,
    statusUpdate,
    writeLogEntry,
}) {
    _callLlmFn = callLargeLanguageModel;
    _isLlmRuntimeEnabledFn = isLlmRuntimeEnabled;
    _isBackgroundEnabledFn = isBackgroundSummaryGenerationEnabled;
    _statusUpdateFn = statusUpdate;
    _writeLogEntryFn = writeLogEntry;
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
        "Return clean Markdown. Keep the response concise (2-4 short paragraphs or bullet lists).",
        "",
        "Workspace context (JSON):",
        JSON.stringify(context, null, 2),
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

function _collectProtoDecoderContext() {
    const protoOutput = document.getElementById("data-tools-proto-output");
    const selectedProtocol =
        document.getElementById("data-tools-protocol-select")?.value || "auto";
    let decodedText = "";
    if (protoOutput) {
        decodedText = protoOutput.innerText || "";
    }
    return {
        subtab: "decodes",
        selectedProtocol,
        decodedPreview: _truncate(decodedText, 6000),
    };
}

function _collectSummaryContext(activeSubtab) {
    const base = {
        activeSubtab,
        timestamp: new Date().toISOString(),
    };
    switch (activeSubtab) {
        case "conversions":
        case "extraction":
        case "packet-json":
            return { ...base, ..._collectConversionContext() };
        case "hashes":
            return { ...base, ..._collectHashesContext() };
        case "decodes":
            return { ...base, ..._collectProtoDecoderContext() };
        default:
            return { ...base, ..._collectConversionContext(), subtab: activeSubtab };
    }
}

async function _runSummaryRequest(activeSubtab, signal) {
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
        _writeLogEntryFn(`[DataToolsLLM] Summary requested for subtab=${activeSubtab}`);
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
                `[DataToolsLLM] Summary complete subtab=${activeSubtab} chars=${lastSummaryText.length}`,
            );
        }
    } catch (error) {
        if (signal?.aborted) return;
        const message = error?.message || String(error);
        _showError(message);
        _setInsightSummary("");
    }
}

// Request a background summary for the given active Conv subtab.
// Consecutive calls with the same effective input are debounced and deduplicated.
function requestDataToolsBackgroundSummary(activeSubtab = "conversions") {
    if (pendingSummaryTimeout) {
        clearTimeout(pendingSummaryTimeout);
        pendingSummaryTimeout = null;
    }
    if (activeSummaryController) {
        activeSummaryController.abort();
        activeSummaryController = null;
    }

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

    pendingSummaryTimeout = setTimeout(() => {
        activeSummaryController = new AbortController();
        lastSummaryInputHash = inputHash;
        void _runSummaryRequest(activeSubtab, activeSummaryController.signal);
    }, SUMMARY_DEBOUNCE_MS);
}

function clearDataToolsSummary() {
    if (pendingSummaryTimeout) {
        clearTimeout(pendingSummaryTimeout);
        pendingSummaryTimeout = null;
    }
    if (activeSummaryController) {
        activeSummaryController.abort();
        activeSummaryController = null;
    }
    lastSummaryInputHash = "";
    lastSummaryText = "";
    _setInsightStatus("idle");
    _setInsightSummary("");
}

module.exports = {
    initDataToolsLlmSummarizer,
    requestDataToolsBackgroundSummary,
    clearDataToolsSummary,
};
