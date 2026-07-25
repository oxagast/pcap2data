// Lightweight background LLM summarization for the keystore workspace.
// Runs on a fixed interval and reviews the active keystore entries only when
// the persistent keychain has been unlocked by the user. The latest summary
// is cached and can be retrieved later (e.g. by a future context-compaction
// feature) via getLatestKeystoreSummary().

const KEYSTORE_REVIEW_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes
const KEYSTORE_REVIEW_DEBOUNCE_MS = 600;
const KEYSTORE_MAX_INPUT_CHARS = 12000;
const KEYSTORE_MAX_OUTPUT_CHARS = 6000;
const KEYSTORE_MAX_RETRIES = 3;

let _callLlmFn = null;
let _isLlmRuntimeEnabledFn = null;
let _isBackgroundEnabledFn = null;
let _statusUpdateFn = null;
let _writeLogEntryFn = null;
let _getPanelApiFn = null;

let intervalId = null;
let activeReviewController = null;
let pendingReviewTimeout = null;
let runningReviewFlag = false;
let lastEntriesHash = "";
let latestSummaryText = "";
let latestSummaryTimestamp = "";
let lastReviewError = "";
let stopped = false;

function initKeystoreLlmSummarizer({
    callLargeLanguageModel,
    isLlmRuntimeEnabled,
    isBackgroundSummaryGenerationEnabled,
    statusUpdate,
    writeLogEntry,
    getKeystorePanelApi,
}) {
    _callLlmFn = callLargeLanguageModel;
    _isLlmRuntimeEnabledFn = isLlmRuntimeEnabled;
    _isBackgroundEnabledFn = isBackgroundSummaryGenerationEnabled;
    _statusUpdateFn = statusUpdate;
    _writeLogEntryFn = writeLogEntry;
    _getPanelApiFn = getKeystorePanelApi;
    startKeystoreReviewTimer();
}

function _isEnabled() {
    return (
        !stopped &&
        typeof _isBackgroundEnabledFn === "function" &&
        _isBackgroundEnabledFn() &&
        typeof _isLlmRuntimeEnabledFn === "function" &&
        _isLlmRuntimeEnabledFn()
    );
}

function _getPanelApi() {
    return typeof _getPanelApiFn === "function" ? _getPanelApiFn() : null;
}

function _canReviewKeystore() {
    const api = _getPanelApi();
    if (!api) return false;
    const mode =
        typeof api.getKeystoreMode === "function" ? api.getKeystoreMode() : "session";
    if (mode === "persistent") {
        return typeof api.isUnlocked === "function" && api.isUnlocked();
    }
    return true;
}

function _hashEntries(entries) {
    const normalized = Array.isArray(entries)
        ? entries.map((entry) => ({
            type: entry?.type,
            label: entry?.label,
            source: entry?.source,
            packetIndex: entry?.packetIndex,
            createdAt: entry?.createdAt,
        }))
        : [];
    const json = JSON.stringify(normalized);
    let h = 0;
    for (let i = 0; i < json.length; i += 1) {
        h = (h << 5) - h + json.charCodeAt(i);
        h |= 0;
    }
    return String(h);
}

function _truncate(str, maxLength) {
    if (!str || str.length <= maxLength) return str || "";
    return str.slice(0, maxLength) + "\n\n[TRUNCATED]";
}

function _maskContent(value) {
    const text = String(value || "");
    if (text.length <= 4) return "*".repeat(text.length || 1);
    return `${text.slice(0, 2)}***${text.slice(-2)}`;
}

function _buildKeystoreReviewContext() {
    const api = _getPanelApi();
    if (!api) return null;
    const mode = typeof api.getKeystoreMode === "function" ? api.getKeystoreMode() : "session";
    const rawEntries =
        typeof api.getActiveCryptKeystoreEntries === "function"
            ? api.getActiveCryptKeystoreEntries()
            : [];
    const entries = Array.isArray(rawEntries) ? rawEntries : [];
    const sanitized = entries.map((entry) => ({
        type: entry?.type || "unknown",
        label: entry?.label || "",
        source: entry?.source || "",
        packetIndex: entry?.packetIndex ?? "?",
        createdAt: entry?.createdAt || "",
        contentLength: String(entry?.content || "").length,
        contentPreview: _maskContent(entry?.content),
        existingSummary: entry?.summary || "",
    }));
    return {
        mode,
        timestamp: new Date().toISOString(),
        totalEntries: sanitized.length,
        entries: sanitized.slice(0, 200), // cap item count for prompt size
    };
}

function _buildKeystoreReviewPrompt(context) {
    return [
        "You are PacketSnitch, a network-data analysis assistant.",
        "Review the active keystore entries below and produce a concise summary for an analyst.",
        "Use only the metadata provided. Do not invent values or reconstruct secrets.",
        "Do not include raw secrets, passwords, keys, or full credential values in your response.",
        "Focus on categories, sources, likely purposes, and anything noteworthy (e.g. many session secrets from a single packet, unusual labels, duplicate types).",
        "Return clean Markdown. Keep the response concise (2-4 short paragraphs or bullet lists).",
        "",
        "Keystore context (JSON):",
        JSON.stringify(context, null, 2),
    ].join("\n");
}

async function _runKeystoreReview(signal) {
    if (!_isEnabled()) {
        return;
    }
    if (typeof _callLlmFn !== "function") {
        lastReviewError = "LLM callback is not configured";
        return;
    }
    if (!_canReviewKeystore()) {
        return;
    }
    if (runningReviewFlag) {
        return;
    }
    runningReviewFlag = true;

    try {
        const context = _buildKeystoreReviewContext();
        if (!context || context.totalEntries === 0) {
            latestSummaryText = "";
            latestSummaryTimestamp = "";
            runningReviewFlag = false;
            return;
        }

        const entriesHash = _hashEntries(context.entries);
        if (entriesHash === lastEntriesHash && latestSummaryText) {
            runningReviewFlag = false;
            return;
        }

        const prompt = _truncate(
            _buildKeystoreReviewPrompt(context),
            KEYSTORE_MAX_INPUT_CHARS,
        );

        if (typeof _statusUpdateFn === "function") {
            _statusUpdateFn("Status: PacketSnitch is reviewing the keychain...");
        }
        if (typeof _writeLogEntryFn === "function") {
            _writeLogEntryFn(`[KeystoreLLM] Reviewing ${context.totalEntries} keychain entries`);
        }

        let response = null;
        let attempts = 0;
        while (attempts < KEYSTORE_MAX_RETRIES) {
            attempts += 1;
            try {
                response = await _callLlmFn(prompt, { signal });
                break;
            } catch (error) {
                if (signal?.aborted) return;
                if (attempts >= KEYSTORE_MAX_RETRIES) {
                    throw error;
                }
                if (typeof _writeLogEntryFn === "function") {
                    _writeLogEntryFn(`[KeystoreLLM] LLM call attempt ${attempts} failed: ${error?.message || String(error)}`);
                }
                if (typeof _statusUpdateFn === "function") {
                    _statusUpdateFn(`Status: Keychain review attempt ${attempts} failed, retrying...`);
                }
                await new Promise((resolve) => setTimeout(resolve, attempts * 500));
            }
        }
        if (signal?.aborted) return;

        const text = String(response?.response || "").trim();
        if (!text) {
            lastReviewError = "no summary returned";
            if (typeof _writeLogEntryFn === "function") {
                _writeLogEntryFn(`[KeystoreLLM] No summary returned for ${context.totalEntries} entries`);
            }
            if (typeof _statusUpdateFn === "function") {
                _statusUpdateFn("Status: Keychain review returned no summary.");
            }
            return;
        }

        latestSummaryText = _truncate(text, KEYSTORE_MAX_OUTPUT_CHARS);
        latestSummaryTimestamp = new Date().toISOString();
        lastEntriesHash = entriesHash;
        lastReviewError = "";

        if (typeof _statusUpdateFn === "function") {
            _statusUpdateFn("Status: Keychain review complete.");
        }
        if (typeof _writeLogEntryFn === "function") {
            _writeLogEntryFn(
                `[KeystoreLLM] Summary complete mode=${context.mode} entries=${context.totalEntries} chars=${latestSummaryText.length}`,
            );
        }
    } catch (error) {
        if (signal?.aborted) return;
        lastReviewError = error?.message || String(error);
        if (typeof _writeLogEntryFn === "function") {
            _writeLogEntryFn(`[KeystoreLLM] Review failed: ${lastReviewError}`);
        }
        if (typeof _statusUpdateFn === "function") {
            _statusUpdateFn("Status: Keychain review failed.");
        }
    } finally {
        runningReviewFlag = false;
    }
}

function _scheduleReview() {
    if (pendingReviewTimeout) {
        clearTimeout(pendingReviewTimeout);
        pendingReviewTimeout = null;
    }
    if (activeReviewController) {
        activeReviewController.abort();
        activeReviewController = null;
    }
    pendingReviewTimeout = setTimeout(() => {
        pendingReviewTimeout = null;
        activeReviewController = new AbortController();
        void _runKeystoreReview(activeReviewController.signal);
    }, KEYSTORE_REVIEW_DEBOUNCE_MS);
}

function startKeystoreReviewTimer() {
    if (intervalId) return;
    intervalId = setInterval(() => {
        if (_isEnabled() && _canReviewKeystore()) {
            _scheduleReview();
        }
    }, KEYSTORE_REVIEW_INTERVAL_MS);
    if (intervalId.unref && typeof intervalId.unref === "function") {
        intervalId.unref();
    }
}

function stopKeystoreReviewTimer() {
    if (intervalId) {
        clearInterval(intervalId);
        intervalId = null;
    }
    if (pendingReviewTimeout) {
        clearTimeout(pendingReviewTimeout);
        pendingReviewTimeout = null;
    }
    if (activeReviewController) {
        activeReviewController.abort();
        activeReviewController = null;
    }
}

function requestKeystoreReviewNow() {
    if (!_isEnabled() || !_canReviewKeystore()) return;
    _scheduleReview();
}

function getLatestKeystoreSummary() {
    return latestSummaryText
        ? {
            text: latestSummaryText,
            timestamp: latestSummaryTimestamp,
        }
        : null;
}

function clearKeystoreSummary() {
    lastEntriesHash = "";
    latestSummaryText = "";
    latestSummaryTimestamp = "";
    lastReviewError = "";
    if (pendingReviewTimeout) {
        clearTimeout(pendingReviewTimeout);
        pendingReviewTimeout = null;
    }
    if (activeReviewController) {
        activeReviewController.abort();
        activeReviewController = null;
    }
}

function stopKeystoreReview() {
    stopped = true;
    stopKeystoreReviewTimer();
    clearKeystoreSummary();
}

module.exports = {
    initKeystoreLlmSummarizer,
    startKeystoreReviewTimer,
    stopKeystoreReviewTimer,
    requestKeystoreReviewNow,
    getLatestKeystoreSummary,
    clearKeystoreSummary,
    stopKeystoreReview,
};
