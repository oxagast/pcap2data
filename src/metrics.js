// Centralized, opt-in, privacy-respecting usage metrics for PacketSnitch.
//
// This module owns the in-memory event queue and the Settings gating. The
// renderer is the only consumer; it never makes a network call. The actual
// HTTP POST is performed by the main process via the `metricsapi` bridge
// exposed in `src/preload.js` (channels `metrics:track` and `metrics:flush`).
//
// Design contract:
//   - `metrics.track()` is a no-op when `metricsEnabled` is false.
//   - The queue is capped at `metricsMaxQueueSize` (oldest entries dropped).
//   - `metrics.flush()` is a fire-and-forget forwarder to the main process.
//   - `props` are filtered through `SAFE_PROP_KEYS` so we never accidentally
//     send raw user content (PCAP paths, IPs, LLM prompts, etc.).
//   - The first time `init()` runs we generate a UUIDv4 install id and write
//     it back to `settings.privacy.metricsInstallId`.

const SAFE_PROP_KEYS = new Set([
    "tab",
    "subtab",
    "source",
    "bytes",
    "resultCount",
    "model",
    "ok",
    "durationMs",
    "kind",
    "context",
    "action",
    "protocol",
    "resetToDefaults",
    "capability",
    "okCount",
    "failCount",
    "evictedCount",
]);

const SAFE_PROP_VALUE_LIMITS = {
    bytes: 10,
    resultCount: 10,
    durationMs: 10,
    okCount: 10,
    failCount: 10,
    evictedCount: 10,
};

const EVENT_NAME_PATTERN = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)?$/;

const metrics = {
    initialized: false,
    installId: "",
    pending: [],
    inFlight: false,
    retryQueue: [],
    // A synchronous snapshot of the current settings. The host
    // (``src/ui/main-frontend.js``) pushes a fresh copy here whenever
    // it loads or saves settings. Without this, ``window.settingsapi.get``
    // is async, so any code that called ``getPrivacy()`` synchronously
    // would actually get the unresolved Promise and silently read an
    // empty privacy block. That had two bad effects:
    //   1. ``metrics.track()`` was always a no-op because
    //      ``isEnabled()`` saw ``metricsEnabled`` as undefined.
    //   2. ``init()`` always thought there was no install id, so it
    //      generated a new one on every run and wrote it back via
    //      ``settingsapi.update({ privacy: { metricsInstallId: id } })``.
    //      That partial update used to clobber the user's other
    //      privacy fields (the main process did a shallow merge);
    //      it is now a deep merge but the snapshot makes the
    //      dependency explicit and removes the race entirely.
    settingsSnapshot: null,
};

function setSettingsSnapshot(snapshot) {
    if (snapshot && typeof snapshot === "object") {
        metrics.settingsSnapshot = snapshot;
    } else {
        metrics.settingsSnapshot = null;
    }
}

function getSettings() {
    if (metrics.settingsSnapshot && typeof metrics.settingsSnapshot === "object") {
        return metrics.settingsSnapshot;
    }
    return {};
}

function getPrivacy() {
    const settings = getSettings();
    const privacy = settings && settings.privacy && typeof settings.privacy === "object"
        ? settings.privacy
        : {};
    return privacy;
}

function isEnabled() {
    return Boolean(getPrivacy().metricsEnabled);
}

function getEndpointUrl() {
    return String(getPrivacy().metricsEndpointUrl || "").trim();
}

function getMaxQueueSize() {
    const raw = Number(getPrivacy().metricsMaxQueueSize);
    if (!Number.isFinite(raw) || raw < 1) {
        return 500;
    }
    return Math.min(10000, Math.max(1, Math.floor(raw)));
}

function sanitizeProps(rawProps) {
    if (!rawProps || typeof rawProps !== "object" || Array.isArray(rawProps)) {
        return {};
    }
    const out = {};
    for (const [key, value] of Object.entries(rawProps)) {
        if (!SAFE_PROP_KEYS.has(key)) continue;
        if (typeof value === "boolean") {
            out[key] = value;
            continue;
        }
        if (typeof value === "number" && Number.isFinite(value)) {
            const limit = SAFE_PROP_VALUE_LIMITS[key];
            if (limit) {
                const lower = -1 * Math.pow(10, limit);
                const upper = Math.pow(10, limit);
                if (value < lower || value > upper) {
                    out[key] = value < lower ? lower : upper;
                } else {
                    out[key] = value;
                }
            } else {
                out[key] = value;
            }
            continue;
        }
        if (typeof value === "string") {
            const trimmed = value.length > 64 ? value.slice(0, 64) : value;
            out[key] = trimmed;
            continue;
        }
    }
    return out;
}

function pruneOldest(arr, maxSize) {
    if (arr.length <= maxSize) return;
    arr.splice(0, arr.length - maxSize);
}

function generateInstallId() {
    if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
        return crypto.randomUUID();
    }
    // Fallback: a v4-shaped random id. Sufficient for a non-cryptographic
    // anonymous install marker; the only requirement is uniqueness.
    const bytes = new Uint8Array(16);
    if (typeof crypto !== "undefined" && crypto.getRandomValues) {
        crypto.getRandomValues(bytes);
    } else {
        for (let i = 0; i < bytes.length; i += 1) {
            bytes[i] = Math.floor(Math.random() * 256);
        }
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function persistInstallId(id) {
    if (typeof window === "undefined" || !window.settingsapi || typeof window.settingsapi.update !== "function") {
        return;
    }
    try {
        window.settingsapi.update({ privacy: { metricsInstallId: id } });
    } catch (_error) {
        // Best-effort: the id is also kept in memory for the rest of this run.
    }
}

function init({ appVersion = "" } = {}) {
    if (metrics.initialized) {
        return metrics;
    }
    const privacy = getPrivacy();
    let id = String(privacy.metricsInstallId || "").trim();
    if (!id) {
        id = generateInstallId();
        persistInstallId(id);
    }
    metrics.installId = id;
    metrics.appVersion = String(appVersion || "");
    metrics.initialized = true;
    return metrics;
}

function getConsentStatus() {
    const privacy = getPrivacy();
    const hasId = Boolean(String(privacy.metricsInstallId || "").trim());
    if (!hasId) {
        return "first-run";
    }
    return privacy.metricsEnabled ? "enabled" : "disabled";
}

function setEnabled(enabled) {
    if (typeof window === "undefined" || !window.settingsapi || typeof window.settingsapi.update !== "function") {
        return;
    }
    try {
        window.settingsapi.update({ privacy: { metricsEnabled: Boolean(enabled) } });
    } catch (_error) {
        // ignore
    }
}

function setEndpointUrl(url) {
    if (typeof window === "undefined" || !window.settingsapi || typeof window.settingsapi.update !== "function") {
        return;
    }
    try {
        window.settingsapi.update({ privacy: { metricsEndpointUrl: String(url || "").trim() } });
    } catch (_error) {
        // ignore
    }
}

function track(name, props = {}) {
    if (!metrics.initialized) {
        init();
    }
    if (!isEnabled()) {
        return;
    }
    if (typeof name !== "string" || !EVENT_NAME_PATTERN.test(name)) {
        return;
    }
    const safeProps = sanitizeProps(props);
    const event = {
        ts: new Date().toISOString(),
        name,
        props: safeProps,
    };
    metrics.pending.push(event);
    pruneOldest(metrics.pending, getMaxQueueSize());
}

function getQueue() {
    return metrics.pending.slice();
}

function clearQueue() {
    metrics.pending.length = 0;
    metrics.retryQueue.length = 0;
}

async function flush() {
    if (!metrics.initialized) {
        init();
    }
    if (!isEnabled()) {
        return { ok: false, reason: "disabled" };
    }
    const endpoint = getEndpointUrl();
    if (!endpoint) {
        return { ok: false, reason: "no-endpoint" };
    }
    if (metrics.inFlight) {
        return { ok: false, reason: "in-flight" };
    }
    const batch = metrics.pending.splice(0, metrics.pending.length).concat(metrics.retryQueue.splice(0, metrics.retryQueue.length));
    if (batch.length === 0) {
        return { ok: true, sent: 0 };
    }
    metrics.inFlight = true;
    const payload = {
        installId: metrics.installId,
        appVersion: metrics.appVersion,
        sentAt: new Date().toISOString(),
        events: batch,
    };
    try {
        const api = (typeof window !== "undefined" && window.metricsapi) || null;
        let result = null;
        if (api && typeof api.flush === "function") {
            result = await api.flush(payload);
        }
        if (!result || result.ok !== true) {
            // Put events back at the head of the queue so the next flush retries.
            metrics.retryQueue.unshift(...batch);
            pruneOldest(metrics.retryQueue, getMaxQueueSize());
            return { ok: false, reason: result && result.error ? result.error : "send-failed" };
        }
        return { ok: true, sent: batch.length };
    } catch (_error) {
        metrics.retryQueue.unshift(...batch);
        pruneOldest(metrics.retryQueue, getMaxQueueSize());
        return { ok: false, reason: "exception" };
    } finally {
        metrics.inFlight = false;
    }
}

const metricsApi = {
    init,
    track,
    flush,
    getConsentStatus,
    setEnabled,
    setEndpointUrl,
    getQueue,
    clearQueue,
    setSettingsSnapshot,
};

module.exports = metricsApi;
module.exports.default = metricsApi;
module.exports.init = init;
module.exports.track = track;
module.exports.flush = flush;
module.exports.getConsentStatus = getConsentStatus;
module.exports.setEnabled = setEnabled;
module.exports.setEndpointUrl = setEndpointUrl;
module.exports.getQueue = getQueue;
module.exports.clearQueue = clearQueue;
module.exports.setSettingsSnapshot = setSettingsSnapshot;
