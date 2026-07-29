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
//   - Every `settingsapi.update` (consent, setEnabled, setEndpointUrl,
//     persistInstallId) dispatches a `packetsnitch:settings-updated`
//     CustomEvent on `window` with the new settings in `detail`, so the
//     renderer can refresh its in-memory snapshot and re-sync the
//     privacy tab form. Without this the consent overlay's Yes button
//     would write the new state to disk but the privacy tab would
//     still show the old value.

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

// True when the metrics module has been seeded with a settings
// snapshot. The first-run consent overlay must wait for this before
// asking the user: ``getConsentStatus()`` returns "first-run" while
// the snapshot is null, so without a guard the overlay would re-appear
// on every launch even after the user has previously answered.
function hasSettingsSnapshot() {
    return Boolean(
        metrics.settingsSnapshot
        && typeof metrics.settingsSnapshot === "object",
    );
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
        return Promise.resolve(null);
    }
    try {
        const savedSettings = window.settingsapi.update({ privacy: { metricsInstallId: id } });
        return broadcastSettingsUpdated(savedSettings);
    } catch (_error) {
        // Best-effort: the id is also kept in memory for the rest of this run.
        return Promise.resolve(null);
    }
}

// Settings changes made through the metrics module (consent, toggling
// the privacy switch, updating the endpoint URL, etc.) only round-trip
// to the renderer's in-memory ``appSettings`` and the privacy form if
// the renderer is told about them. ``settingsapi.update`` returns the
// post-merge settings from the main process, so we forward them as a
// ``packetsnitch:settings-updated`` CustomEvent.  Anything else in
// the renderer that needs to stay in sync (e.g. the privacy tab
// checkbox, the consent status text) can listen for it.
function broadcastSettingsUpdated(updatePromise) {
    if (typeof window === "undefined" || !updatePromise || typeof updatePromise.then !== "function") {
        return Promise.resolve(null);
    }
    return Promise.resolve(updatePromise)
        .then((savedSettings) => {
            if (
                savedSettings
                && typeof savedSettings === "object"
                && typeof window.dispatchEvent === "function"
                && typeof window.CustomEvent === "function"
            ) {
                try {
                    window.dispatchEvent(
                        new window.CustomEvent("packetsnitch:settings-updated", {
                            detail: savedSettings,
                        }),
                    );
                } catch (_error) {
                    // ignore: best-effort notification
                }
            }
            return savedSettings || null;
        })
        .catch(() => null);
}

function init({ appVersion = "" } = {}) {
    if (metrics.initialized) {
        return metrics;
    }
    const privacy = getPrivacy();
    // The install id is a stable per-install marker, not a tracking
    // payload. Generate it on first run regardless of metrics consent
    // so the catalog server (and other non-tracking features like
    // license reconciliation) can personalize responses for this
    // install. The id is *only* sent to the metrics endpoint when the
    // user has opted in to metrics — see ``flushMetricsQueue`` /
    // ``buildMetricsFlushBody``. For opted-out installs the id stays
    // on disk and is reused for catalog / license calls but never
    // accompanies a metrics POST.
    let id = String(privacy.metricsInstallId || "").trim();
    if (!id) {
        id = generateInstallId();
        // Best-effort persist; the in-memory copy is what matters for
        // the rest of this run even if the IPC write fails.
        try {
            persistInstallId(id);
        } catch (_error) {
            // ignore: we still have the id in memory
        }
    }
    metrics.installId = id;
    metrics.appVersion = String(appVersion || "");
    metrics.initialized = true;
    return metrics;
}

function hasBeenAsked() {
    const privacy = getPrivacy();
    // An explicit ``true`` from the user is the canonical signal
    // that they have been prompted. ``false`` (or a missing key on
    // a fresh install) is treated as "not yet asked".
    if (privacy.metricsConsentAsked === true) {
        return true;
    }
    // Backwards-compatibility: legacy installs only set
    // ``metricsEnabled`` (and possibly ``metricsInstallId``). The
    // install id is the stronger signal here because it can only
    // be produced after an explicit opt-in (the consent flow is
    // what generates it). If a user has a non-empty install id
    // they must have answered the prompt at some point.
    if (Boolean(String(privacy.metricsInstallId || "").trim())) {
        return true;
    }
    if (typeof privacy.metricsEnabled === "boolean") {
        // Without an install id and without ``metricsConsentAsked``
        // we cannot tell an explicit opt-out from the default
        // state. Stay safe and prompt the user; if they really
        // did mean to opt out, they'll just click "No" again.
        return false;
    }
    return false;
}

function getConsentStatus() {
    if (!hasBeenAsked()) {
        return "first-run";
    }
    const privacy = getPrivacy();
    return privacy.metricsEnabled ? "enabled" : "disabled";
}

function setEnabled(enabled) {
    if (typeof window === "undefined" || !window.settingsapi || typeof window.settingsapi.update !== "function") {
        return Promise.resolve(null);
    }
    try {
        return broadcastSettingsUpdated(
            window.settingsapi.update({ privacy: { metricsEnabled: Boolean(enabled) } }),
        );
    } catch (_error) {
        return Promise.resolve(null);
    }
}

function recordConsent(enabled) {
    // Persist the user's first-run decision. On an opt-in we also
    // stamp the install id at the same time so we never have a window
    // where ``metricsConsentAsked`` is true but no install id has
    // been generated. On an opt-out we still mark the prompt as
    // answered so we don't pester the user on every launch.
    const decided = Boolean(enabled);
    if (!hasBeenAsked()) {
        if (typeof window === "undefined" || !window.settingsapi || typeof window.settingsapi.update !== "function") {
            return Promise.resolve(false);
        }
        try {
            const installId = decided ? generateInstallId() : "";
            const savedPromise = window.settingsapi.update({
                privacy: {
                    metricsConsentAsked: true,
                    metricsEnabled: decided,
                    metricsInstallId: installId,
                },
            });
            return broadcastSettingsUpdated(savedPromise).then(() => true);
        } catch (_error) {
            return Promise.resolve(false);
        }
    }
    // Already asked: just toggle the flag. The install id (if any) is
    // preserved on the main process side.
    return setEnabled(decided).then(() => true);
}

function setEndpointUrl(url) {
    if (typeof window === "undefined" || !window.settingsapi || typeof window.settingsapi.update !== "function") {
        return Promise.resolve(null);
    }
    try {
        return broadcastSettingsUpdated(
            window.settingsapi.update({ privacy: { metricsEndpointUrl: String(url || "").trim() } }),
        );
    } catch (_error) {
        return Promise.resolve(null);
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

// Records a tab or subtab switch.  ``tab`` is the high-level tab
// (summary, data, stats, list, notes, settings, data-tools,
// crypt, keystore); ``subtab`` is the optional subtab inside it
// (e.g. a settings subtab, a conv subtab, a crypt subtab).  When
// only ``tab`` is set, this fires ``tab.switch`` so the dashboard
// can answer questions like "which main tab is opened most?".  When
// both are set, this fires ``subtab.switch`` so the same dashboard
// can answer "which subtab inside data-tools is most used?".
// Both are no-ops if the user has not opted in to diagnostics.
function trackTabSwitch({ tab, subtab } = {}) {
    const safeTab = typeof tab === "string" && tab.trim() ? tab.trim().slice(0, 64) : "";
    const safeSubtab = typeof subtab === "string" && subtab.trim() ? subtab.trim().slice(0, 64) : "";
    if (!safeTab && !safeSubtab) {
        return;
    }
    if (safeSubtab) {
        track("subtab.switch", { tab: safeTab, subtab: safeSubtab });
    } else {
        track("tab.switch", { tab: safeTab });
    }
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
    trackTabSwitch,
    flush,
    getConsentStatus,
    hasBeenAsked,
    hasSettingsSnapshot,
    recordConsent,
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
module.exports.trackTabSwitch = trackTabSwitch;
module.exports.flush = flush;
module.exports.getConsentStatus = getConsentStatus;
module.exports.hasBeenAsked = hasBeenAsked;
module.exports.hasSettingsSnapshot = hasSettingsSnapshot;
module.exports.recordConsent = recordConsent;
module.exports.setEnabled = setEnabled;
module.exports.setEndpointUrl = setEndpointUrl;
module.exports.getQueue = getQueue;
module.exports.clearQueue = clearQueue;
module.exports.setSettingsSnapshot = setSettingsSnapshot;
