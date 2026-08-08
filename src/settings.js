// Defines default settings and normalizes persisted configuration values.

const DEFAULT_BACKEND_WORKER_THREADS = Math.max(
    1,
    (
        (Number(
            typeof navigator !== "undefined" ? navigator.hardwareConcurrency : 0,
        ) || 1) // divide by 2
    ) / 2 | 0,
);

const DEFAULT_FRONTEND_INGEST_WORKER_THREADS = Math.max(
    1,
    Math.min(
        8,
        Number(typeof navigator !== "undefined" ? navigator.hardwareConcurrency : 2) || 2,
    ),
);

// Single source of truth for heatmap map projection calibration defaults.
// Both the renderer (stats-panel.js) and the persisted debug settings
// reference this object so the two cannot drift apart.
const MAP_PROJECTION_CALIBRATION = Object.freeze({
    zoomX: 0.29,
    zoomY: 0.83,
    offsetX: -1.30,
    offsetY: 0.39,
});

const DEFAULT_SETTINGS = Object.freeze({
    general: {
        themeId: "snitchbitch",
        convJsonIndentSpaces: 2,
        statusResetSeconds: 10,
        backendPacketChunkSize: 2000,
        backendWorkerThreads: DEFAULT_BACKEND_WORKER_THREADS,
        streamContextWarnPacketThreshold: 20,
        manualConvImportMaxBytes: 2 * 1024 * 1024,
        nmapServiceScanEnabled: false,
        checkForNewReleasesOnStartup: true,
        // Landing tab opened after a capture finishes loading. Users
        // who want the richer at-a-glance overview can prefer "stats",
        // packet hunters can prefer "list", and the per-packet drill-down
        // remains available via "data". Stored as the same identifier
        // the main-tab state machine already uses (``MAIN_TAB_*``).
        defaultTab: "stats",
        // Theme catalog + recache. The catalog server URL, the
        // self-signed-cert allowance, and the recache interval are
        // hard-coded so the purchase path can't be redirected or
        // neutralized via settings edits. Locked values:
        //   - themeServerBaseUrl:          https://catalog.packetsnitch.com:9021/
        //   - allowInsecureTlsEndpoints:  true (self-signed cert allowed)
        //   - themeRefreshIntervalHours:   72 (3 days)
        themeServerBaseUrl: "https://catalog.packetsnitch.com:9021/",
        themeRefreshIntervalHours: 72,
        allowInsecureTlsEndpoints: true,
    },
    backend: {
        tcpHost: "127.0.0.1",
        tcpPort: 9020,
        forceLegacySpawn: false,
    },
    debug: {
        bsonGzipSessionEnabled: true,
        ungroupedListVirtualizationEnabled: false,
        backendHttpDataModeEnabled: true,
        backendJsonDataEmitMinIntervalMs: 800,
        backendIncrementalRefreshMinIntervalMs: 1500,
        backendIncrementalRefreshMinPackets: 4000,
        frontendIngestThreadingEnabled: true,
        frontendIngestWorkerThreads: DEFAULT_FRONTEND_INGEST_WORKER_THREADS,
        mapProjectionZoomX: MAP_PROJECTION_CALIBRATION.zoomX,
        mapProjectionZoomY: MAP_PROJECTION_CALIBRATION.zoomY,
        mapProjectionOffsetX: MAP_PROJECTION_CALIBRATION.offsetX,
        mapProjectionOffsetY: MAP_PROJECTION_CALIBRATION.offsetY,
        mapProjectionCalibrationLocked: true,
    },
    list: {
        columnVisibility: {},
        columnWidths: {},
        columnOrder: [],
    },
    llm: {
        ollamaModel: "minimax-m3:cloud",
        activeByDefault: false,
        backgroundSummaryGenerationEnabled: true,
        triggerDelaySeconds: 5,
        maxSummaryTokens: 1024,
        ollamaRequestTimeoutSeconds: 300,
        retryCount: 2,
        analysisCompactionThresholdBlubs: 6,
    },
    apiKeys: {
        ollamaApiKey: "",
        virusTotalApiKey: "",
    },
    plugins: {
        autoDisableFailureThreshold: 3,
        perPluginFailureThreshold: {},
    },
    privacy: {
        metricsEnabled: false,
        metricsConsentAsked: false,
        metricsEndpointUrl: "http://143.198.179.97:8088/mhook",
        metricsFlushIntervalSeconds: 60,
        metricsMaxQueueSize: 500,
        metricsInstallId: "",
    },
});

const VALID_BACKEND_CHUNK_SIZES = new Set([25, 100, 250, 500, 2000, 8000]);

function cloneDefaultSettings() {
    return JSON.parse(JSON.stringify(DEFAULT_SETTINGS));
}

function toPositiveInteger(value, fallback, minimum = 1) {
    const parsed = Number.parseInt(String(value), 10);
    if (!Number.isFinite(parsed) || parsed < minimum) {
        return fallback;
    }
    return parsed;
}

function toFiniteNumber(value, fallback, minimum = null, maximum = null) {
    const parsed = Number.parseFloat(String(value));
    if (!Number.isFinite(parsed)) {
        return fallback;
    }
    if (Number.isFinite(minimum) && parsed < minimum) {
        return minimum;
    }
    if (Number.isFinite(maximum) && parsed > maximum) {
        return maximum;
    }
    return parsed;
}

function normalizeThemeId(value, fallback) {
    if (typeof value !== "string") {
        return fallback;
    }
    const normalized = value.trim().toLowerCase().replace(/[^a-z0-9_-]/g, "");
    return normalized || fallback;
}

function normalizeBooleanRecord(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
        return {};
    }
    return Object.fromEntries(
        Object.entries(value)
            .filter(([key, entryValue]) => typeof key === "string" && typeof entryValue === "boolean")
            .map(([key, entryValue]) => [key, entryValue]),
    );
}

function normalizePositiveIntegerRecord(value, minimum = 1, maximum = Number.POSITIVE_INFINITY) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
        return {};
    }
    return Object.fromEntries(
        Object.entries(value)
            .filter(([key]) => typeof key === "string")
            .map(([key, entryValue]) => {
                const parsedValue = toPositiveInteger(entryValue, minimum, minimum);
                return [key, Math.min(maximum, Math.max(minimum, parsedValue))];
            }),
    );
}

function normalizeStringArray(value) {
    if (!Array.isArray(value)) {
        return [];
    }
    return value
        .filter((entry) => typeof entry === "string" && entry.trim())
        .map((entry) => entry.trim());
}

function normalizeThresholdRecord(value, minimum = 1, maximum = 100) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
        return {};
    }
    return Object.fromEntries(
        Object.entries(value)
            .filter(([key]) => typeof key === "string" && key.trim())
            .map(([key, thresholdValue]) => {
                const normalizedValue = toPositiveInteger(thresholdValue, minimum, minimum);
                return [
                    key.trim(),
                    Math.max(minimum, Math.min(maximum, normalizedValue)),
                ];
            }),
    );
}

function normalizeSettings(rawSettings = {}) {
    const source = rawSettings && typeof rawSettings === "object" ? rawSettings : {};
    const general = source.general && typeof source.general === "object" ? source.general : {};
    const backend = source.backend && typeof source.backend === "object" ? source.backend : {};
    const debug = source.debug && typeof source.debug === "object" ? source.debug : {};
    const list = source.list && typeof source.list === "object" ? source.list : {};
    const llm = source.llm && typeof source.llm === "object" ? source.llm : {};
    const apiKeys = source.apiKeys && typeof source.apiKeys === "object" ? source.apiKeys : {};
    const plugins = source.plugins && typeof source.plugins === "object" ? source.plugins : {};
    const privacy = source.privacy && typeof source.privacy === "object" ? source.privacy : {};
    const generalDefaults = DEFAULT_SETTINGS.general;
    const backendDefaults = DEFAULT_SETTINGS.backend;
    const debugDefaults = DEFAULT_SETTINGS.debug;
    const listDefaults = DEFAULT_SETTINGS.list;
    const defaults = DEFAULT_SETTINGS.llm;
    const apiKeysDefaults = DEFAULT_SETTINGS.apiKeys;
    const pluginDefaults = DEFAULT_SETTINGS.plugins;
    const privacyDefaults = DEFAULT_SETTINGS.privacy;

    const normalizedBackendChunkSize = toPositiveInteger(
        general.backendPacketChunkSize,
        generalDefaults.backendPacketChunkSize,
        1,
    );

    return {
        general: {
            themeId: normalizeThemeId(general.themeId, generalDefaults.themeId),
            convJsonIndentSpaces: toPositiveInteger(
                general.convJsonIndentSpaces,
                generalDefaults.convJsonIndentSpaces,
                0,
            ),
            statusResetSeconds: toPositiveInteger(
                general.statusResetSeconds,
                generalDefaults.statusResetSeconds,
                1,
            ),
            backendPacketChunkSize: VALID_BACKEND_CHUNK_SIZES.has(normalizedBackendChunkSize)
                ? normalizedBackendChunkSize
                : generalDefaults.backendPacketChunkSize,
            backendWorkerThreads: toPositiveInteger(
                general.backendWorkerThreads,
                generalDefaults.backendWorkerThreads,
                1,
            ),
            streamContextWarnPacketThreshold: toPositiveInteger(
                general.streamContextWarnPacketThreshold,
                generalDefaults.streamContextWarnPacketThreshold,
                5,
            ),
            manualConvImportMaxBytes: toPositiveInteger(
                general.manualConvImportMaxBytes,
                generalDefaults.manualConvImportMaxBytes,
                1024,
            ),
            nmapServiceScanEnabled:
                typeof general.nmapServiceScanEnabled === "boolean"
                    ? general.nmapServiceScanEnabled
                    : generalDefaults.nmapServiceScanEnabled,
            checkForNewReleasesOnStartup:
                typeof general.checkForNewReleasesOnStartup === "boolean"
                    ? general.checkForNewReleasesOnStartup
                    : generalDefaults.checkForNewReleasesOnStartup,
            defaultTab: normalizeDefaultTab(
                general.defaultTab,
                generalDefaults.defaultTab,
            ),
            // Locked values — ignore whatever the user has saved and
            // always emit the hard-coded defaults so the catalog server
            // can't be redirected and the recache can't be neutralized.
            themeServerBaseUrl: generalDefaults.themeServerBaseUrl,
            themeRefreshIntervalHours: generalDefaults.themeRefreshIntervalHours,
            allowInsecureTlsEndpoints: generalDefaults.allowInsecureTlsEndpoints,
        },
        backend: {
            tcpHost:
                typeof backend.tcpHost === "string" && backend.tcpHost.trim()
                    ? backend.tcpHost.trim()
                    : backendDefaults.tcpHost,
            tcpPort: toPositiveInteger(
                backend.tcpPort,
                backendDefaults.tcpPort,
                1,
            ),
            forceLegacySpawn:
                typeof backend.forceLegacySpawn === "boolean"
                    ? backend.forceLegacySpawn
                    : backendDefaults.forceLegacySpawn,
        },
        debug: {
            bsonGzipSessionEnabled:
                typeof debug.bsonGzipSessionEnabled === "boolean"
                    ? debug.bsonGzipSessionEnabled
                    : debugDefaults.bsonGzipSessionEnabled,
            ungroupedListVirtualizationEnabled:
                typeof debug.ungroupedListVirtualizationEnabled === "boolean"
                    ? debug.ungroupedListVirtualizationEnabled
                    : debugDefaults.ungroupedListVirtualizationEnabled,
            backendHttpDataModeEnabled:
                typeof debug.backendHttpDataModeEnabled === "boolean"
                    ? debug.backendHttpDataModeEnabled
                    : debugDefaults.backendHttpDataModeEnabled,
            backendJsonDataEmitMinIntervalMs: toPositiveInteger(
                debug.backendJsonDataEmitMinIntervalMs,
                debugDefaults.backendJsonDataEmitMinIntervalMs,
                250,
            ),
            backendIncrementalRefreshMinIntervalMs: toPositiveInteger(
                debug.backendIncrementalRefreshMinIntervalMs,
                debugDefaults.backendIncrementalRefreshMinIntervalMs,
                100,
            ),
            backendIncrementalRefreshMinPackets: toPositiveInteger(
                debug.backendIncrementalRefreshMinPackets,
                debugDefaults.backendIncrementalRefreshMinPackets,
                100,
            ),
            frontendIngestThreadingEnabled:
                typeof debug.frontendIngestThreadingEnabled === "boolean"
                    ? debug.frontendIngestThreadingEnabled
                    : debugDefaults.frontendIngestThreadingEnabled,
            frontendIngestWorkerThreads: toPositiveInteger(
                debug.frontendIngestWorkerThreads,
                debugDefaults.frontendIngestWorkerThreads,
                1,
            ),
            mapProjectionZoomX: toFiniteNumber(
                debug.mapProjectionZoomX,
                debugDefaults.mapProjectionZoomX,
                0.1,
                3,
            ),
            mapProjectionZoomY: toFiniteNumber(
                debug.mapProjectionZoomY,
                debugDefaults.mapProjectionZoomY,
                0.1,
                3,
            ),
            mapProjectionOffsetX: toFiniteNumber(
                debug.mapProjectionOffsetX,
                debugDefaults.mapProjectionOffsetX,
                -2.2,
                2.2,
            ),
            mapProjectionOffsetY: toFiniteNumber(
                debug.mapProjectionOffsetY,
                debugDefaults.mapProjectionOffsetY,
                -2.2,
                2.2,
            ),
            mapProjectionCalibrationLocked:
                typeof debug.mapProjectionCalibrationLocked === "boolean"
                    ? debug.mapProjectionCalibrationLocked
                    : debugDefaults.mapProjectionCalibrationLocked,
        },
        list: {
            columnVisibility: normalizeBooleanRecord(list.columnVisibility || listDefaults.columnVisibility),
            columnWidths: normalizePositiveIntegerRecord(
                list.columnWidths || listDefaults.columnWidths,
                48,
                640,
            ),
            columnOrder: normalizeStringArray(list.columnOrder || listDefaults.columnOrder),
        },
        llm: {
            ollamaModel:
                typeof llm.ollamaModel === "string" && llm.ollamaModel.trim()
                    ? llm.ollamaModel.trim()
                    : defaults.ollamaModel,
            activeByDefault:
                typeof llm.activeByDefault === "boolean"
                    ? llm.activeByDefault
                    : defaults.activeByDefault,
            backgroundSummaryGenerationEnabled:
                typeof llm.backgroundSummaryGenerationEnabled === "boolean"
                    ? llm.backgroundSummaryGenerationEnabled
                    : defaults.backgroundSummaryGenerationEnabled,
            triggerDelaySeconds: toPositiveInteger(
                llm.triggerDelaySeconds,
                defaults.triggerDelaySeconds,
                0,
            ),
            maxSummaryTokens: toPositiveInteger(
                llm.maxSummaryTokens,
                defaults.maxSummaryTokens,
                1,
            ),
            ollamaRequestTimeoutSeconds: toPositiveInteger(
                llm.ollamaRequestTimeoutSeconds,
                defaults.ollamaRequestTimeoutSeconds,
                1,
            ),
            retryCount: toPositiveInteger(
                llm.retryCount,
                defaults.retryCount,
                0,
            ),
            analysisCompactionThresholdBlubs: toPositiveInteger(
                llm.analysisCompactionThresholdBlubs,
                defaults.analysisCompactionThresholdBlubs,
                1,
            ),
        },
        apiKeys: {
            ollamaApiKey:
                typeof apiKeys.ollamaApiKey === "string" && apiKeys.ollamaApiKey.trim()
                    ? apiKeys.ollamaApiKey.trim()
                    : apiKeysDefaults.ollamaApiKey,
            virusTotalApiKey:
                typeof apiKeys.virusTotalApiKey === "string" && apiKeys.virusTotalApiKey.trim()
                    ? apiKeys.virusTotalApiKey.trim()
                    : apiKeysDefaults.virusTotalApiKey,
        },
        plugins: {
            autoDisableFailureThreshold: toPositiveInteger(
                plugins.autoDisableFailureThreshold,
                pluginDefaults.autoDisableFailureThreshold,
                1,
            ),
            perPluginFailureThreshold: normalizeThresholdRecord(
                plugins.perPluginFailureThreshold,
                1,
                100,
            ),
        },
        privacy: {
            metricsEnabled:
                typeof privacy.metricsEnabled === "boolean"
                    ? privacy.metricsEnabled
                    : privacyDefaults.metricsEnabled,
            metricsConsentAsked:
                typeof privacy.metricsConsentAsked === "boolean"
                    ? privacy.metricsConsentAsked
                    : privacyDefaults.metricsConsentAsked,
            metricsEndpointUrl: normalizeEndpointUrl(
                privacy.metricsEndpointUrl,
                privacyDefaults.metricsEndpointUrl,
            ),
            metricsFlushIntervalSeconds: toPositiveInteger(
                privacy.metricsFlushIntervalSeconds,
                privacyDefaults.metricsFlushIntervalSeconds,
                5,
            ),
            metricsMaxQueueSize: toPositiveInteger(
                privacy.metricsMaxQueueSize,
                privacyDefaults.metricsMaxQueueSize,
                10,
            ),
            metricsInstallId:
                typeof privacy.metricsInstallId === "string"
                    ? privacy.metricsInstallId.trim()
                    : privacyDefaults.metricsInstallId,
        },
    };
}

function normalizeEndpointUrl(value, fallback) {
    if (typeof value !== "string") {
        return fallback;
    }
    const trimmed = value.trim();
    if (!trimmed) {
        return fallback;
    }
    try {
        const parsed = new URL(trimmed);
        if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
            return fallback;
        }
        // Preserve the user's chosen scheme. We previously auto-upgraded
        // any non-loopback ``http://`` URL to ``https://`` here, but the
        // default metrics endpoint is plain HTTP and self-hosters regularly
        // run the open-source collector over plain HTTP on their own box.
        // Silently rewriting the scheme produced confusing "fetch failed"
        // errors against the production endpoint and broke the self-hosted
        // use case entirely. HTTPS still works when the user types it.
        return parsed.toString();
    } catch (_error) {
        return fallback;
    }
}

// Valid identifiers for the landing-tab preference. The values must
// stay in sync with ``MAIN_TAB_*`` in ``src/ui/main-frontend.js``;
// unknown values fall back to the default so a stale persisted
// setting can never brick the initial-tab dispatch.
const VALID_DEFAULT_TABS = new Set(["data", "stats", "list"]);

function normalizeDefaultTab(value, fallback) {
    if (typeof value !== "string") {
        return fallback;
    }
    const trimmed = value.trim().toLowerCase();
    return VALID_DEFAULT_TABS.has(trimmed) ? trimmed : fallback;
}

module.exports = {
    DEFAULT_SETTINGS,
    MAP_PROJECTION_CALIBRATION,
    VALID_DEFAULT_TABS,
    cloneDefaultSettings,
    normalizeSettings,
    normalizeEndpointUrl,
    normalizeDefaultTab,
};