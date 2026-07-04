const DEFAULT_SETTINGS = Object.freeze({
    general: {
        themeId: "snitchbitch",
        convJsonIndentSpaces: 2,
        statusResetSeconds: 10,
        backendPacketChunkSize: 250,
        streamContextWarnPacketThreshold: 20,
    },
    backend: {
        tcpHost: "127.0.0.1",
        tcpPort: 9020,
        forceLegacySpawn: false,
    },
    debug: {
        ungroupedListVirtualizationEnabled: false,
        backendHttpDataModeEnabled: false,
        mapProjectionZoomX: 0.55,
        mapProjectionZoomY: 0.95,
        mapProjectionOffsetX: -0.53,
        mapProjectionOffsetY: 0,
        mapProjectionCalibrationLocked: true,
    },
    llm: {
        ollamaModel: "minimax-m2.5:cloud",
        ollamaApiKey: "",
        activeByDefault: false,
        triggerDelaySeconds: 5,
        maxSummaryTokens: 1024,
        ollamaRequestTimeoutSeconds: 300,
        retryCount: 2,
    },
});

const VALID_BACKEND_CHUNK_SIZES = new Set([25, 100, 250, 500, 2000]);

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

function normalizeSettings(rawSettings = {}) {
    const source = rawSettings && typeof rawSettings === "object" ? rawSettings : {};
    const general = source.general && typeof source.general === "object" ? source.general : {};
    const backend = source.backend && typeof source.backend === "object" ? source.backend : {};
    const debug = source.debug && typeof source.debug === "object" ? source.debug : {};
    const llm = source.llm && typeof source.llm === "object" ? source.llm : {};
    const generalDefaults = DEFAULT_SETTINGS.general;
    const backendDefaults = DEFAULT_SETTINGS.backend;
    const debugDefaults = DEFAULT_SETTINGS.debug;
    const defaults = DEFAULT_SETTINGS.llm;

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
            streamContextWarnPacketThreshold: toPositiveInteger(
                general.streamContextWarnPacketThreshold,
                generalDefaults.streamContextWarnPacketThreshold,
                5,
            ),
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
            ungroupedListVirtualizationEnabled:
                typeof debug.ungroupedListVirtualizationEnabled === "boolean"
                    ? debug.ungroupedListVirtualizationEnabled
                    : debugDefaults.ungroupedListVirtualizationEnabled,
            backendHttpDataModeEnabled:
                typeof debug.backendHttpDataModeEnabled === "boolean"
                    ? debug.backendHttpDataModeEnabled
                    : debugDefaults.backendHttpDataModeEnabled,
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
        llm: {
            ollamaModel:
                typeof llm.ollamaModel === "string" && llm.ollamaModel.trim()
                    ? llm.ollamaModel.trim()
                    : defaults.ollamaModel,
            ollamaApiKey:
                typeof llm.ollamaApiKey === "string" && llm.ollamaApiKey.trim()
                    ? llm.ollamaApiKey.trim()
                    : defaults.ollamaApiKey,
            activeByDefault:
                typeof llm.activeByDefault === "boolean"
                    ? llm.activeByDefault
                    : defaults.activeByDefault,
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
        },
    };
}

module.exports = {
    DEFAULT_SETTINGS,
    cloneDefaultSettings,
    normalizeSettings,
};