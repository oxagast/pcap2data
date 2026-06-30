const DEFAULT_SETTINGS = Object.freeze({
    general: {
        convJsonIndentSpaces: 2,
        statusResetSeconds: 10,
        backendPacketChunkSize: 250,
    },
    llm: {
        ollamaModel: "minimax-m2.5:cloud",
        ollamaApiKey: "",
        activeByDefault: false,
        triggerDelaySeconds: 5,
        maxSummaryTokens: 1024,
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

function normalizeSettings(rawSettings = {}) {
    const source = rawSettings && typeof rawSettings === "object" ? rawSettings : {};
    const general = source.general && typeof source.general === "object" ? source.general : {};
    const llm = source.llm && typeof source.llm === "object" ? source.llm : {};
    const generalDefaults = DEFAULT_SETTINGS.general;
    const defaults = DEFAULT_SETTINGS.llm;

    const normalizedBackendChunkSize = toPositiveInteger(
        general.backendPacketChunkSize,
        generalDefaults.backendPacketChunkSize,
        1,
    );

    return {
        general: {
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
        },
    };
}

module.exports = {
    DEFAULT_SETTINGS,
    cloneDefaultSettings,
    normalizeSettings,
};