const DEFAULT_SETTINGS = Object.freeze({
    llm: {
        ollamaModel: "minimax-m2.5:cloud",
        ollamaApiKey: "",
        activeByDefault: false,
        triggerDelaySeconds: 5,
        maxSummaryTokens: 1024,
    },
});

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
    const llm = source.llm && typeof source.llm === "object" ? source.llm : {};
    const defaults = DEFAULT_SETTINGS.llm;

    return {
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