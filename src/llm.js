// Unified LLM module for PacketSnitch
// Provides a provider-agnostic interface for LLM generation.
// New providers can be added by:
//   1. Creating a handler function `(prompt, options, settings) => Promise<response>`.
//   2. Registering it via `registerProviderHandler("provider-id", handler)`.
//   3. Adding provider-specific settings to DEFAULT_SETTINGS in settings.js.

const { Agent, fetch: undiciFetch } = require("undici");
const { getAppSettings } = require("./settings");

let Ollama = null;
try {
    ({ Ollama } = require("ollama"));
} catch (error) {
    console.warn(
        "Ollama Node client module is unavailable. Ollama LLM features will be disabled.",
        error,
    );
}

const PROVIDER_HANDLER_REGISTRY = new Map();
const PROVIDER_DISPATCHER_CACHES = new Map();

function registerProviderHandler(providerId, handler) {
    if (typeof providerId !== "string" || !providerId.trim()) {
        throw new Error("Provider id must be a non-empty string");
    }
    if (typeof handler !== "function") {
        throw new Error("Provider handler must be a function");
    }
    const normalizedId = providerId.trim().toLowerCase();
    PROVIDER_HANDLER_REGISTRY.set(normalizedId, handler);
    return normalizedId;
}

function unregisterProviderHandler(providerId) {
    if (typeof providerId !== "string") return false;
    return PROVIDER_HANDLER_REGISTRY.delete(providerId.trim().toLowerCase());
}

function listProviderIds() {
    return Array.from(PROVIDER_HANDLER_REGISTRY.keys());
}

function getProviderDispatcherCache(providerId) {
    let cache = PROVIDER_DISPATCHER_CACHES.get(providerId);
    if (!cache) {
        cache = new Map();
        PROVIDER_DISPATCHER_CACHES.set(providerId, cache);
    }
    return cache;
}

function getDispatcherForProvider(providerId, timeoutMs) {
    const normalizedTimeoutMs = Number.isFinite(timeoutMs) && timeoutMs > 0
        ? Math.floor(timeoutMs)
        : 5 * 60 * 1000;
    const cacheKey = String(normalizedTimeoutMs);
    const cache = getProviderDispatcherCache(providerId);
    if (!cache.has(cacheKey)) {
        cache.set(
            cacheKey,
            new Agent({
                headersTimeout: normalizedTimeoutMs,
                bodyTimeout: normalizedTimeoutMs,
            }),
        );
    }
    return cache.get(cacheKey);
}

function getFetchForProvider(providerId, timeoutMs) {
    const dispatcher = getDispatcherForProvider(providerId, timeoutMs);
    return (input, init = {}) =>
        undiciFetch(input, {
            ...init,
            headers: (() => {
                const headers = new Headers(init.headers || {});
                headers.set("User-Agent", `Mozilla/5.0 (compatible; PacketSnitch/0.0.0; +http://packetsnitch.com)`);
                return headers;
            })(),
            dispatcher,
        });
}

function isOllamaClientModuleAvailable() {
    return typeof Ollama === "function";
}

function isOllamaCloudModel(modelName) {
    const normalized = String(modelName || "").trim().toLowerCase();
    return normalized.endsWith(":cloud");
}

/**
 * Generate a response using the configured LLM provider.
 * The configured provider's registered handler is invoked.
 * @param {string} prompt - The prompt to send to the LLM
 * @param {Object} options - Generation options
 * @param {number} [options.maxTokens] - Maximum tokens to generate
 * @param {number} [options.temperature] - Temperature for generation
 * @param {boolean} [options.think] - Whether to enable thinking mode (provider-specific)
 * @returns {Promise<Object>} The LLM response
 */
async function generate(prompt, options = {}) {
    const settings = getAppSettings();
    const provider = (settings.llm?.provider || "ollama").toLowerCase();

    const handler = PROVIDER_HANDLER_REGISTRY.get(provider);
    if (!handler) {
        throw new Error(
            `LLM provider "${provider}" is not registered. Available providers: ${listProviderIds().join(", ")}`,
        );
    }

    return handler(prompt, options, settings);
}

/**
 * Generate a response using Ollama.
 */
async function generateOllama(prompt, options, settings) {
    if (!isOllamaClientModuleAvailable()) {
        throw new Error("Ollama client module is unavailable");
    }

    const fetch = getFetchForProvider("ollama", Number(settings.llm.ollamaRequestTimeoutSeconds) * 1000);

    const ollamaClient = settings.apiKeys.ollamaApiKey
        ? new Ollama({
            fetch,
            headers: {
                Authorization: settings.apiKeys.ollamaApiKey.startsWith("Bearer ")
                    ? settings.apiKeys.ollamaApiKey
                    : `Bearer ${settings.apiKeys.ollamaApiKey}`,
            },
        })
        : new Ollama({ fetch });

    const overrideTokens = Number(options && options.maxTokens);
    const numPredict = Number.isFinite(overrideTokens) && overrideTokens > 0
        ? Math.max(settings.llm.maxSummaryTokens, overrideTokens)
        : settings.llm.maxSummaryTokens;

    const overrideTemp = Number(options && options.temperature);
    const temperature = Number.isFinite(overrideTemp) ? overrideTemp : 0.5;

    const overrideThink = options && Object.prototype.hasOwnProperty.call(options, "think")
        ? options.think
        : false;

    const response = await ollamaClient.generate({
        model: settings.llm.ollamaModel,
        prompt,
        think: overrideThink === false ? false : Boolean(overrideThink),
        options: {
            temperature,
            num_predict: numPredict,
        },
    });

    return response;
}

/**
 * Generate a response using OpenRouter.
 * OpenRouter exposes an OpenAI-compatible chat completions API.
 */
async function generateOpenRouter(prompt, options, settings) {
    const apiKey = settings.apiKeys?.openrouterApiKey;
    if (!apiKey) {
        throw new Error("OpenRouter API key is not configured");
    }

    const model = settings.llm?.openrouterModel || "openai/gpt-4o-mini";
    const timeoutMs = Number(settings.llm?.openrouterRequestTimeoutSeconds || 300) * 1000;
    const fetch = getFetchForProvider("openrouter", timeoutMs);

    const overrideTokens = Number(options && options.maxTokens);
    const maxTokens = Number.isFinite(overrideTokens) && overrideTokens > 0
        ? Math.max(settings.llm.maxSummaryTokens, overrideTokens)
        : settings.llm.maxSummaryTokens;

    const overrideTemp = Number(options && options.temperature);
    const temperature = Number.isFinite(overrideTemp) ? overrideTemp : 0.5;

    const requestBody = {
        model,
        messages: [
            {
                role: "user",
                content: prompt,
            },
        ],
        max_tokens: maxTokens,
        temperature,
    };

    const response = await fetch("https://openrouter.ai/api/v1/chat/completions", {
        method: "POST",
        headers: {
            Authorization: apiKey.startsWith("Bearer ") ? apiKey : `Bearer ${apiKey}`,
        },
        body: JSON.stringify(requestBody),
    });

    if (!response.ok) {
        const errorText = await response.text();
        const error = new Error(`OpenRouter API error: ${response.status} ${response.statusText} - ${errorText}`);
        error.status = response.status;
        error.status_code = response.status;
        throw error;
    }

    const data = await response.json();

    // Normalize OpenRouter response to match Ollama response format.
    return {
        response: data.choices?.[0]?.message?.content || "",
        model: data.model,
        done: true,
    };
}

// Register the bundled providers. New providers should be registered
// here (or lazily via `registerProviderHandler` in their own module).
registerProviderHandler("ollama", generateOllama);
registerProviderHandler("openrouter", generateOpenRouter);

/**
 * Get the currently configured provider.
 */
function getProvider() {
    const settings = getAppSettings();
    return settings.llm?.provider || "ollama";
}

/**
 * Get the currently configured model for the active provider.
 */
function getModel() {
    const settings = getAppSettings();
    const provider = settings.llm?.provider || "ollama";
    return provider === "openrouter"
        ? settings.llm?.openrouterModel || "openai/gpt-4o-mini"
        : settings.llm?.ollamaModel || "minimax-m3:cloud";
}

module.exports = {
    generate,
    generateOllama,
    generateOpenRouter,
    getProvider,
    getModel,
    isOllamaClientModuleAvailable,
    isOllamaCloudModel,
    registerProviderHandler,
    unregisterProviderHandler,
    listProviderIds,
};
