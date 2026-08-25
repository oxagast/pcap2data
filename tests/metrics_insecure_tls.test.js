// Regression tests for the metrics-server self-signed-cert support.
//
// The metrics flush lives in src/main.js (`flushMetricsQueue`). It posts
// queued events to the configured endpoint via `undiciFetch`, which by
// default enforces strict TLS verification. The production metrics
// endpoint shares its self-signed cert with the theme catalog server,
// so the GUI must attach an undici dispatcher that disables cert
// verification when the endpoint is HTTPS.
//
// These tests (like `tests/themes_subtab.test.js`) avoid loading the
// full main.js (which pulls in `electron` and many other module
// dependencies). Instead, we extract the relevant helpers with
// `vm.runInContext` and stub the dependencies (`Agent`, `undiciFetch`,
// `app`, `appendActivityLogLine`, `getMetricsPrivacy`, `getAppSettings`)
// so the function under test can run in plain Node.

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const PROJECT_ROOT = path.join(__dirname, '..');
const MAIN_PATH = path.join(PROJECT_ROOT, 'src', 'main.js');
const SETTINGS_PATH = path.join(PROJECT_ROOT, 'src', 'settings.js');

function extractFunctionDeclaration(sourceText, functionName) {
    const startToken = `async function ${functionName}`;
    const startIndex = sourceText.indexOf(startToken);
    if (startIndex === -1) {
        return extractFunctionDeclarationFallback(sourceText, functionName);
    }
    let cursor = startIndex + startToken.length;
    let parenDepth = 0;
    let seenOpenParen = false;
    for (; cursor < sourceText.length; cursor += 1) {
        const char = sourceText[cursor];
        if (char === "(") {
            parenDepth += 1;
            seenOpenParen = true;
            continue;
        }
        if (char === ")") {
            parenDepth -= 1;
            if (seenOpenParen && parenDepth === 0) {
                cursor += 1;
                break;
            }
        }
    }
    let depth = 0;
    for (; cursor < sourceText.length; cursor += 1) {
        const char = sourceText[cursor];
        if (char === "{") depth += 1;
        if (char === "}") {
            depth -= 1;
            if (depth === 0) {
                return sourceText.slice(startIndex, cursor + 1);
            }
        }
    }
    throw new Error(`Could not parse function ${functionName}`);
}

function extractFunctionDeclarationFallback(sourceText, functionName) {
    const startToken = `function ${functionName}`;
    const startIndex = sourceText.indexOf(startToken);
    if (startIndex === -1) {
        throw new Error(`Could not find function ${functionName}`);
    }
    let cursor = startIndex + startToken.length;
    let parenDepth = 0;
    let seenOpenParen = false;
    for (; cursor < sourceText.length; cursor += 1) {
        const char = sourceText[cursor];
        if (char === "(") {
            parenDepth += 1;
            seenOpenParen = true;
            continue;
        }
        if (char === ")") {
            parenDepth -= 1;
            if (seenOpenParen && parenDepth === 0) {
                cursor += 1;
                break;
            }
        }
    }
    let depth = 0;
    for (; cursor < sourceText.length; cursor += 1) {
        const char = sourceText[cursor];
        if (char === "{") depth += 1;
        if (char === "}") {
            depth -= 1;
            if (depth === 0) {
                return sourceText.slice(startIndex, cursor + 1);
            }
        }
    }
    throw new Error(`Could not parse function ${functionName}`);
}

function makeDispatchers() {
    // Tiny stand-in for undici's Agent; we don't run real HTTPS in the
    // test, so we just record the constructor options so the test can
    // assert that ``rejectUnauthorized: false`` was passed.
    const constructCalls = [];
    class FakeAgent {
        constructor(options) {
            this.options = options || {};
            constructCalls.push(this.options);
        }
    }
    return { FakeAgent, constructCalls };
}

function makeMetricsVm({ dispatcherOutcome, fetchBody } = {}) {
    const sourceText = fs.readFileSync(MAIN_PATH, "utf8");
    const fnSources = [
        "isMetricsAllowInsecureTls",
        "getInsecureMetricsDispatcher",
        "flushMetricsQueue",
    ]
        .map((name) => extractFunctionDeclaration(sourceText, name))
        .join("\n\n");

    const { FakeAgent, constructCalls } = makeDispatchers();
    const fetchCalls = [];
    const logLines = [];
    const appVersion = "test-version-1.2.3";
    const { DEFAULT_SETTINGS, normalizeSettings } = require(SETTINGS_PATH);

    const baseContext = {
        console,
        Agent: FakeAgent,
        app: { getVersion: () => appVersion },
        process: { platform: "linux" },
        String,
        Number,
        Math,
        Boolean,
        Array,
        Object,
        JSON,
        URL,
        Map,
        URLSearchParams,
        Error,
        Promise,
        setTimeout,
        clearTimeout,
        AbortController,
        Headers,
        platform: "linux",
        userAgent: "PacketSnitch/test",
        undiciFetch: async (url, init) => {
            fetchCalls.push({ url, init });
            if (typeof dispatcherOutcome === "function") {
                return dispatcherOutcome({ url, init });
            }
            return {
                status: 200,
                ok: true,
                async text() {
                    return fetchBody || "";
                },
                async json() {
                    return fetchBody ? JSON.parse(fetchBody) : {};
                },
            };
        },
        appendActivityLogLine: (line) => {
            logLines.push(line);
        },
        getMetricsPrivacy: () => privacySettings,
        getAppSettings: () => currentSettings,
        insecureMetricsDispatcherCache: new Map(),
        METRICS_HTTP_TIMEOUT_MS: 5000,
        METRICS_MAX_EVENT_BATCH: 1000,
    };

    let privacySettings = {};
    let currentSettings = DEFAULT_SETTINGS;
    const context = { ...baseContext };
    vm.createContext(context);
    // Bind the cache and constants the runner needs before evaluating
    // the source. The dispatcher cache is checked by reference, so we
    // hand it in via the globals.
    context.insecureMetricsDispatcherCache = baseContext.insecureMetricsDispatcherCache;
    context.METRICS_HTTP_TIMEOUT_MS = baseContext.METRICS_HTTP_TIMEOUT_MS;
    context.METRICS_MAX_EVENT_BATCH = baseContext.METRICS_MAX_EVENT_BATCH;
    vm.runInContext(fnSources, context);

    const setPrivacy = (nextPrivacy) => {
        privacySettings = nextPrivacy;
        currentSettings = normalizeSettings({
            ...DEFAULT_SETTINGS,
            privacy: nextPrivacy,
        });
    };

    return {
        context,
        fetchCalls,
        constructCalls,
        logLines,
        setPrivacy,
    };
}

describe("metrics flush self-signed-cert support", () => {
    test("isMetricsAllowInsecureTls reads the locked allowInsecureTlsEndpoints flag", () => {
        const harness = makeMetricsVm();
        // The default settings lock `allowInsecureTlsEndpoints` to true.
        expect(harness.context.isMetricsAllowInsecureTls()).toBe(true);
        // Patch the settings helper to return `false` so we can prove
        // that the gate is actually read live (the normalizer locks the
        // default to true, so we have to bypass it).
        const originalGetAppSettings = harness.context.getAppSettings;
        harness.context.getAppSettings = () => ({
            general: {
                allowInsecureTlsEndpoints: false,
            },
        });
        expect(harness.context.isMetricsAllowInsecureTls()).toBe(false);
        harness.context.getAppSettings = originalGetAppSettings;
    });

    test("getInsecureMetricsDispatcher returns an Agent with rejectUnauthorized=false", () => {
        const harness = makeMetricsVm();
        harness.context.METRICS_HTTP_TIMEOUT_MS = 5000;
        const dispatcher = harness.context.getInsecureMetricsDispatcher(5000);
        expect(dispatcher).toBeDefined();
        expect(dispatcher.options).toBeDefined();
        expect(dispatcher.options.connect).toBeDefined();
        expect(dispatcher.options.connect.rejectUnauthorized).toBe(false);
        expect(dispatcher.options.headersTimeout).toBeGreaterThanOrEqual(1000);
        expect(dispatcher.options.bodyTimeout).toBeGreaterThanOrEqual(1000);
        expect(harness.constructCalls.length).toBe(1);
    });

    test("getInsecureMetricsDispatcher caches dispatchers by timeout", () => {
        const harness = makeMetricsVm();
        const first = harness.context.getInsecureMetricsDispatcher(5000);
        const second = harness.context.getInsecureMetricsDispatcher(5000);
        expect(first).toBe(second);
        expect(harness.constructCalls.length).toBe(1);
        const third = harness.context.getInsecureMetricsDispatcher(7000);
        expect(third).not.toBe(first);
        expect(harness.constructCalls.length).toBe(2);
    });

    test("HTTPS endpoint attaches the insecure dispatcher when allowInsecureTlsEndpoints is true", async () => {
        const harness = makeMetricsVm();
        harness.setPrivacy({
            metricsEnabled: true,
            metricsConsentAsked: true,
            metricsEndpointUrl: "https://example.invalid:9021/mhook",
            metricsInstallId: "11111111-2222-3333-4444-555555555555",
        });
        const result = await harness.context.flushMetricsQueue({
            events: [{ name: "test.event", ts: new Date().toISOString() }],
            sentAt: "2024-01-01T00:00:00.000Z",
        });
        expect(result.ok).toBe(true);
        expect(harness.fetchCalls.length).toBe(1);
        const fetchInit = harness.fetchCalls[0].init;
        expect(fetchInit.dispatcher).toBeDefined();
        expect(fetchInit.dispatcher.options.connect.rejectUnauthorized).toBe(false);
        const insecureTlsLog = harness.logLines.find((line) => line.includes("insecureTls=true"));
        expect(insecureTlsLog).toBeDefined();
    });

    test("HTTPS endpoint omits the dispatcher when allowInsecureTlsEndpoints is false", async () => {
        const harness = makeMetricsVm();
        // Drop the dispatcher cache so the previous test's allow=true
        // agent doesn't leak into this one.
        harness.context.insecureMetricsDispatcherCache.clear();
        // `normalizeSettings` always locks `allowInsecureTlsEndpoints` to
        // true, so we have to bypass the normalizer and patch the
        // settings object directly. That's the same object the
        // flushMetricsQueue function will see via
        // `getAppSettings()?.general?.allowInsecureTlsEndpoints`.
        harness.context.getAppSettings = () => ({
            general: {
                allowInsecureTlsEndpoints: false,
            },
        });
        harness.setPrivacy({
            metricsEnabled: true,
            metricsConsentAsked: true,
            metricsEndpointUrl: "https://example.invalid:9021/mhook",
            metricsInstallId: "22222222-3333-4444-5555-666666666666",
        });
        const result = await harness.context.flushMetricsQueue({
            events: [{ name: "test.event", ts: new Date().toISOString() }],
            sentAt: "2024-01-01T00:00:00.000Z",
        });
        expect(result.ok).toBe(true);
        expect(harness.fetchCalls.length).toBe(1);
        const fetchInit = harness.fetchCalls[0].init;
        expect(fetchInit.dispatcher).toBeUndefined();
        const insecureTlsLog = harness.logLines.find((line) => line.includes("insecureTls=false"));
        expect(insecureTlsLog).toBeDefined();
    });

    test("plain HTTP endpoint never attaches the insecure dispatcher", async () => {
        const harness = makeMetricsVm();
        harness.setPrivacy({
            metricsEnabled: true,
            metricsConsentAsked: true,
            metricsEndpointUrl: "http://127.0.0.1:8088/mhook",
            metricsInstallId: "33333333-4444-5555-6666-777777777777",
        });
        const result = await harness.context.flushMetricsQueue({
            events: [{ name: "test.event", ts: new Date().toISOString() }],
            sentAt: "2024-01-01T00:00:00.000Z",
        });
        expect(result.ok).toBe(true);
        expect(harness.fetchCalls.length).toBe(1);
        expect(harness.fetchCalls[0].init.dispatcher).toBeUndefined();
    });

    test("flushMetricsQueue flags isTlsError=true when the transport throws a TLS error", async () => {
        const harness = makeMetricsVm({
            dispatcherOutcome: () => {
                const error = new Error("unable to verify the first certificate: self-signed certificate");
                throw error;
            },
        });
        harness.setPrivacy({
            metricsEnabled: true,
            metricsConsentAsked: true,
            metricsEndpointUrl: "https://example.invalid:9021/mhook",
            metricsInstallId: "44444444-5555-6666-7777-888888888888",
        });
        const result = await harness.context.flushMetricsQueue({
            events: [{ name: "test.event", ts: new Date().toISOString() }],
            sentAt: "2024-01-01T00:00:00.000Z",
        });
        expect(result.ok).toBe(false);
        expect(result.isTlsError).toBe(true);
        expect(result.error).toMatch(/self-signed/);
    });

    test("flushMetricsQueue flags isTlsError=false on non-TLS failures", async () => {
        const harness = makeMetricsVm({
            dispatcherOutcome: () => {
                const error = new Error("ECONNREFUSED 127.0.0.1:9999");
                throw error;
            },
        });
        harness.setPrivacy({
            metricsEnabled: true,
            metricsConsentAsked: true,
            metricsEndpointUrl: "https://example.invalid:9021/mhook",
            metricsInstallId: "55555555-6666-7777-8888-999999999999",
        });
        const result = await harness.context.flushMetricsQueue({
            events: [{ name: "test.event", ts: new Date().toISOString() }],
            sentAt: "2024-01-01T00:00:00.000Z",
        });
        expect(result.ok).toBe(false);
        expect(result.isTlsError).toBe(false);
    });

    test("flushMetricsQueue short-circuits when metricsEnabled is false", async () => {
        const harness = makeMetricsVm();
        harness.setPrivacy({
            metricsEnabled: false,
            metricsConsentAsked: true,
            metricsEndpointUrl: "https://example.invalid/mhook",
            metricsInstallId: "",
        });
        const result = await harness.context.flushMetricsQueue({
            events: [{ name: "ignored.event" }],
        });
        expect(result.ok).toBe(false);
        expect(result.error).toBe("disabled");
        expect(harness.fetchCalls.length).toBe(0);
    });

    test("flushMetricsQueue returns endpoint-protocol for non-http(s) URLs", async () => {
        const harness = makeMetricsVm();
        harness.setPrivacy({
            metricsEnabled: true,
            metricsConsentAsked: true,
            metricsEndpointUrl: "ftp://example.invalid/mhook",
            metricsInstallId: "",
        });
        const result = await harness.context.flushMetricsQueue({
            events: [{ name: "test.event" }],
        });
        expect(result.ok).toBe(false);
        expect(result.error).toBe("endpoint-protocol");
        expect(harness.fetchCalls.length).toBe(0);
    });
});

describe("metrics:status IPC handler exposes insecureTls", () => {
    test("metrics:status returns insecureTls=true for HTTPS endpoints when the locked flag is true", () => {
        const sourceText = fs.readFileSync(MAIN_PATH, "utf8");
        // The handler must build the response with insecureTls when the
        // endpoint is https and the flag is enabled.
        expect(sourceText).toMatch(
            /insecureTls\s*=\s*true/,
        );
        // Both the http and the https + locked flag branches must be
        // present.
        expect(sourceText).toMatch(/endpointProtocol\s*=\s*parsedUrl\.protocol/);
        expect(sourceText).toMatch(/isMetricsAllowInsecureTls\(\)/);
    });

    test("renderer's cachedMetricsDiagnostics records insecureTls / endpointProtocol", () => {
        const rendererPath = path.join(PROJECT_ROOT, "src", "ui", "main-frontend.js");
        const source = fs.readFileSync(rendererPath, "utf8");
        expect(source).toMatch(/endpointProtocol:\s*String\(status\?\.endpointProtocol/);
        expect(source).toMatch(/insecureTls:\s*Boolean\(status\?\.insecureTls\)/);
        expect(source).toMatch(/allowInsecureTls:\s*Boolean\(status\?\.allowInsecureTls\)/);
    });

    test("renderer renders the TLS pill in the diagnostics row", () => {
        const rendererPath = path.join(PROJECT_ROOT, "src", "ui", "main-frontend.js");
        const source = fs.readFileSync(rendererPath, "utf8");
        expect(source).toMatch(/settings-api-keys-metrics-tls-status/);
        expect(source).toMatch(/Self-signed allowed/);
    });

    test("index.html includes the TLS pill in the diagnostics row", () => {
        const htmlPath = path.join(PROJECT_ROOT, "src", "index.html");
        const html = fs.readFileSync(htmlPath, "utf8");
        expect(html).toMatch(/id="settings-api-keys-metrics-tls-status"/);
    });
});

describe("settings.js self-signed-cert defaults", () => {
    test("allowInsecureTlsEndpoints is locked to true", () => {
        const settings = require(SETTINGS_PATH);
        expect(settings.DEFAULT_SETTINGS.general.allowInsecureTlsEndpoints).toBe(true);
        const normalized = settings.normalizeSettings({
            ...settings.DEFAULT_SETTINGS,
            general: {
                ...settings.DEFAULT_SETTINGS.general,
                // User attempts to flip it off — normalizer must ignore.
                allowInsecureTlsEndpoints: false,
            },
        });
        expect(normalized.general.allowInsecureTlsEndpoints).toBe(true);
    });
});

describe("normalizeEndpointUrl preserves the user's chosen scheme", () => {
    // The default metrics endpoint is plain HTTP
    // (``http://64.227.4.43:8088/mhook``). Self-hosters also
    // commonly run the open-source collector over plain HTTP on
    // their own box. ``normalizeEndpointUrl`` must not silently
    // rewrite ``http://`` to ``https://`` for non-loopback hosts,
    // because doing so produces confusing "fetch failed" errors
    // against the production endpoint and breaks the self-hosted
    // use case entirely. HTTPS still works when the user types
    // it.
    const settings = require(SETTINGS_PATH);
    const { normalizeEndpointUrl } = settings;
    const fallback = "http://64.227.4.43:8088/mhook";

    test("the default endpoint is plain HTTP", () => {
        expect(settings.DEFAULT_SETTINGS.privacy.metricsEndpointUrl).toBe(fallback);
    });

    test("preserves HTTP for the default non-loopback host", () => {
        const result = normalizeEndpointUrl(
            "http://64.227.4.43:8088/mhook",
            fallback,
        );
        expect(result.startsWith("http://")).toBe(true);
        expect(result.startsWith("https://")).toBe(false);
    });

    test("preserves HTTP for loopback hosts", () => {
        const result = normalizeEndpointUrl(
            "http://127.0.0.1:8088/mhook",
            fallback,
        );
        expect(result.startsWith("http://")).toBe(true);
        expect(result.startsWith("https://")).toBe(false);
    });

    test("preserves HTTP for self-hosted collector hostnames", () => {
        const result = normalizeEndpointUrl(
            "http://metrics.example.com:8088/mhook",
            fallback,
        );
        expect(result.startsWith("http://")).toBe(true);
        expect(result.startsWith("https://")).toBe(false);
    });

    test("preserves HTTPS when the user types it", () => {
        const result = normalizeEndpointUrl(
            "https://metrics.example.com:8443/mhook",
            fallback,
        );
        expect(result.startsWith("https://")).toBe(true);
    });

    test("falls back to default for empty / non-string values", () => {
        expect(normalizeEndpointUrl("", fallback)).toBe(fallback);
        expect(normalizeEndpointUrl("   ", fallback)).toBe(fallback);
        expect(normalizeEndpointUrl(null, fallback)).toBe(fallback);
        expect(normalizeEndpointUrl(undefined, fallback)).toBe(fallback);
        expect(normalizeEndpointUrl(42, fallback)).toBe(fallback);
    });

    test("falls back to default for non-http(s) schemes", () => {
        // ``ftp://`` is not a valid metrics transport. The
        // normalizer must reject it and return the default.
        expect(normalizeEndpointUrl("ftp://example.com/mhook", fallback)).toBe(fallback);
        expect(normalizeEndpointUrl("file:///etc/passwd", fallback)).toBe(fallback);
        expect(normalizeEndpointUrl("ws://example.com/mhook", fallback)).toBe(fallback);
    });

    test("falls back to default for malformed URLs", () => {
        // ``URL`` will accept ``not a url`` and parse it as
        // ``not-a-url:`` -- a non-http(s) protocol -- so the
        // function correctly falls back. We assert that the
        // returned value is the fallback (i.e. we did not
        // preserve the bogus scheme).
        expect(normalizeEndpointUrl("not a url", fallback)).toBe(fallback);
    });

    test("normalizeSettings leaves the default as HTTP", () => {
        // Going through the full normalizeSettings path is the
        // real-world regression guard. If a future refactor
        // reintroduces a scheme-rewriting helper anywhere, this
        // test will fail and the production endpoint will start
        // failing with "fetch failed" again.
        const normalized = settings.normalizeSettings(settings.cloneDefaultSettings());
        expect(normalized.privacy.metricsEndpointUrl).toBe(fallback);
        expect(normalized.privacy.metricsEndpointUrl.startsWith("http://")).toBe(true);
    });

    test("normalizeSettings preserves an http:// user value on non-loopback hosts", () => {
        const normalized = settings.normalizeSettings({
            ...settings.DEFAULT_SETTINGS,
            privacy: {
                ...settings.DEFAULT_SETTINGS.privacy,
                metricsEndpointUrl: "http://metrics.example.com:8088/mhook",
            },
        });
        expect(normalized.privacy.metricsEndpointUrl).toBe(
            "http://metrics.example.com:8088/mhook",
        );
    });

    test("normalizeSettings preserves an https:// user value", () => {
        const normalized = settings.normalizeSettings({
            ...settings.DEFAULT_SETTINGS,
            privacy: {
                ...settings.DEFAULT_SETTINGS.privacy,
                metricsEndpointUrl: "https://metrics.example.com:8443/mhook",
            },
        });
        expect(normalized.privacy.metricsEndpointUrl).toBe(
            "https://metrics.example.com:8443/mhook",
        );
    });

    test("normalizeSettings falls back to the default when the URL is invalid", () => {
        const normalized = settings.normalizeSettings({
            ...settings.DEFAULT_SETTINGS,
            privacy: {
                ...settings.DEFAULT_SETTINGS.privacy,
                metricsEndpointUrl: "ftp://example.com/mhook",
            },
        });
        expect(normalized.privacy.metricsEndpointUrl).toBe(fallback);
    });
});
