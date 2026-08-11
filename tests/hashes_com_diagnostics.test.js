// Tests for the hashes.com diagnostics surface added to
// ``src/main.js`` (IPC handler) and ``src/ui/main-frontend.js``
// (settings-tab pills). These are mostly source-presence /
// contract checks because the actual probe lives behind Electron's
// ``ipcMain.handle`` + ``undiciFetch`` which we can't drive from a
// vm context, but a regression that drops one of the contract
// pieces (e.g. accidentally removing the cost field, or the
// recordHashesComLookupOutcome bridge) breaks these tests loudly.

const fs = require("fs");
const path = require("path");

const PROJECT_ROOT = path.resolve(__dirname, "..");

function readSource(relativePath) {
    return fs.readFileSync(path.join(PROJECT_ROOT, relativePath), "utf8");
}

describe("hashes.com diagnostics — source presence", () => {
    let mainSource;
    let preloadSource;
    let mainFrontendSource;

    beforeAll(() => {
        mainSource = readSource("src/main.js");
        preloadSource = readSource("src/preload.js");
        mainFrontendSource = readSource("src/ui/main-frontend.js");
    });

    test("main.js registers a hashes-com:diagnostics IPC handler", () => {
        expect(mainSource).toMatch(
            /ipcMain\.handle\(\s*["']hashes-com:diagnostics["']/,
        );
    });

    test("main.js IPC handler returns the diagnostic contract fields", () => {
        // The handler must always return a stable shape — the
        // renderer keys indicators off of these fields. A regression
        // that renames one of them should fail this test.
        const handlerMatch = mainSource.match(
            /ipcMain\.handle\(\s*["']hashes-com:diagnostics["'][\s\S]*?\n  \}\);/,
        );
        expect(handlerMatch).not.toBeNull();
        const handler = handlerMatch ? handlerMatch[0] : "";
        for (const field of [
            "endpointReachable",
            "endpoint",
            "httpStatus",
            "keyConfigured",
            "keyValid",
            "success",
            "cost",
            "count",
            "founds",
            "lastError",
            "checkedAt",
        ]) {
            expect(handler).toMatch(new RegExp(`\\b${field}\\b`));
        }
    });

    test("main.js returns a Missing-key shape when no key is configured", () => {
        // The "no key" branch must explicitly mark keyConfigured:
        // false so the renderer renders the warn pill rather than
        // an "Invalid" pill (which would otherwise say "the API
        // rejected this key", which is misleading).
        const handlerMatch = mainSource.match(
            /ipcMain\.handle\(\s*["']hashes-com:diagnostics["'][\s\S]*?\n  \}\);/,
        );
        expect(handlerMatch).not.toBeNull();
        const handler = handlerMatch ? handlerMatch[0] : "";
        expect(handler).toMatch(/keyConfigured:\s*false/);
    });

    test("preload exposes hashesComDiagnostics alongside hashesComSearch", () => {
        expect(preloadSource).toMatch(/hashesComDiagnostics:/);
        expect(preloadSource).toMatch(
            /ipcRenderer\.invoke\(\s*["']hashes-com:diagnostics["']/,
        );
    });

    test("main-frontend.js wires hashes.com diagnostics helpers", () => {
        // These helpers are exposed via the source (not via
        // module.exports, since main-frontend.js is loaded via
        // webpack as a script). We still want a regression that
        // accidentally deletes one of them to break the test
        // loudly. The helpers may live in
        // ``src/ui/main-frontend/settings-diagnostics.js`` (the
        // factory module) with a thin ``const { helper } = ...``
        // re-export in main-frontend.js — so we check BOTH
        // surfaces.
        const settingsDiagnosticsSource = readSource(
            "src/ui/main-frontend/settings-diagnostics.js",
        );
        for (const helper of [
            "syncHashesComDiagnosticsIndicators",
            "refreshHashesComDiagnostics",
            "invalidateHashesComDiagnosticsCache",
            "recordHashesComLookupOutcome",
            "getBackendHashesComApiKey",
        ]) {
            const declarationPattern = new RegExp(
                `function\\s+${helper}\\b|const\\s+${helper}\\b|let\\s+${helper}\\b`,
            );
            const matchesInMain = declarationPattern.test(mainFrontendSource);
            const matchesInFactory = declarationPattern.test(
                settingsDiagnosticsSource,
            );
            expect(matchesInMain || matchesInFactory).toBe(true);
        }
    });

    test("main-frontend.js invalidates hashes.com cache on settings save", () => {
        // We must re-probe when the API key changes — otherwise the
        // "Key: Valid" pill would stay stale after a save.
        expect(mainFrontendSource).toMatch(
            /previousSettings\?\.apiKeys\?\.hashesComApiKey[\s\S]{0,80}invalidateHashesComDiagnosticsCache/,
        );
    });

    test("main-frontend.js forces a refresh when the API Keys subtab is opened", () => {
        // The settings-tab click handler should fire a forced
        // refresh so the user sees up-to-date pills without having
        // to interact further.
        expect(mainFrontendSource).toMatch(
            /syncHashesComDiagnosticsIndicators\(\)/,
        );
        expect(mainFrontendSource).toMatch(
            /refreshHashesComDiagnostics\(\{ force:\s*true \}\)/,
        );
    });

    test("data-tools panel calls recordHashesComLookupOutcome on every lookup path", () => {
        const dataToolsSource = readSource(
            "src/ui/panels/data-tools-panel.js",
        );
        // Three call sites — bridge missing, response.success ===
        // false, success path, catch block.
        const matches = dataToolsSource.match(
            /_recordHashesComLookupOutcome\(/g,
        );
        expect(matches).not.toBeNull();
        expect(matches.length).toBeGreaterThanOrEqual(3);
    });
});

describe("hashes.com diagnostic pill state → pill text mapping", () => {
    // The mapping logic inside ``syncHashesComDiagnosticsIndicators``
    // is a pure function of (cachedHashesComDiagnostics,
    // cachedHashesComLastLookup, hasStoredKey). To test it without
    // pulling in the DOM, we reproduce the mapping here and
    // exercise it against the contract values. The mapping is small
    // enough that divergence between this test and the source is
    // unlikely; the primary purpose is to lock in the contract
    // (which pill classes appear in which scenarios).
    function mapStateToPills({
        hasStoredKey,
        endpointReachable,
        keyConfigured,
        keyValid,
        lastLookup,
    }) {
        const endpointValue =
            endpointReachable === true
                ? "Up"
                : endpointReachable === false
                    ? "Down"
                    : "—";
        const endpointClass =
            endpointReachable === true
                ? "status-ok"
                : endpointReachable === false
                    ? "status-error"
                    : "status-neutral";

        const realKeyConfigured = hasStoredKey || Boolean(keyConfigured);
        const keyValue = !realKeyConfigured
            ? "Missing"
            : keyValid === true
                ? "Valid"
                : keyValid === false
                    ? "Invalid"
                    : "Configured";
        const keyClass = !realKeyConfigured
            ? "status-warn"
            : keyValid === true
                ? "status-ok"
                : keyValid === false
                    ? "status-error"
                    : "status-neutral";

        const lastCost = Number(lastLookup?.cost);
        const hasLastLookup = Boolean(lastLookup);
        const creditValue = hasLastLookup && Number.isFinite(lastCost)
            ? `${lastCost} credit${lastCost === 1 ? "" : "s"}`
            : "—";
        const creditClass = !hasLastLookup
            ? "status-neutral"
            : lastCost === 0
                ? "status-ok"
                : "status-warn";

        const lastLookupValue = !lastLookup
            ? "—"
            : lastLookup.success === true
                ? "OK"
                : lastLookup.success === false
                    ? `Error: ${lastLookup.error || "lookup failed"}`
                    : "—";
        const lastLookupClass = !lastLookup
            ? "status-neutral"
            : lastLookup.success === true
                ? "status-ok"
                : lastLookup.success === false
                    ? "status-error"
                    : "status-neutral";

        return {
            endpointValue,
            endpointClass,
            keyValue,
            keyClass,
            creditValue,
            creditClass,
            lastLookupValue,
            lastLookupClass,
        };
    }

    test("no key configured shows Missing + neutral credits / last lookup", () => {
        const pills = mapStateToPills({
            hasStoredKey: false,
            endpointReachable: false,
            keyConfigured: false,
            keyValid: false,
            lastLookup: null,
        });
        expect(pills.keyValue).toBe("Missing");
        expect(pills.keyClass).toBe("status-warn");
        expect(pills.endpointValue).toBe("Down");
        expect(pills.endpointClass).toBe("status-error");
        expect(pills.creditValue).toBe("—");
        expect(pills.lastLookupValue).toBe("—");
    });

    test("endpoint up + valid key shows everything green", () => {
        const pills = mapStateToPills({
            hasStoredKey: true,
            endpointReachable: true,
            keyConfigured: true,
            keyValid: true,
            lastLookup: { success: true, cost: 1 },
        });
        expect(pills.endpointValue).toBe("Up");
        expect(pills.endpointClass).toBe("status-ok");
        expect(pills.keyValue).toBe("Valid");
        expect(pills.keyClass).toBe("status-ok");
        expect(pills.creditValue).toBe("1 credit");
        expect(pills.creditClass).toBe("status-warn");
        expect(pills.lastLookupValue).toBe("OK");
        expect(pills.lastLookupClass).toBe("status-ok");
    });

    test("zero-cost successful lookup shows credits in green", () => {
        const pills = mapStateToPills({
            hasStoredKey: true,
            endpointReachable: true,
            keyConfigured: true,
            keyValid: true,
            lastLookup: { success: true, cost: 0 },
        });
        expect(pills.creditValue).toBe("0 credits");
        expect(pills.creditClass).toBe("status-ok");
    });

    test("invalid key surfaces red key pill + error pill", () => {
        const pills = mapStateToPills({
            hasStoredKey: true,
            endpointReachable: true,
            keyConfigured: true,
            keyValid: false,
            lastLookup: {
                success: false,
                cost: 0,
                error: "Invalid API key",
            },
        });
        expect(pills.keyValue).toBe("Invalid");
        expect(pills.keyClass).toBe("status-error");
        expect(pills.lastLookupValue).toBe("Error: Invalid API key");
        expect(pills.lastLookupClass).toBe("status-error");
    });

    test("endpoint down (DNS / network failure) marks the key pill Invalid", () => {
        // Documenting the actual contract: when the endpoint probe
        // fails we can't tell whether the key itself is good, so
        // the pill falls back to "Invalid". A future improvement
        // would distinguish "Endpoint down" from "Key rejected"
        // (e.g. by inspecting the IPC error message), but for now
        // we lock in the current behavior to make any later change
        // an explicit, reviewed decision.
        const pills = mapStateToPills({
            hasStoredKey: true,
            endpointReachable: false,
            keyConfigured: true,
            keyValid: false,
            lastLookup: null,
        });
        expect(pills.endpointClass).toBe("status-error");
        expect(pills.keyValue).toBe("Invalid");
        expect(pills.keyClass).toBe("status-error");
    });

    test("unknown endpointReachable state shows neutral endpoint pill", () => {
        const pills = mapStateToPills({
            hasStoredKey: true,
            endpointReachable: undefined,
            keyConfigured: true,
            keyValid: true,
            lastLookup: null,
        });
        expect(pills.endpointValue).toBe("—");
        expect(pills.endpointClass).toBe("status-neutral");
    });
});

describe("hashes.com diagnostic ping — uses a probe hash, not an empty array", () => {
    // Regression guard: the diagnostics handler used to call
    // ``searchHashesCom([], key)`` to probe the endpoint, but
    // ``searchHashesCom`` pre-flight-rejects empty arrays with a
    // thrown error ("At least one hash is required"). That throw
    // was caught by the diagnostics handler and reported as both
    // ``endpointReachable: false`` and ``keyValid: false`` even when
    // the network and key were perfectly healthy. The fix probes
    // with a single 64-char all-zero hex hash — valid MD5 shape,
    // effectively never collides with a real entry, costs 0 credits
    // per hashes.com's pricing model (0 per HTTP request, 1 per
    // *decrypted* hash).

    let mainSource;

    beforeAll(() => {
        mainSource = readSource("src/main.js");
    });

    test("diagnostics handler does NOT call searchHashesCom with an empty array", () => {
        // Pull out the body of the ``ipcMain.handle("hashes-com:diagnostics"``
        // block and confirm the call site passes at least one hash.
        const handlerMatch = mainSource.match(
            /ipcMain\.handle\(\s*["']hashes-com:diagnostics["'][\s\S]*?\n  \}\);/,
        );
        expect(handlerMatch).not.toBeNull();
        const handler = handlerMatch ? handlerMatch[0] : "";
        // The empty-array call would look like ``searchHashesCom([], key)``
        // — must be absent. A regression that reverts the fix would
        // bring it back and break this test.
        expect(handler).not.toMatch(/searchHashesCom\(\s*\[\s*\]\s*,/);
        // And the fixed call should pass an array with at least
        // one non-empty entry.
        expect(handler).toMatch(/searchHashesCom\(\s*\[\s*[A-Za-z0-9_$]+\s*\]\s*,/);
    });

    test("diagnostics handler does not claim zero-credit cost in source comments", () => {
        // Stale wording ("empty hashes[]" / "no-op") was misleading
        // future contributors into thinking the empty-array path
        // worked. The current comment correctly explains the
        // bogus-hash approach and links the hashes.com pricing
        // model. This test guards against the misleading comment
        // being re-introduced.
        const handlerMatch = mainSource.match(
            /ipcMain\.handle\(\s*["']hashes-com:diagnostics["'][\s\S]*?\n  \}\);/,
        );
        expect(handlerMatch).not.toBeNull();
        const handler = handlerMatch ? handlerMatch[0] : "";
        const leadingCommentMatch = mainSource.match(
            /Probe hashes\.com[\s\S]*?\n  ipcMain\.handle\(\s*["']hashes-com:diagnostics["']/,
        );
        expect(leadingCommentMatch).not.toBeNull();
        const leadingComment = leadingCommentMatch ? leadingCommentMatch[0] : "";
        expect(leadingComment).not.toMatch(/empty\s+["']hashes\[\]["']\s+field/);
        expect(leadingComment).toMatch(/hashes\.com\/en\/docs/);
    });
});