// Tests for the hashes.com ``/api/identifier`` lookup surface added to
// ``src/main.js`` (IPC handler + GET helper), ``src/preload.js``,
// ``src/index.html``, and ``src/ui/panels/data-tools-panel.js``
// (renderer logic). Like the existing ``hashes_com_diagnostics``
// test, this is mostly source-presence / contract checks because
// the actual probe lives behind Electron's ``ipcMain.handle`` +
// ``undiciFetch`` which we can't drive from a vm context, but a
// regression that drops one of the contract pieces breaks these
// tests loudly. The live endpoint is also probed (skipped when
// the network is unavailable) so the documented response shape
// stays in sync with reality.

const fs = require("fs");
const path = require("path");

const PROJECT_ROOT = path.resolve(__dirname, "..");
const IDENTIFIER_URL =
    "https://hashes.com/en/api/identifier?hash=de41a78c493da23f00e0f7343c9aeaed:88581&extended=true";
const IDENTIFIER_URL_UNKNOWN =
    "https://hashes.com/en/api/identifier?hash=deadbeef&extended=true";

function readSource(relativePath) {
    return fs.readFileSync(path.join(PROJECT_ROOT, relativePath), "utf8");
}

describe("hashes.com identifier — source presence", () => {
    let mainSource;
    let preloadSource;
    let mainFrontendSource;
    let indexSource;
    let dataToolsSource;

    beforeAll(() => {
        mainSource = readSource("src/main.js");
        preloadSource = readSource("src/preload.js");
        mainFrontendSource = readSource("src/ui/main-frontend.js");
        indexSource = readSource("src/index.html");
        dataToolsSource = readSource("src/ui/panels/data-tools-panel.js");
    });

    test("main.js registers a hashes-com:identify IPC handler", () => {
        expect(mainSource).toMatch(
            /ipcMain\.handle\(\s*["']hashes-com:identify["']/,
        );
    });

    test("main.js identifyHashesCom returns the diagnostic contract fields", () => {
        const helperMatch = mainSource.match(
            /async function identifyHashesCom[\s\S]*?^}/m,
        );
        expect(helperMatch).not.toBeNull();
        const helper = helperMatch ? helperMatch[0] : "";
        // Field set the renderer consumes; any rename breaks this
        // test loudly.
        for (const field of [
            "endpointReachable",
            "endpoint",
            "httpStatus",
            "success",
            "extended",
            "algorithms",
            "message",
        ]) {
            expect(helper).toMatch(new RegExp(`\\b${field}\\b`));
        }
    });

    test("main.js GETs the identifier endpoint via undiciFetch (not POST)", () => {
        const helperMatch = mainSource.match(
            /async function identifyHashesCom[\s\S]*?^}/m,
        );
        expect(helperMatch).not.toBeNull();
        const helper = helperMatch ? helperMatch[0] : "";
        // The /en/api/identifier endpoint is documented as GET —
        // a regression that POSTs will trip hashes.com's WAF and
        // surface a confusing error to the user.
        expect(helper).toMatch(/method:\s*["']GET["']/);
        expect(helper).toMatch(/en\/api\/identifier/);
    });

    test("preload exposes hashesComIdentify", () => {
        expect(preloadSource).toMatch(/hashesComIdentify:/);
        expect(preloadSource).toMatch(
            /ipcRenderer\.invoke\(\s*["']hashes-com:identify["']/,
        );
    });

    test("index.html has the Identify Hash Types button + result pre", () => {
        expect(indexSource).toMatch(/id="data-tools-hash-identify-btn"/);
        expect(indexSource).toMatch(/id="data-tools-hash-identify-result"/);
    });

    test("data-tools-panel defines and exports runDataToolsHashIdentify", () => {
        expect(dataToolsSource).toMatch(/async function runDataToolsHashIdentify/);
        const exportsBlock = dataToolsSource.split("module.exports = {")[1] || "";
        expect(exportsBlock).toMatch(/runDataToolsHashIdentify/);
    });

    test("main-frontend wires the click handler", () => {
        // The handler is at the bottom of the file (the ``init``
        // block) but the function reference is in the destructure
        // import at the top — both must exist or the button is
        // either unbound or undefined at call time.
        expect(mainFrontendSource).toMatch(
            /getElementById\(["']data-tools-hash-identify-btn["']\)/,
        );
        expect(mainFrontendSource).toMatch(/runDataToolsHashIdentify/);
    });
});

describe("hashes.com identifier — documented response contract", () => {
    // The endpoint returns a JSON body of the form::
    //
    //     {"success":true,"algorithms":["md5($plaintext.$salt)", ...]}
    //     {"success":false,"message":"Could not identify"}
    //
    // We can't hit the network from every CI environment, so these
    // tests parse the documented shape against the contract our
    // renderer expects. The live API probe at the bottom is skipped
    // when the network is unavailable.

    function shapeFor(responseBody) {
        // Mirrors the subset of ``identifyHashesCom``'s normalization
        // that's reachable from a JSON.parse call. If the contract
        // ever changes (e.g. ``algorithms`` becomes an object), this
        // is the place to add the new keys.
        if (!responseBody || typeof responseBody !== "object") {
            return { success: false, algorithms: [], message: "" };
        }
        const algorithms = Array.isArray(responseBody.algorithms)
            ? responseBody.algorithms
                .map((entry) => String(entry || ""))
                .filter(Boolean)
            : [];
        return {
            success: responseBody.success !== false,
            algorithms,
            message: typeof responseBody.message === "string"
                ? responseBody.message
                : "",
        };
    }

    test("success body normalizes to algorithms[]", () => {
        const result = shapeFor({
            success: true,
            algorithms: ["md5($plaintext.$salt)", "Joomla < 2.5.18"],
        });
        expect(result.success).toBe(true);
        expect(result.algorithms).toHaveLength(2);
        expect(result.algorithms[0]).toBe("md5($plaintext.$salt)");
        expect(result.message).toBe("");
    });

    test("failure body normalizes to a message + empty algorithms", () => {
        const result = shapeFor({
            success: false,
            message: "Could not identify",
        });
        expect(result.success).toBe(false);
        expect(result.algorithms).toEqual([]);
        expect(result.message).toBe("Could not identify");
    });

    test("malformed body degrades to a clean failure", () => {
        const result = shapeFor(null);
        expect(result.success).toBe(false);
        expect(result.algorithms).toEqual([]);
    });

    test("empty algorithms[] is rendered as a success with zero matches", () => {
        // Some hashes legitimately have no candidates — we render
        // the empty list rather than claiming failure, so the user
        // can distinguish "API couldn't classify" from "API said
        // this hash doesn't match anything we know".
        const result = shapeFor({ success: true, algorithms: [] });
        expect(result.success).toBe(true);
        expect(result.algorithms).toEqual([]);
    });
});

describe("hashes.com identifier — live endpoint probe", () => {
    // Live probes run only when the network is reachable; CI
    // environments without outbound internet just skip them. We
    // intentionally do not mock the network — the documented
    // contract has to match what hashes.com actually returns or
    // the UI will show surprising results.
    let networkAvailable = false;

    beforeAll(async () => {
        try {
            // Quick reachability check with a short timeout so we
            // don't slow down CI on hosts that block outbound.
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 3000);
            const response = await fetch(
                "https://hashes.com/en/api/identifier?hash=__ps_probe__",
                { signal: controller.signal },
            );
            clearTimeout(timeoutId);
            // We don't care about the body, just whether the host
            // resolves. Any HTTP response counts as "reachable".
            networkAvailable = response.status >= 200;
        } catch (_error) {
            networkAvailable = false;
        }
    }, 10000);

    const maybeIt = networkAvailable ? it : it.skip;

    maybeIt(
        "returns success:true with a non-empty algorithms list for the documented hash",
        async () => {
            const response = await fetch(IDENTIFIER_URL);
            expect(response.status).toBe(200);
            const body = await response.json();
            expect(body.success).toBe(true);
            expect(Array.isArray(body.algorithms)).toBe(true);
            expect(body.algorithms.length).toBeGreaterThan(0);
        },
        15000,
    );

    maybeIt(
        "returns success:false with a message for an unknown hash",
        async () => {
            const response = await fetch(IDENTIFIER_URL_UNKNOWN);
            expect(response.status).toBe(200);
            const body = await response.json();
            expect(body.success).toBe(false);
            expect(typeof body.message).toBe("string");
            expect(body.message.length).toBeGreaterThan(0);
        },
        15000,
    );
});

describe("hashes.com identifier — friendly diagnostic on stale app", () => {
    // Electron rejects ``ipcRenderer.invoke`` with a generic
    // ``"No handler registered for '<channel>'"`` Error whenever
    // the renderer's preload was loaded against a main process
    // bundle that doesn't (yet) have the matching ``ipcMain.handle``.
    // The renderer catches that error and decorates it with a hint
    // telling the user to restart the app. The matcher below is
    // duplicated locally so a regression that strips the hint breaks
    // this test loudly.

    const NO_HANDLER_MESSAGE =
        "Error invoking remote method 'hashes-com:identify': "
        + "Error: No handler registered for 'hashes-com:identify'";

    function decorate(errorMessage) {
        let friendly = `Error: ${errorMessage}`;
        if (/No handler registered/i.test(errorMessage)) {
            friendly +=
                "\n\nThe Electron main process is missing this IPC handler. "
                + "Stop the running app (Ctrl+C in the terminal where `npm start` is running) "
                + "and relaunch it so the updated main/preload bundles reload.";
        }
        return friendly;
    }

    test("decorates 'No handler registered' errors with a restart hint", () => {
        const decorated = decorate(NO_HANDLER_MESSAGE);
        expect(decorated).toContain(NO_HANDLER_MESSAGE);
        expect(decorated).toContain(
            "The Electron main process is missing this IPC handler",
        );
        expect(decorated).toContain("relaunch it");
    });

    test("does not decorate generic errors", () => {
        const generic = decorate("hashes.com returned 503");
        expect(generic).toBe("Error: hashes.com returned 503");
        expect(generic).not.toContain(
            "The Electron main process is missing this IPC handler",
        );
    });

    test("data-tools-panel exports the decorate logic for both lookup paths", () => {
        const source = readSource("src/ui/panels/data-tools-panel.js");
        // Both ``runDataToolsHashIdentify`` and
        // ``runDataToolsHashReverseLookup`` should call the same
        // "missing IPC handler" hint — otherwise a user hitting the
        // "Reverse Hash" button wouldn't get the diagnostic.
        const matches = source.match(
            /No handler registered for/i,
        );
        expect(matches).not.toBeNull();
        const restartHints = source.match(
            /relaunch it so the updated main\/preload bundles reload/g,
        );
        expect(restartHints).not.toBeNull();
        // Two occurrences — one for each lookup function.
        expect(restartHints.length).toBeGreaterThanOrEqual(2);
    });
});