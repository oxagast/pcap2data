// Tests for src/session-format.js — the shared, dependency-free session
// payload validator used by the session-import IPC handler.
//
// The canonical PacketSnitch session is { "capture.data": { host: {...} } }.
// Legacy sessions place the host map at the root (and sometimes use "Host").
// The validator must accept both shapes and reject anything that does not
// look like a session with a precise error message.

const path = require("path");

let sessionFormat;

beforeEach(() => {
    jest.resetModules();
    sessionFormat = require(path.resolve("src/session-format"));
});

function makeModernSession() {
    return {
        "capture.data": {
            host: {
                "10.0.0.1": [
                    { "packet.info": { index: 0, src: "10.0.0.1" } },
                ],
            },
            "final.summary": "ok",
        },
        "session.state": {
            schemaVersion: 2,
            savedAt: "2026-09-01T00:00:00.000Z",
        },
    };
}

describe("validateSessionJsonString — modern format", () => {
    test("accepts a well-formed modern session payload", () => {
        const result = sessionFormat.validateSessionJsonString(
            JSON.stringify(makeModernSession()),
        );
        expect(result.valid).toBe(true);
        expect(result.legacy).toBe(false);
        expect(result.parsed).toBeTruthy();
    });

    test("accepts the session.state block as optional", () => {
        const session = makeModernSession();
        delete session["session.state"];
        const result = sessionFormat.validateSessionJsonString(JSON.stringify(session));
        expect(result.valid).toBe(true);
    });
});

describe("validateSessionJsonString — legacy format", () => {
    test("accepts a root-level host map (pre capture.data wrapper)", () => {
        const legacy = {
            host: {
                "10.0.0.2": [{ "packet.info": { index: 0 } }],
            },
        };
        const result = sessionFormat.validateSessionJsonString(JSON.stringify(legacy));
        expect(result.valid).toBe(true);
        expect(result.legacy).toBe(true);
    });

    test("accepts the legacy capitalized Host key", () => {
        const legacy = {
            Host: {
                "10.0.0.3": [{ "packet.info": { index: 0 } }],
            },
        };
        const result = sessionFormat.validateSessionJsonString(JSON.stringify(legacy));
        expect(result.valid).toBe(true);
        expect(result.legacy).toBe(true);
    });
});

describe("validateSessionJsonString — rejection cases", () => {
    test("rejects an empty string", () => {
        const result = sessionFormat.validateSessionJsonString("");
        expect(result.valid).toBe(false);
        expect(result.error).toMatch(/empty/i);
    });

    test("rejects a non-JSON string", () => {
        const result = sessionFormat.validateSessionJsonString("not json {");
        expect(result.valid).toBe(false);
        expect(result.error).toMatch(/not valid JSON/i);
    });

    test("rejects a JSON array", () => {
        const result = sessionFormat.validateSessionJsonString("[1, 2, 3]");
        expect(result.valid).toBe(false);
        expect(result.error).toMatch(/object/i);
    });

    test("rejects a JSON object without a host map", () => {
        const result = sessionFormat.validateSessionJsonString(JSON.stringify({ foo: "bar" }));
        expect(result.valid).toBe(false);
        expect(result.error).toMatch(/host/i);
    });

    test("rejects an empty host map", () => {
        const result = sessionFormat.validateSessionJsonString(
            JSON.stringify({ "capture.data": { host: {} } }),
        );
        expect(result.valid).toBe(false);
        expect(result.error).toMatch(/empty/i);
    });

    test("rejects a host entry that is not an array", () => {
        const result = sessionFormat.validateSessionJsonString(
            JSON.stringify({ "capture.data": { host: { "10.0.0.1": "not-an-array" } } }),
        );
        expect(result.valid).toBe(false);
        expect(result.error).toMatch(/not an array/i);
    });

    test("rejects a payload with no packets across any host", () => {
        const result = sessionFormat.validateSessionJsonString(
            JSON.stringify({ "capture.data": { host: { "10.0.0.1": [] } } }),
        );
        expect(result.valid).toBe(false);
        expect(result.error).toMatch(/no packets/i);
    });

    test("rejects a first packet that is not an object", () => {
        const result = sessionFormat.validateSessionJsonString(
            JSON.stringify({ "capture.data": { host: { "10.0.0.1": ["string-packet"] } } }),
        );
        expect(result.valid).toBe(false);
        expect(result.error).toMatch(/not an object/i);
    });

    test("rejects a session.state that is not an object", () => {
        const session = makeModernSession();
        session["session.state"] = "not-an-object";
        const result = sessionFormat.validateSessionJsonString(JSON.stringify(session));
        expect(result.valid).toBe(false);
        expect(result.error).toMatch(/session\.state/i);
    });
});

describe("validateSessionPayload — direct object API", () => {
    test("rejects null/undefined", () => {
        expect(sessionFormat.validateSessionPayload(null).valid).toBe(false);
        expect(sessionFormat.validateSessionPayload(undefined).valid).toBe(false);
    });

    test("rejects a non-object (array)", () => {
        const result = sessionFormat.validateSessionPayload([1, 2]);
        expect(result.valid).toBe(false);
    });

    test("returns legacy flag for root-level host map", () => {
        const result = sessionFormat.validateSessionPayload({ host: { h: [{}] } });
        expect(result.valid).toBe(true);
        expect(result.legacy).toBe(true);
    });
});

describe("normalizeSessionPayload", () => {
    test("extracts capture.data + session.state for the modern shape", () => {
        const modern = makeModernSession();
        const normalized = sessionFormat.normalizeSessionPayload(modern);
        expect(normalized.legacy).toBe(false);
        expect(normalized.captureData).toBe(modern["capture.data"]);
        expect(normalized.sessionState).toBe(modern["session.state"]);
    });

    test("treats a root-level host map as legacy", () => {
        const legacy = { host: { h: [{}] } };
        const normalized = sessionFormat.normalizeSessionPayload(legacy);
        expect(normalized.legacy).toBe(true);
        expect(normalized.captureData).toBe(legacy);
        expect(normalized.sessionState).toBeNull();
    });
});