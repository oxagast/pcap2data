// Session payload validation for import / load paths.
//
// The canonical PacketSnitch session file is a JSON document (often gzipped
// BSON, .psb) shaped like:
//
//   {
//     "capture.data": {
//       "host": { "<host>": [ <packet>, ... ], ... },
//       "final.summary": "..."   // optional
//     },
//     "session.state": { ... }    // optional, renderer-side snapshot
//   }
//
// Older sessions omit the "capture.data" wrapper and place the host map at
// the root, sometimes using the legacy "Host" key. The helpers below accept
// both shapes and report a structured validation result so callers can show
// the user a precise error instead of importing garbage into the library.
//
// This module is dependency-free (no Electron / no DOM) so it can be required
// from both the main process (`src/main.js`) and Jest tests.

"use strict";

const SESSION_CAPTURE_KEY = "capture.data";
const SESSION_STATE_KEY = "session.state";

/**
 * Normalise the parsed payload into a { captureData, sessionState, legacy }
 * triple, or return null when the payload does not look like a session at
 * all. `legacy` is true when the payload used the root-level / "Host" shape
 * rather than the modern "capture.data" wrapper.
 */
function normalizeSessionPayload(parsed) {
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        return null;
    }

    const hasWrappedCapture =
        parsed[SESSION_CAPTURE_KEY] &&
        typeof parsed[SESSION_CAPTURE_KEY] === "object" &&
        !Array.isArray(parsed[SESSION_CAPTURE_KEY]);

    if (hasWrappedCapture) {
        return {
            captureData: parsed[SESSION_CAPTURE_KEY],
            sessionState:
                parsed[SESSION_STATE_KEY] &&
                    typeof parsed[SESSION_STATE_KEY] === "object" &&
                    !Array.isArray(parsed[SESSION_STATE_KEY])
                    ? parsed[SESSION_STATE_KEY]
                    : null,
            legacy: false,
        };
    }

    // Legacy shape: the host map lives at the root.
    if (typeof parsed === "object" && !Array.isArray(parsed)) {
        return {
            captureData: parsed,
            sessionState: null,
            legacy: true,
        };
    }

    return null;
}

function isPlainObject(value) {
    return (
        value !== null &&
        typeof value === "object" &&
        !Array.isArray(value)
    );
}

/**
 * Validate that a parsed payload matches the expected PacketSnitch session
 * structure. Returns { valid, error?, legacy? }.
 *
 * The minimum requirement is a host map (under "capture.data" for modern
 * sessions, or at the root / under "Host" for legacy sessions) containing at
 * least one host entry. Each host entry must be an array of packet objects.
 */
function validateSessionPayload(parsed) {
    if (parsed === null || parsed === undefined) {
        return { valid: false, error: "Session payload is empty" };
    }
    if (!isPlainObject(parsed)) {
        return {
            valid: false,
            error:
                "Session payload must be a JSON object (got " +
                (Array.isArray(parsed) ? "array" : typeof parsed) +
                ")",
        };
    }

    const normalized = normalizeSessionPayload(parsed);
    if (!normalized) {
        return { valid: false, error: "Session payload is not a valid session object" };
    }

    const { captureData, legacy } = normalized;
    if (!isPlainObject(captureData)) {
        return {
            valid: false,
            error: "Missing \"capture.data\" object in session payload",
        };
    }

    const hostMap =
        isPlainObject(captureData.host)
            ? captureData.host
            : isPlainObject(captureData.Host)
                ? captureData.Host
                : null;

    if (!hostMap) {
        return {
            valid: false,
            error:
                "Session payload is missing the \"host\" map (capture.data.host). " +
                "The file does not appear to be a PacketSnitch session.",
        };
    }

    const hostNames = Object.keys(hostMap);
    if (hostNames.length === 0) {
        return {
            valid: false,
            error: "Session payload has an empty \"host\" map — nothing to import",
        };
    }

    // Validate that each host entry is an array of packet objects. We only
    // sample-check the first host to keep validation cheap, but verify that at
    // least one host has a non-empty packet array.
    let anyPackets = false;
    for (const name of hostNames) {
        const entry = hostMap[name];
        if (!Array.isArray(entry)) {
            return {
                valid: false,
                error:
                    "Host entry \"" + name + "\" is not an array of packets",
            };
        }
        if (entry.length > 0) {
            anyPackets = true;
            // Spot-check the first packet is an object.
            const first = entry[0];
            if (!isPlainObject(first)) {
                return {
                    valid: false,
                    error:
                        "First packet under host \"" + name + "\" is not an object",
                };
            }
        }
    }

    if (!anyPackets) {
        return {
            valid: false,
            error: "Session payload contains no packets across any host entry",
        };
    }

    // Optional: validate session.state shape if present on the wrapped payload.
    // A present-but-non-object session.state is a structural error, not a
    // missing-field condition.
    const rawSessionState =
        isPlainObject(parsed[SESSION_CAPTURE_KEY]) ? parsed[SESSION_STATE_KEY] : undefined;
    if (rawSessionState !== undefined && rawSessionState !== null && !isPlainObject(rawSessionState)) {
        return {
            valid: false,
            error: "\"session.state\" must be an object when present",
        };
    }

    return { valid: true, legacy };
}

/**
 * Convenience wrapper: parse a JSON string and validate it. Returns
 * { valid, error?, legacy?, parsed? }.
 */
function validateSessionJsonString(jsonString) {
    if (typeof jsonString !== "string" || jsonString.trim() === "") {
        return { valid: false, error: "Session file is empty" };
    }
    let parsed;
    try {
        parsed = JSON.parse(jsonString);
    } catch (err) {
        return {
            valid: false,
            error: "File is not valid JSON: " + (err && err.message ? err.message : String(err)),
        };
    }
    const result = validateSessionPayload(parsed);
    if (result.valid) {
        return { valid: true, legacy: result.legacy, parsed };
    }
    return { valid: false, error: result.error };
}

module.exports = {
    SESSION_CAPTURE_KEY,
    SESSION_STATE_KEY,
    normalizeSessionPayload,
    validateSessionPayload,
    validateSessionJsonString,
};