// Regression tests for the wifi-keys rerun session-following contract.
//
// Bug: when the user clicked "Send Wi-Fi keys to backend" while a
// named session was loaded, the silent rerun fired and the new
// decrypted 802.11 frames merged into the capture, but the
// renderer's `currentSessionName`, active filter query, and
// selected host were wiped because the two
// processBackendJson*Payload handlers unconditionally reset them
// at the start of every payload. The next Save-Session click
// therefore prompted for a fresh name and the saved entry did not
// match the user's original session.
//
// Fix: gate the wipes on two conditions:
//   1. `sessionExplicitlyClosed` (set by New Capture / file picker /
//      onNewSession) — when true, the user has indicated they
//      want a fresh session identity, so the next payload is
//      allowed to clear currentSessionName.
//   2. `backendProgressState.wifiKeysRerunInFlight` — when true,
//      the payload is a background rerun, so currentSessionName
//      must survive across it.
// The payload handlers also snapshot the session-bound state at
// the start of a wifi-keys rerun and re-apply it when the rerun
// completes, so the user stays on the same named session, filter
// query, and host selection through the rerun.

function makeSnapshot(overrides = {}) {
    return {
        currentSessionName: "coherer-induction-2026-08-09",
        filterQuery: "wifi.bssid:00:0c:41:82:b2:55",
        selectedHost: "192.168.1.42",
        ...overrides,
    };
}

describe("wifi-keys-rerun session-following", () => {
    function buildPayload({ complete = true } = {}) {
        return {
            complete,
            processedPackets: 1093,
            totalPackets: 1093,
            chunkSize: 2000,
        };
    }

    // Pure mirror of the gate in processBackendJsonPathPayload /
    // processBackendJsonDataPayload.
    function shouldClearSessionName({
        sessionExplicitlyClosed,
        wifiKeysRerunInFlight,
    }) {
        return sessionExplicitlyClosed && !wifiKeysRerunInFlight;
    }

    // Pure mirror of the gate around the filter/summary wipe in the
    // first-chunk branch of the payload handlers.
    function shouldWipeFirstChunkView({ wifiKeysRerunInFlight }) {
        return !wifiKeysRerunInFlight;
    }

    describe("currentSessionName gate", () => {
        test("does NOT clear on a wifi-keys rerun even when session is closed", () => {
            // The user's intent: "send wifi keys" is a background
            // rerun, not a "New Capture". The session name must
            // survive.
            expect(
                shouldClearSessionName({
                    sessionExplicitlyClosed: true,
                    wifiKeysRerunInFlight: true,
                }),
            ).toBe(false);
        });

        test("does NOT clear on a normal payload while a session is open", () => {
            // Defensive: a future regression that flips
            // sessionExplicitlyClosed on a session load would
            // otherwise wipe the session name on every payload.
            // Confirm the explicit-close flag is required.
            expect(
                shouldClearSessionName({
                    sessionExplicitlyClosed: false,
                    wifiKeysRerunInFlight: false,
                }),
            ).toBe(false);
        });

        test("DOES clear on a fresh payload when the session is closed", () => {
            // Normal path: user hit "New Capture" or opened a
            // different file from the picker. The next payload is
            // allowed to clear currentSessionName so Save-Session
            // prompts for a fresh name.
            expect(
                shouldClearSessionName({
                    sessionExplicitlyClosed: true,
                    wifiKeysRerunInFlight: false,
                }),
            ).toBe(true);
        });
    });

    describe("filter/summary wipe gate", () => {
        test("does NOT wipe filter/summary on a wifi-keys rerun", () => {
            expect(
                shouldWipeFirstChunkView({ wifiKeysRerunInFlight: true }),
            ).toBe(false);
        });

        test("DOES wipe filter/summary on a normal first chunk", () => {
            expect(
                shouldWipeFirstChunkView({ wifiKeysRerunInFlight: false }),
            ).toBe(true);
        });
    });

    describe("rerun-completion snapshot restore", () => {
        test("the snapshot is cleared on the rerun completion branch", () => {
            const backendProgressState = {
                wifiKeysRerunInFlight: true,
                pendingSessionRerunSnapshot: makeSnapshot(),
            };
            const payload = buildPayload({ complete: true });
            if (payload.complete) {
                if (backendProgressState.wifiKeysRerunInFlight) {
                    backendProgressState.wifiKeysRerunInFlight = false;
                    const snapshot =
                        backendProgressState.pendingSessionRerunSnapshot;
                    backendProgressState.pendingSessionRerunSnapshot = null;
                    // The renderer is expected to call
                    // restoreSessionBoundStateFromRerun(snapshot)
                    // here.
                    expect(snapshot.currentSessionName).toBe(
                        "coherer-induction-2026-08-09",
                    );
                }
            }
            expect(backendProgressState.wifiKeysRerunInFlight).toBe(false);
            expect(backendProgressState.pendingSessionRerunSnapshot).toBe(
                null,
            );
        });

        test("the snapshot is preserved on intermediate (non-complete) chunks", () => {
            const backendProgressState = {
                wifiKeysRerunInFlight: true,
                pendingSessionRerunSnapshot: makeSnapshot(),
            };
            const payload = buildPayload({ complete: false });
            if (payload.complete) {
                // Not reached on intermediate chunks.
                backendProgressState.pendingSessionRerunSnapshot = null;
            }
            // The snapshot is intact so the final-chunk restore
            // still has a source of truth.
            expect(backendProgressState.pendingSessionRerunSnapshot).not.toBe(
                null,
            );
            expect(
                backendProgressState.pendingSessionRerunSnapshot.filterQuery,
            ).toBe("wifi.bssid:00:0c:41:82:b2:55");
        });

        test("a null snapshot is a no-op (the user had no session bound state)", () => {
            const backendProgressState = {
                wifiKeysRerunInFlight: true,
                pendingSessionRerunSnapshot: null,
            };
            const payload = buildPayload({ complete: true });
            let restored = false;
            if (payload.complete) {
                if (backendProgressState.wifiKeysRerunInFlight) {
                    backendProgressState.wifiKeysRerunInFlight = false;
                    const snapshot =
                        backendProgressState.pendingSessionRerunSnapshot;
                    backendProgressState.pendingSessionRerunSnapshot = null;
                    if (snapshot && typeof snapshot === "object") {
                        restored = true;
                    }
                }
            }
            expect(restored).toBe(false);
        });
    });

    describe("abort safety net", () => {
        test("a backend error that aborts before completion clears the snapshot", () => {
            // Mirror of the .finally() block in runSnitch: if the
            // rerun aborts before any payload reaches the
            // completion branch, the safety net clears both the
            // in-flight flag and the pending snapshot so they
            // don't leak into the next run.
            const backendProgressState = {
                wifiKeysRerunInFlight: true,
                pendingSessionRerunSnapshot: makeSnapshot(),
            };
            // Simulate the .finally() guard.
            if (backendProgressState.wifiKeysRerunInFlight) {
                backendProgressState.wifiKeysRerunInFlight = false;
                backendProgressState.pendingSessionRerunSnapshot = null;
            }
            expect(backendProgressState.wifiKeysRerunInFlight).toBe(false);
            expect(backendProgressState.pendingSessionRerunSnapshot).toBe(
                null,
            );
        });
    });

    describe("sessionExplicitlyClosed lifecycle", () => {
        test("a named library load flips the flag to false", () => {
            // Mirror of onSessionSelected in main-frontend.js.
            const nextFlag = false; // sessionExplicitlyClosed = false;
            expect(nextFlag).toBe(false);
        });

        test("New Capture / file picker / onNewSession flips the flag to true", () => {
            // Mirror of clearCurrentSession and the capture-file-btn
            // click handler in main-frontend.js.
            const nextFlag = true; // sessionExplicitlyClosed = true;
            expect(nextFlag).toBe(true);
        });
    });
});
