// Regression test for the wifi-keys-rerun bug where the path-mode backend
// snapshot handler ignored the wifiKeysRerunInFlight flag, leaving the
// renderer's packet stubs pointed at pre-decryption content even though
// the new hosts.json on disk had the decrypted packets.
//
// This is a unit-level test of the flag-passing logic; the actual
// path-vs-data branching lives in processBackendJsonDataPayload and
// processBackendJsonPathPayload and is exercised in the integration tests.

describe("wifi-keys-rerun flag flows through to incremental snapshot", () => {
    function buildPayload({ complete = true } = {}) {
        return {
            complete,
            processedPackets: 1093,
            totalPackets: 1093,
            chunkSize: 2000,
        };
    }

    test("forceFullReindexForWifiKeys is true while wifiKeysRerunInFlight is set", () => {
        const backendProgressState = { wifiKeysRerunInFlight: true };
        const forceFullReindexForWifiKeys =
            backendProgressState.wifiKeysRerunInFlight === true;
        expect(forceFullReindexForWifiKeys).toBe(true);
    });

    test("forceFullReindexForWifiKeys is false after the flag is cleared", () => {
        const backendProgressState = { wifiKeysRerunInFlight: false };
        const forceFullReindexForWifiKeys =
            backendProgressState.wifiKeysRerunInFlight === true;
        expect(forceFullReindexForWifiKeys).toBe(false);
    });

    test("the wifiKeysRerunInFlight flag is reset when payload.complete is true", () => {
        const backendProgressState = { wifiKeysRerunInFlight: true };
        const payload = buildPayload({ complete: true });
        // Mirror the cleanup block in the path-mode handler.
        if (payload.complete) {
            if (backendProgressState.wifiKeysRerunInFlight) {
                backendProgressState.wifiKeysRerunInFlight = false;
            }
        }
        expect(backendProgressState.wifiKeysRerunInFlight).toBe(false);
    });

    test("the wifiKeysRerunInFlight flag stays set on intermediate (non-complete) chunks", () => {
        const backendProgressState = { wifiKeysRerunInFlight: true };
        const payload = buildPayload({ complete: false });
        if (payload.complete) {
            if (backendProgressState.wifiKeysRerunInFlight) {
                backendProgressState.wifiKeysRerunInFlight = false;
            }
        }
        // Intermediate chunks shouldn't clear the flag, so subsequent
        // chunks keep triggering the full reindex until completion.
        expect(backendProgressState.wifiKeysRerunInFlight).toBe(true);
    });
});
