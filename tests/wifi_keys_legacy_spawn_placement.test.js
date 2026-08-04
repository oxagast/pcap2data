// Regression test for the wifi-keys file placement in the legacy spawn
// path.  When the bridge spawns a backend for a wifi rerun, it must
// stage the wifi-keys JSON file at a path that survives the
// `rmSync(jobOutputDir)` wipe that happens immediately before the
// backend process is launched.
//
// Earlier the file was written inside jobOutputDir, so the wipe
// deleted it before the backend could read it and the legacy spawn
// silently skipped 802.11 decryption on the second run.
//
// This is a structural test that reads the bridge source and asserts
// the wifi-keys file is staged in testcaseOutputDir (a sibling of
// jobOutputDir), not inside jobOutputDir itself.

const fs = require("fs");
const path = require("path");

describe("wifi-keys legacy spawn placement", () => {
    const bridgePath = path.resolve(
        __dirname,
        "..",
        "src",
        "back-comm.js",
    );
    const source = fs.readFileSync(bridgePath, "utf8");

    test("wifi-keys file is staged outside jobOutputDir", () => {
        // The legacy spawn path wipes jobOutputDir just before
        // launching the backend.  If the wifi-keys file were inside
        // jobOutputDir, the wipe would delete it and the backend
        // would silently skip decryption.
        //
        // The fix is to stage the file in testcaseOutputDir (a
        // sibling of jobOutputDir) so the wipe doesn't touch it.
        const wifiKeysFileMatch = source.match(
            /wifiKeysFilePath\s*=\s*path\.join\(\s*testcaseOutputDir\s*,\s*[`'"]wifi-keys-[^`'"]+[`'"]/,
        );
        expect(wifiKeysFileMatch).not.toBeNull();
    });

    test("wifi-keys file is not staged inside jobOutputDir", () => {
        // Sanity check: the older (buggy) location was inside
        // jobOutputDir.  Make sure no code path writes it there.
        const buggyMatch = source.match(
            /wifiKeysFilePath\s*=\s*path\.join\(\s*jobOutputDir\s*,\s*["']wifi-keys\.json["']/,
        );
        expect(buggyMatch).toBeNull();
    });

    test("bridge cleans up the wifi-keys file after the backend closes", () => {
        // The wifi-keys file is a per-job artifact; lingering files
        // would accumulate in testcaseOutputDir.  The bridge should
        // unlink it when the backend process closes.
        const cleanupMatch = source.match(
            /fs\.unlinkSync\(\s*wifiKeysFilePath\s*\)/,
        );
        expect(cleanupMatch).not.toBeNull();
    });

    test("bridge passes the staged path to the backend via --wifi-keys-file", () => {
        // The bridge must pass the file path on the command line so
        // the backend can read it before processing packets.
        const argMatch = source.match(
            /legacyExtraArgs\s*=\s*wifiKeysFilePath\s*\?\s*\[\s*["']--wifi-keys-file["']\s*,\s*wifiKeysFilePath\s*\]\s*:\s*\[\s*\]/,
        );
        expect(argMatch).not.toBeNull();
    });
});
