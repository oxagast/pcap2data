// Regression tests for the Windows installer elevation guard.
//
// Squirrel.Windows installs/updates the PacketSnitch app by spawning
// ``Update.exe --createShortcut=...``, which writes Start Menu
// shortcuts, Program Files binaries, and HKLM registry entries — all
// of which require Administrator elevation. When the user runs the
// installer without "Run as Administrator" the writes silently fail
// and the user is dropped at the application as if install succeeded.
//
// ``src/main.js`` now wraps ``require("electron-squirrel-startup")``
// with a gate that:
//   * On non-Windows: delegates straight to squirrel-startup.
//   * On Windows for any squirrel event (install / update / uninstall
//     / obsolete): runs ``Update.exe`` itself so we can capture the
//     exit code and surface shortcut-creation failures to the user.
//   * On Windows for ``--squirrel-install`` / ``--squirrel-updated``:
//     probes elevation via ``net session``. If not elevated, shows
//     a native message box, attempts a UAC relaunch of the
//     installer, and exits. If elevated, skips the warning and the
//     UAC relaunch — the install just continues.
//
// After the install steps, a post-install summary dialog shows the
// user the on-disk locations of the application, the backend
// binaries, and the support databases (GeoLite2, IEEE OUI MAC
// vendors, IANA service-names-port-numbers).
//
// The tests below extract the gate's helpers with ``vm.runInContext``,
// the same pattern as ``tests/metrics_insecure_tls.test.js``, so we
// can run them on any host without pulling the real ``electron`` or
// ``electron-squirrel-startup`` modules into plain Node.

const fs = require('fs');
const os = require('os');
const path = require('path');
const vm = require('vm');

const PROJECT_ROOT = path.join(__dirname, '..');
const MAIN_PATH = path.join(PROJECT_ROOT, 'src', 'main.js');

function extractFunctionDeclaration(sourceText, functionName) {
    const startToken = `function ${functionName}`;
    const startIndex = sourceText.indexOf(startToken);
    if (startIndex === -1) {
        throw new Error(`Could not find function ${functionName}`);
    }
    // If the declaration is ``async function <name>`` (used by
    // ``runSquirrelShortcutOperation`` and
    // ``runSquirrelStartupGateAsync``), rewind the start index so
    // the extracted snippet preserves the ``async`` keyword; the
    // ``vm`` sandbox otherwise evaluates the body as a plain
    // function and rejects the top-level ``await`` it contains.
    let snippetStart = startIndex;
    if (snippetStart >= 6 && sourceText.slice(snippetStart - 6, snippetStart) === "async ") {
        snippetStart -= 6;
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
                return sourceText.slice(snippetStart, cursor + 1);
            }
        }
    }
    throw new Error(`Could not parse function ${functionName}`);
}

function makeGateVm() {
    const sourceText = fs.readFileSync(MAIN_PATH, "utf8");
    const fnSources = [
        "isWindowsProcessElevated",
        "showWindowsElevationMessageBox",
        "relaunchInstallerElevatedViaUac",
        "resolveSquirrelUpdateExe",
        "resolveSquirrelInstalledFiles",
        "resolveSquirrelStartMenuBaseDir",
        "runSquirrelUpdateStep",
        "runSquirrelShortcutOperation",
        "buildSquirrelSummaryText",
        "showWindowsSquirrelSummaryDialog",
        "openActivityLogFileInDefaultApp",
        "runSquirrelStartupGate",
        "runSquirrelStartupGateAsync",
    ]
        .map((name) => extractFunctionDeclaration(sourceText, name))
        .join("\n\n");

    const sandbox = {
        console,
        process: { platform: "linux", exit: (code) => { sandbox.__processExitCalls.push(code); } },
        require: (id) => {
            // The gate reaches for ``require("child_process").execSync``
            // and ``require("child_process").spawnSync`` when no
            // dependency is injected. Hand back a tiny stub that
            // records calls so tests can assert on them.
            if (id === "child_process") {
                return {
                    execSync: () => {
                        throw new Error("execSync should be stubbed in tests");
                    },
                    execFile: () => {
                        throw new Error("execFile should be stubbed in tests");
                    },
                    spawn: () => {
                        throw new Error("spawn should be stubbed in tests");
                    },
                    spawnSync: () => {
                        throw new Error("spawnSync should be stubbed in tests");
                    },
                };
            }
            if (id === "electron-squirrel-startup") {
                throw new Error("electron-squirrel-startup should be stubbed in tests");
            }
            throw new Error(`Unexpected require: ${id}`);
        },
        String,
        Number,
        Math,
        Boolean,
        Array,
        Object,
        JSON,
        Error,
        // ``Buffer`` is used by the PowerShell dialog helpers to
        // build the ``-EncodedCommand`` base64 payload. The vm
        // sandbox otherwise doesn't expose the global ``Buffer``
        // that Node injects.
        Buffer,
        // ``app`` is referenced in the gate's exit branch. Stub it so
        // a path that calls ``app.quit()`` doesn't blow up; the stub
        // records calls instead.
        app: {
            quit: () => {
                sandbox.__appQuitCalls += 1;
            },
        },
        fs,
        path,
        os,
    };
    sandbox.__appQuitCalls = 0;
    sandbox.__processExitCalls = [];
    vm.createContext(sandbox);
    vm.runInContext(fnSources, sandbox);
    return sandbox;
}

describe("isWindowsProcessElevated", () => {
    test("returns true on non-Windows platforms without spawning net", () => {
        const harness = makeGateVm();
        const calls = [];
        // On non-Windows we shouldn't even hit execSync; provide one
        // that throws so we'd notice if we did.
        const elevated = harness.isWindowsProcessElevated({
            platformName: "linux",
            execSyncFn: () => {
                calls.push("called");
                throw new Error("should not be called on linux");
            },
        });
        expect(elevated).toBe(true);
        expect(calls).toEqual([]);
    });

    test("returns true on Windows when `net session` exits 0", () => {
        const harness = makeGateVm();
        let captured = null;
        const elevated = harness.isWindowsProcessElevated({
            platformName: "win32",
            execSyncFn: (cmd, options) => {
                captured = { cmd, options };
                // Returning without throwing mimics a 0 exit code.
            },
        });
        expect(elevated).toBe(true);
        expect(captured.cmd).toBe("net session");
        // The options we pass must include a timeout so a hung
        // net.exe can't stall the install.
        expect(captured.options.timeout).toBeGreaterThan(0);
        expect(captured.options.windowsHide).toBe(true);
        // We discard stderr so the installer console isn't spammed
        // with the "Access is denied" message on a non-elevated run.
        expect(captured.options.stdio).toEqual(["ignore", "ignore", "ignore"]);
    });

    test("returns false on Windows when `net session` throws (non-zero exit)", () => {
        const harness = makeGateVm();
        const elevated = harness.isWindowsProcessElevated({
            platformName: "win32",
            execSyncFn: () => {
                const error = new Error("Command failed: net session");
                error.status = 5;
                throw error;
            },
        });
        expect(elevated).toBe(false);
    });

    test("returns false on Windows when `net session` times out", () => {
        const harness = makeGateVm();
        const elevated = harness.isWindowsProcessElevated({
            platformName: "win32",
            execSyncFn: () => {
                const error = new Error("Command timed out");
                error.signal = "SIGTERM";
                throw error;
            },
        });
        expect(elevated).toBe(false);
    });
});

describe("showWindowsElevationMessageBox", () => {
    test("no-ops on non-Windows without spawning PowerShell", () => {
        const harness = makeGateVm();
        let spawned = false;
        harness.showWindowsElevationMessageBox({
            platformName: "linux",
            spawnFn: () => {
                spawned = true;
                return { status: 0 };
            },
        });
        expect(spawned).toBe(false);
    });

    test("spawns powershell.exe with WinForms MessageBox on Windows", () => {
        const harness = makeGateVm();
        let captured = null;
        harness.showWindowsElevationMessageBox({
            platformName: "win32",
            spawnFn: (cmd, args, options) => {
                captured = { cmd, args, options };
                return { status: 0 };
            },
        });
        expect(captured).not.toBeNull();
        expect(captured.cmd).toBe("powershell.exe");
        expect(Array.isArray(captured.args)).toBe(true);
        // The PowerShell script is passed via ``-EncodedCommand`` as
        // a base64-encoded UTF-16LE payload. Decode it before
        // asserting so the test stays readable and the schema
        // matches what the runtime PowerShell host actually sees.
        const encodedIndex = captured.args.indexOf("-EncodedCommand");
        expect(encodedIndex).toBeGreaterThanOrEqual(0);
        const encodedPayload = captured.args[encodedIndex + 1];
        const decodedScript = Buffer.from(encodedPayload, "base64").toString("utf16le");
        expect(decodedScript).toContain("System.Windows.Forms.MessageBox");
        expect(decodedScript).toContain("PacketSnitch installer");
    });

    test("swallows spawn failures so the gate never throws", () => {
        const harness = makeGateVm();
        expect(() => {
            harness.showWindowsElevationMessageBox({
                platformName: "win32",
                spawnFn: () => {
                    throw new Error("PowerShell not found");
                },
            });
        }).not.toThrow();
    });

    test("default message tells the user about the UAC prompt instead of asking them to relaunch manually", () => {
        // The gate auto-relaunches the installer via UAC when the
        // user clicks Yes on the consent prompt. Asking them to
        // right-click and "Run as administrator" themselves would
        // mean two installers running concurrently — which races on
        // the per-version install folder and the per-user HKCU
        // registry entries. The default message must NOT contain
        // that instruction.
        const harness = makeGateVm();
        let captured = null;
        harness.showWindowsElevationMessageBox({
            platformName: "win32",
            spawnFn: (cmd, args) => {
                captured = { args };
                return { status: 0 };
            },
        });
        const encodedIndex = captured.args.indexOf("-EncodedCommand");
        const decodedScript = Buffer.from(captured.args[encodedIndex + 1], "base64").toString("utf16le");
        expect(decodedScript).not.toMatch(/right-click/i);
        expect(decodedScript).not.toMatch(/Run as administrator/i);
        // The message should at least mention the UAC consent
        // prompt so the user knows what to expect next.
        expect(decodedScript).toMatch(/Administrator permission/i);
    });
});

describe("relaunchInstallerElevatedViaUac", () => {
    test("no-ops on non-Windows without spawning PowerShell", () => {
        const harness = makeGateVm();
        let spawned = false;
        const ok = harness.relaunchInstallerElevatedViaUac({
            platformName: "linux",
            exePath: "C:\\path\\PacketSnitch.exe",
            argv: ["C:\\path\\PacketSnitch.exe", "--squirrel-install"],
            spawnFn: () => {
                spawned = true;
                return { status: 0 };
            },
        });
        expect(ok).toBe(false);
        expect(spawned).toBe(false);
    });

    test("spawns powershell.exe with Start-Process -Verb RunAs on Windows", () => {
        const harness = makeGateVm();
        let captured = null;
        const ok = harness.relaunchInstallerElevatedViaUac({
            platformName: "win32",
            exePath: "C:\\Program Files\\PacketSnitch\\PacketSnitch.exe",
            argv: [
                "C:\\Program Files\\PacketSnitch\\PacketSnitch.exe",
                "--squirrel-install",
            ],
            spawnFn: (cmd, args, options) => {
                captured = { cmd, args, options };
                return { status: 0 };
            },
        });
        expect(ok).toBe(true);
        expect(captured.cmd).toBe("powershell.exe");
        const commandArg = captured.args[captured.args.length - 1];
        expect(commandArg).toContain("Start-Process");
        // The PowerShell verb must be RunAs to trigger UAC.
        expect(commandArg).toContain("-Verb RunAs");
        // Both the executable path and the squirrel flag must be
        // passed through to PowerShell so the elevated relaunch
        // re-issues the same Squirrel command.
        expect(commandArg).toContain("PacketSnitch.exe");
        expect(commandArg).toContain("--squirrel-install");
    });

    test("returns false when powershell.exe exits non-zero (user cancelled UAC)", () => {
        const harness = makeGateVm();
        const ok = harness.relaunchInstallerElevatedViaUac({
            platformName: "win32",
            exePath: "C:\\path\\PacketSnitch.exe",
            argv: ["C:\\path\\PacketSnitch.exe", "--squirrel-install"],
            spawnFn: () => ({ status: 1 }),
        });
        expect(ok).toBe(false);
    });

    test("escapes embedded double quotes in argv so paths with quotes survive", () => {
        const harness = makeGateVm();
        let captured = null;
        harness.relaunchInstallerElevatedViaUac({
            platformName: "win32",
            exePath: "C:\\path with \"quotes\"\\PacketSnitch.exe",
            argv: [
                "C:\\path with \"quotes\"\\PacketSnitch.exe",
                "--squirrel-install",
            ],
            spawnFn: (cmd, args) => {
                captured = { args };
                return { status: 0 };
            },
        });
        const commandArg = captured.args[captured.args.length - 1];
        // PowerShell v5+ escapes embedded double quotes by doubling
        // them. ``JSON.stringify`` produces an escaped backslash for
        // every literal backslash and an escaped quote for every
        // literal quote, so the path round-trips through PowerShell
        // intact: ``C:\path with "quotes"\PacketSnitch.exe``. We
        // assert on a stable substring that survives both escapes.
        expect(commandArg).toContain('with \\\"quotes\\\"');
    });
});

describe("runSquirrelShortcutOperation", () => {
    // The new helper delegates to PowerShell via
    // ``spawnSync(powershell.exe, [...])``: ``spawnFn`` records
    // the argv and returns a ``{ status, stderr }`` result.
    // ``Buffer.from(...)`` is used inside the helper to decode the
    // stderr bytes; providing a string is fine here because the
    // helper passes it through unchanged.
    const makeSpawnStub = (capture) => (cmd, args, options) => {
        capture.cmd = cmd;
        capture.args = args;
        capture.options = options;
        return { status: 0, stderr: "" };
    };

    test("creates the Desktop shortcut and Start Menu folder on install", async () => {
        // The user wants a folder in the Start Menu called
        // ``PacketSnitch`` containing both the app link and a link
        // to the documentation site. The new helper owns the
        // Desktop shortcut as well so all shortcut metadata lives
        // in one PowerShell script.
        const harness = makeGateVm();
        const captured = {};
        const operationLog = [];
        const result = await harness.runSquirrelShortcutOperation({
            platformName: "win32",
            squirrelCommand: "--squirrel-install",
            execPath: "C:\\Program Files\\PacketSnitch\\app-1.2.3\\PacketSnitch.exe",
            spawnFn: makeSpawnStub(captured),
            operationLog,
            folderName: "PacketSnitch",
            folderIconPath: "C:\\Program Files\\PacketSnitch\\app-1.2.3\\resources\\ps-icon.ico",
            docsUrl: "https://packetsnitch.com/docu/",
            startMenuBaseDir: "C:\\Users\\me\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs",
            desktopDir: "C:\\Users\\me\\Desktop",
        });
        expect(captured.cmd).toBe("powershell.exe");
        const encodedIndex = captured.args.indexOf("-EncodedCommand");
        expect(encodedIndex).toBeGreaterThanOrEqual(0);
        const decodedScript = Buffer.from(captured.args[encodedIndex + 1], "base64").toString("utf16le");
        // The PowerShell script must create the WScript.Shell COM
        // object, emit two .lnk files, and target the URL as the
        // docs link.
        expect(decodedScript).toContain("WScript.Shell");
        expect(decodedScript).toContain("CreateShortcut");
        expect(decodedScript).toContain("https://packetsnitch.com/docu/");
        expect(decodedScript).toContain("PacketSnitch.lnk");
        expect(decodedScript).toContain("Documentation.lnk");
        expect(decodedScript).toContain("ps-icon.ico");
        expect(result.ok).toBe(true);
        // The operation log should surface BOTH actions so the
        // summary dialog can list them by step.
        expect(operationLog.length).toBe(2);
        expect(operationLog[0].label).toContain("Desktop shortcut");
        expect(operationLog[1].label).toContain("Start Menu folder");
    });

    test("creates the same Desktop shortcut and Start Menu folder on update", async () => {
        const harness = makeGateVm();
        const captured = {};
        const operationLog = [];
        await harness.runSquirrelShortcutOperation({
            platformName: "win32",
            squirrelCommand: "--squirrel-updated",
            execPath: "C:\\Program Files\\PacketSnitch\\app-1.2.3\\PacketSnitch.exe",
            spawnFn: makeSpawnStub(captured),
            operationLog,
            folderName: "PacketSnitch",
            folderIconPath: "C:\\path\\ps-icon.ico",
            startMenuBaseDir: "C:\\Users\\me\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs",
            desktopDir: "C:\\Users\\me\\Desktop",
        });
        // The PowerShell script should be the same shape as
        // install: ``CreateShortcut`` is invoked twice, once for
        // the Desktop ``.lnk`` and once for the Start Menu
        // ``.lnk`` (and a third time for the docs URL).
        const encodedIndex = captured.args.indexOf("-EncodedCommand");
        const decodedScript = Buffer.from(captured.args[encodedIndex + 1], "base64").toString("utf16le");
        const createShortcutCalls = (decodedScript.match(/CreateShortcut/g) || []).length;
        expect(createShortcutCalls).toBeGreaterThanOrEqual(3);
    });

    test("removes the Desktop shortcut and Start Menu folder on uninstall", async () => {
        const harness = makeGateVm();
        const captured = {};
        const operationLog = [];
        const result = await harness.runSquirrelShortcutOperation({
            platformName: "win32",
            squirrelCommand: "--squirrel-uninstall",
            execPath: "C:\\Program Files\\PacketSnitch\\app-1.2.3\\PacketSnitch.exe",
            spawnFn: makeSpawnStub(captured),
            operationLog,
            folderName: "PacketSnitch",
            folderIconPath: "C:\\path\\ps-icon.ico",
            startMenuBaseDir: "C:\\Users\\me\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs",
            desktopDir: "C:\\Users\\me\\Desktop",
        });
        const encodedIndex = captured.args.indexOf("-EncodedCommand");
        const decodedScript = Buffer.from(captured.args[encodedIndex + 1], "base64").toString("utf16le");
        expect(decodedScript).toContain("Remove-Item");
        expect(decodedScript).toContain("PacketSnitch.lnk");
        // The folder path uses the same name as the
        // ``startMenuBaseDir`` + ``folderName`` join.
        expect(decodedScript).toContain("Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\PacketSnitch");
        expect(result.ok).toBe(true);
        expect(operationLog.length).toBe(2);
        expect(operationLog[0].label).toContain("Remove Desktop shortcut");
        expect(operationLog[1].label).toContain("Remove Start Menu folder");
    });

    test("returns a successful no-op for --squirrel-obsolete", async () => {
        const harness = makeGateVm();
        let spawned = false;
        const operationLog = [];
        const result = await harness.runSquirrelShortcutOperation({
            platformName: "win32",
            squirrelCommand: "--squirrel-obsolete",
            execPath: "C:\\Program Files\\PacketSnitch\\app-1.2.3\\PacketSnitch.exe",
            spawnFn: (cmd, args, options) => {
                spawned = true;
                return { status: 0, stderr: "" };
            },
            operationLog,
            folderName: "PacketSnitch",
            folderIconPath: "C:\\path\\ps-icon.ico",
            startMenuBaseDir: "C:\\Users\\me\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs",
            desktopDir: "C:\\Users\\me\\Desktop",
        });
        // ``--squirrel-obsolete`` fires when a previous version is
        // being replaced; we must not spawn PowerShell again. The
        // new install creates the shortcuts for the new version.
        expect(spawned).toBe(false);
        expect(result.ok).toBe(true);
        expect(result.skipped).toBe(false);
        // The no-op entry is still emitted so the summary dialog
        // can show the user what step ran.
        expect(operationLog.length).toBe(1);
        expect(operationLog[0].label).toContain("Obsolete");
    });

    test("captures PowerShell failures so the summary dialog can show them", async () => {
        const harness = makeGateVm();
        const operationLog = [];
        const result = await harness.runSquirrelShortcutOperation({
            platformName: "win32",
            squirrelCommand: "--squirrel-install",
            execPath: "C:\\Program Files\\PacketSnitch\\app-1.2.3\\PacketSnitch.exe",
            spawnFn: () => ({ status: 2, stderr: "icon write failed" }),
            operationLog,
            folderName: "PacketSnitch",
            folderIconPath: "C:\\path\\ps-icon.ico",
            startMenuBaseDir: "C:\\Users\\me\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs",
            desktopDir: "C:\\Users\\me\\Desktop",
        });
        expect(result.ok).toBe(false);
        expect(result.exitCode).toBe(2);
        expect(result.stderr).toContain("icon write failed");
        // Both steps should be marked as failed so neither claims
        // success in the summary dialog.
        expect(operationLog.length).toBe(2);
        operationLog.forEach((entry) => {
            expect(entry.ok).toBe(false);
        });
    });

    test("non-Windows hosts are skipped without spawning PowerShell", async () => {
        const harness = makeGateVm();
        let spawned = false;
        const operationLog = [];
        const result = await harness.runSquirrelShortcutOperation({
            platformName: "linux",
            squirrelCommand: "--squirrel-install",
            execPath: "/usr/local/bin/packetsnitch",
            spawnFn: () => {
                spawned = true;
                return { status: 0, stderr: "" };
            },
            operationLog,
        });
        expect(spawned).toBe(false);
        expect(result.skipped).toBe(true);
        // The skip itself is logged so the summary dialog can tell
        // the user the install path applies to Windows only.
        expect(operationLog.length).toBe(1);
        expect(operationLog[0].skipped).toBe(true);
    });
});

describe("resolveSquirrelInstalledFiles", () => {
    test("returns null on non-Windows so the caller can omit the section", () => {
        const harness = makeGateVm();
        const installed = harness.resolveSquirrelInstalledFiles({
            platformName: "linux",
            execPath: "/usr/local/bin/packetsnitch",
            resourcesPath: "/usr/local/share/packetsnitch/resources",
        });
        expect(installed).toBeNull();
    });

    test("returns the Squirrel install layout for a Windows exe", () => {
        const harness = makeGateVm();
        const installed = harness.resolveSquirrelInstalledFiles({
            platformName: "win32",
            execPath: "C:\\Users\\me\\AppData\\Local\\packetsnitch\\app-1.2.3\\PacketSnitch.exe",
            resourcesPath: "C:\\Users\\me\\AppData\\Local\\packetsnitch\\app-1.2.3\\resources",
            existsSyncFn: () => false,
        });
        expect(installed).not.toBeNull();
        // The helper uses ``path.resolve`` to normalize the result;
        // on Linux that treats Windows-style paths as relative and
        // prefixes the cwd, so we compute the expected value with
        // ``path.win32`` directly to match the on-Windows semantics.
        const win32 = path.win32;
        expect(installed.executable).toBe(
            win32.resolve("C:\\Users\\me\\AppData\\Local\\packetsnitch\\app-1.2.3\\PacketSnitch.exe"),
        );
        // ``Update.exe`` sits one level up from the per-version
        // ``app-<version>`` directory, in the Squirrel install root.
        expect(installed.updateExe).toBe(
            win32.resolve("C:\\Users\\me\\AppData\\Local\\packetsnitch\\Update.exe"),
        );
        expect(installed.backend).toBe(
            win32.resolve("C:\\Users\\me\\AppData\\Local\\packetsnitch\\app-1.2.3\\resources\\snitch.exe"),
        );
        expect(installed.extractor).toBe(
            win32.resolve("C:\\Users\\me\\AppData\\Local\\packetsnitch\\app-1.2.3\\resources\\snitch-extract.exe"),
        );
        expect(installed.commonDir).toBe(
            win32.resolve("C:\\Users\\me\\AppData\\Local\\packetsnitch\\app-1.2.3\\resources\\common"),
        );
    });

    test("lists the GeoIP, MAC vendor, and IANA databases under common/", () => {
        const harness = makeGateVm();
        const installed = harness.resolveSquirrelInstalledFiles({
            platformName: "win32",
            execPath: "C:\\Program Files\\PacketSnitch\\app-1.0.0\\PacketSnitch.exe",
            resourcesPath: "C:\\Program Files\\PacketSnitch\\app-1.0.0\\resources",
            existsSyncFn: () => false,
        });
        const databaseLabels = installed.databases.map((entry) => entry.label);
        // ``labels`` are the user-facing strings shown in the
        // summary dialog; keeping them stable avoids "why is the
        // install message different?" surprises when the database
        // filenames change.
        expect(databaseLabels).toEqual([
            "GeoLite2 City",
            "MAC vendors",
            "Service names",
        ]);
        const fileNames = installed.databases.map((entry) => path.win32.basename(entry.path));
        expect(fileNames).toEqual([
            "GeoLite2-City.mmdb",
            "mac-vendors-export.csv",
            "service-names-port-numbers.csv",
        ]);
        installed.databases.forEach((entry) => {
            // ``path.win32`` relative-prefix check works on any
            // platform because we compare the resolved absolute
            // win32-paths directly.
            expect(entry.path.startsWith(installed.commonDir)).toBe(true);
        });
    });

    test("marks each database as missing when existsSync returns false", () => {
        const harness = makeGateVm();
        const installed = harness.resolveSquirrelInstalledFiles({
            platformName: "win32",
            execPath: "C:\\Program Files\\PacketSnitch\\app-1.0.0\\PacketSnitch.exe",
            resourcesPath: "C:\\Program Files\\PacketSnitch\\app-1.0.0\\resources",
            existsSyncFn: () => false,
        });
        installed.databases.forEach((entry) => {
            expect(entry.exists).toBe(false);
        });
    });
});

describe("buildSquirrelSummaryText", () => {
    test("renders an Installed files section listing binary paths", () => {
        const harness = makeGateVm();
        const text = harness.buildSquirrelSummaryText({
            operationKind: "install",
            version: "1.2.3",
            binaryPaths: {
                executable: "C:\\Program Files\\PacketSnitch\\app-1.2.3\\PacketSnitch.exe",
                updateExe: "C:\\Program Files\\PacketSnitch\\Update.exe",
                backend: "C:\\Program Files\\PacketSnitch\\app-1.2.3\\resources\\snitch.exe",
                extractor: "C:\\Program Files\\PacketSnitch\\app-1.2.3\\resources\\snitch-extract.exe",
                commonDir: "C:\\Program Files\\PacketSnitch\\app-1.2.3\\resources\\common",
                databases: [
                    { label: "GeoLite2 City", path: "C:\\Program Files\\PacketSnitch\\app-1.2.3\\resources\\common\\GeoLite2-City.mmdb" },
                    { label: "MAC vendors", path: "C:\\Program Files\\PacketSnitch\\app-1.2.3\\resources\\common\\mac-vendors-export.csv" },
                ],
            },
        });
        // The user requested that the install message list
        // "where the binaries are located" — every binary path
        // the helper returned should appear in the rendered text.
        expect(text).toContain("PacketSnitch 1.2.3");
        expect(text).toContain("The application was installed successfully.");
        expect(text).toContain("Installed files:");
        expect(text).toContain("Application : C:\\Program Files\\PacketSnitch\\app-1.2.3\\PacketSnitch.exe");
        expect(text).toContain("Squirrel    : C:\\Program Files\\PacketSnitch\\Update.exe");
        expect(text).toContain("Backend     : C:\\Program Files\\PacketSnitch\\app-1.2.3\\resources\\snitch.exe");
        expect(text).toContain("Extractor   : C:\\Program Files\\PacketSnitch\\app-1.2.3\\resources\\snitch-extract.exe");
        expect(text).toContain("Data folder : C:\\Program Files\\PacketSnitch\\app-1.2.3\\resources\\common");
        expect(text).toContain("Databases   :");
        expect(text).toContain("GeoLite2 City: C:\\Program Files\\PacketSnitch\\app-1.2.3\\resources\\common\\GeoLite2-City.mmdb");
        expect(text).toContain("MAC vendors: C:\\Program Files\\PacketSnitch\\app-1.2.3\\resources\\common\\mac-vendors-export.csv");
    });

    test("omits the Installed files section when binaryPaths is not provided", () => {
        const harness = makeGateVm();
        const text = harness.buildSquirrelSummaryText({
            operationKind: "install",
            version: "1.2.3",
        });
        expect(text).toContain("PacketSnitch 1.2.3");
        expect(text).toContain("The application was installed successfully.");
        expect(text).not.toContain("Installed files:");
    });

    test("renders an Installed files section when binaryPaths is an empty object", () => {
        // ``binaryPaths: {}`` means the helper found no install
        // location (e.g. resourcesPath was empty). We still
        // emit the section header so the dialog layout is stable,
        // and the section body is empty because every accessor
        // returned ``undefined``.
        const harness = makeGateVm();
        const text = harness.buildSquirrelSummaryText({
            operationKind: "install",
            version: "1.2.3",
            binaryPaths: {},
        });
        expect(text).toContain("Installed files:");
    });

    test("accepts plain string entries in the databases array", () => {
        const harness = makeGateVm();
        const text = harness.buildSquirrelSummaryText({
            operationKind: "install",
            version: "1.2.3",
            binaryPaths: {
                databases: ["C:\\path\\to\\database.mmdb"],
            },
        });
        expect(text).toContain("Databases   :");
        expect(text).toContain("C:\\path\\to\\database.mmdb");
    });

    test("still appends the error count footer when binaryPaths is provided", () => {
        const harness = makeGateVm();
        const text = harness.buildSquirrelSummaryText({
            operationKind: "install",
            version: "1.2.3",
            binaryPaths: {
                executable: "C:\\path\\PacketSnitch.exe",
            },
            operationLog: [
                { ok: true, label: "Create shortcut" },
                { ok: false, label: "Write registry", stderr: "boom", exitCode: 1 },
            ],
            errorCount: 1,
        });
        expect(text).toContain("Installed files:");
        expect(text).toContain("1 step(s) reported errors.");
    });

    test("renders the Start Menu folder layout with the app and docs links", () => {
        // The user wants a Start Menu folder containing both the
        // app link and the documentation link. The summary dialog
        // must surface the folder path and both individual .lnk
        // files so the user can find them by name.
        const harness = makeGateVm();
        const text = harness.buildSquirrelSummaryText({
            operationKind: "install",
            version: "1.2.3",
            binaryPaths: {
                startMenuFolder: "C:\\Users\\me\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\PacketSnitch",
                appShortcutPath: "C:\\Users\\me\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\PacketSnitch\\PacketSnitch.lnk",
                docsShortcutPath: "C:\\Users\\me\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\PacketSnitch\\Documentation.lnk",
                desktopShortcut: "C:\\Users\\me\\Desktop\\PacketSnitch.lnk",
            },
        });
        expect(text).toContain("Desktop     : C:\\Users\\me\\Desktop\\PacketSnitch.lnk");
        expect(text).toContain("Start menu  : C:\\Users\\me\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\PacketSnitch");
        expect(text).toContain("App link : C:\\Users\\me\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\PacketSnitch\\PacketSnitch.lnk");
        expect(text).toContain("Docs link: C:\\Users\\me\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\PacketSnitch\\Documentation.lnk");
    });
});

describe("resolveSquirrelStartMenuBaseDir", () => {
    test("returns the empty string on non-Windows so the caller can short-circuit", () => {
        const harness = makeGateVm();
        const result = harness.resolveSquirrelStartMenuBaseDir({
            platformName: "linux",
            appDataDir: "/home/user/.config",
        });
        expect(result).toBe("");
    });

    test("returns the empty string when APPDATA is missing", () => {
        const harness = makeGateVm();
        const result = harness.resolveSquirrelStartMenuBaseDir({
            platformName: "win32",
            appDataDir: "",
        });
        expect(result).toBe("");
    });

    test("joins APPDATA with the conventional Start Menu Programs path", () => {
        const harness = makeGateVm();
        const result = harness.resolveSquirrelStartMenuBaseDir({
            platformName: "win32",
            appDataDir: "C:\\Users\\me\\AppData\\Roaming",
        });
        expect(result).toBe(
            path.win32.join("C:\\Users\\me\\AppData\\Roaming", "Microsoft", "Windows", "Start Menu", "Programs"),
        );
    });
});

describe("runSquirrelStartupGate", () => {
    test("delegates to squirrel-startup on non-Windows (no elevation check)", () => {
        const harness = makeGateVm();
        let squirrelCalls = 0;
        let execCalls = 0;
        const result = harness.runSquirrelStartupGate({
            argv: [process.argv[0], "--squirrel-install"],
            platformName: "linux",
            deps: {
                execSyncFn: () => {
                    execCalls += 1;
                },
                squirrelStartupFn: () => {
                    squirrelCalls += 1;
                    return false;
                },
            },
        });
        // The gate must NOT probe elevation on linux, and must hand
        // off to the squirrel hook so the existing installer flow
        // is untouched on non-Windows.
        expect(execCalls).toBe(0);
        expect(squirrelCalls).toBe(1);
        expect(result).toBe(false);
    });

    test("runs Update.exe directly on Windows for non-install events", () => {
        // The current design runs ``Update.exe`` itself for every
        // Windows squirrel event so we can capture the exit code
        // and surface shortcut-creation failures to the user. The
        // legacy ``electron-squirrel-startup`` fallback is gone.
        const harness = makeGateVm();
        let squirrelCalls = 0;
        let execCalls = 0;
        const result = harness.runSquirrelStartupGate({
            argv: [process.argv[0], "--squirrel-uninstall"],
            platformName: "win32",
            deps: {
                execSyncFn: () => {
                    execCalls += 1;
                    throw new Error("should not probe elevation for uninstall");
                },
                squirrelStartupFn: () => {
                    squirrelCalls += 1;
                    return true;
                },
            },
        });
        expect(execCalls).toBe(0);
        // ``runSquirrelStartupGateAsync`` is invoked fire-and-forget
        // for Windows squirrel events, so the synchronous return
        // value is whatever the gate decided (``true``) and the
        // legacy squirrel-startup hook is no longer called.
        expect(squirrelCalls).toBe(0);
        expect(result).toBe(true);
    });

    test("runs Update.exe directly on Windows for --squirrel-obsolete", () => {
        const harness = makeGateVm();
        let squirrelCalls = 0;
        const result = harness.runSquirrelStartupGate({
            argv: [process.argv[0], "--squirrel-obsolete"],
            platformName: "win32",
            deps: {
                execSyncFn: () => {
                    throw new Error("should not probe elevation for obsolete");
                },
                squirrelStartupFn: () => {
                    squirrelCalls += 1;
                    return true;
                },
            },
        });
        expect(squirrelCalls).toBe(0);
        expect(result).toBe(true);
    });

    test("skips the elevation warning when the Windows process IS elevated", () => {
        // The user's request: when the installer is started as
        // administrator initially, it shouldn't ask to be restarted
        // as admin — it should just continue with the install.
        // ``runSquirrelStartupGateAsync`` probes elevation via
        // ``net session`` and, when elevated, skips the message
        // box and the UAC relaunch and runs ``Update.exe`` itself.
        const harness = makeGateVm();
        let execCalls = 0;
        let squirrelCalls = 0;
        const result = harness.runSquirrelStartupGate({
            argv: [process.argv[0], "--squirrel-install"],
            platformName: "win32",
            deps: {
                execSyncFn: () => {
                    execCalls += 1;
                    // 0 exit = elevated
                },
                squirrelStartupFn: () => {
                    squirrelCalls += 1;
                    return true;
                },
            },
        });
        // ``isWindowsProcessElevated`` ran once and returned true.
        expect(execCalls).toBe(1);
        // ``squirrelStartupFn`` is no longer invoked for the
        // elevated install path: ``runSquirrelStartupGateAsync``
        // calls ``Update.exe`` directly so we can capture errors.
        expect(squirrelCalls).toBe(0);
        // The synchronous gate returns ``true`` (matching the
        // outer ``if (runSquirrelStartupGate({}))`` site).
        expect(result).toBe(true);
    });

    test("blocks install and surfaces UI when Windows process is NOT elevated", () => {
        const harness = makeGateVm();
        let messageCalls = 0;
        let relaunchCalls = 0;
        let squirrelCalls = 0;
        let execCalls = 0;
        const result = harness.runSquirrelStartupGate({
            argv: [process.argv[0], "--squirrel-install"],
            platformName: "win32",
            deps: {
                execSyncFn: () => {
                    execCalls += 1;
                    // Mimic ``net session`` access-denied: non-zero exit.
                    const error = new Error("Access is denied");
                    error.status = 5;
                    throw error;
                },
                showMessageFn: () => {
                    messageCalls += 1;
                },
                relaunchFn: () => {
                    relaunchCalls += 1;
                    return true;
                },
                squirrelStartupFn: () => {
                    squirrelCalls += 1;
                    return true;
                },
            },
        });
        // The gate must have:
        //   1. Probed elevation exactly once.
        //   2. Shown the friendly error message.
        //   3. Attempted a UAC relaunch.
        //   4. NOT delegated to the squirrel hook (that would
        //      cause the silent half-install we are fixing).
        //   5. Triggered a clean process exit.
        expect(execCalls).toBe(1);
        expect(messageCalls).toBe(1);
        expect(relaunchCalls).toBe(1);
        expect(squirrelCalls).toBe(0);
        expect(harness.__appQuitCalls).toBe(1);
        expect(harness.__processExitCalls.length).toBe(1);
        expect(harness.__processExitCalls[0]).toBe(0);
        expect(result === true || harness.__processExitCalls[0] === 0).toBe(true);
    });

    test("blocks update (--squirrel-updated) the same way as install", () => {
        const harness = makeGateVm();
        let messageCalls = 0;
        harness.runSquirrelStartupGate({
            argv: [process.argv[0], "--squirrel-updated"],
            platformName: "win32",
            deps: {
                execSyncFn: () => {
                    const error = new Error("Access is denied");
                    error.status = 5;
                    throw error;
                },
                showMessageFn: () => {
                    messageCalls += 1;
                },
                relaunchFn: () => true,
                squirrelStartupFn: () => true,
            },
        });
        expect(messageCalls).toBe(1);
    });

    test("does not exit when UAC relaunch was declined but still shows the message", () => {
        // If the user clicks "No" on the UAC prompt, the elevated
        // copy never starts. The gate must still show the message
        // box and exit cleanly so we don't fall through to a
        // silent half-install — but we shouldn't claim relaunch
        // succeeded.
        const harness = makeGateVm();
        let relaunchCalls = 0;
        let messageCalls = 0;
        harness.runSquirrelStartupGate({
            argv: [process.argv[0], "--squirrel-install"],
            platformName: "win32",
            deps: {
                execSyncFn: () => {
                    const error = new Error("Access is denied");
                    error.status = 5;
                    throw error;
                },
                showMessageFn: () => {
                    messageCalls += 1;
                },
                relaunchFn: () => {
                    relaunchCalls += 1;
                    // User declined UAC.
                    return false;
                },
                squirrelStartupFn: () => true,
            },
        });
        expect(relaunchCalls).toBe(1);
        expect(messageCalls).toBe(1);
        // squirrel-startup must NOT have been called regardless.
        // (We can't observe this directly because we mocked it;
        // the message/relaunch being called is the proxy.)
    });

    test("delegates to squirrel-startup when no squirrel event is firing", () => {
        // Normal GUI launch (no --squirrel-* argv). The gate must
        // skip the elevation probe entirely and hand off.
        const harness = makeGateVm();
        let execCalls = 0;
        let squirrelCalls = 0;
        const result = harness.runSquirrelStartupGate({
            argv: [process.argv[0]],
            platformName: "win32",
            deps: {
                execSyncFn: () => {
                    execCalls += 1;
                    throw new Error("should not probe when no squirrel event");
                },
                squirrelStartupFn: () => {
                    squirrelCalls += 1;
                    return false;
                },
            },
        });
        expect(execCalls).toBe(0);
        expect(squirrelCalls).toBe(1);
        expect(result).toBe(false);
    });
});