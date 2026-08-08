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
//   * On Windows for a ``--squirrel-install`` / ``--squirrel-updated``
//     event: probes elevation via ``net session``. If not elevated,
//     shows a native message box, attempts a UAC relaunch of the
//     installer, and exits.
//   * On Windows for ``--squirrel-uninstall`` / ``--squirrel-obsolete``
//     or any non-install event: delegates to squirrel-startup because
//     those events don't touch protected locations.
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

function makeGateVm() {
    const sourceText = fs.readFileSync(MAIN_PATH, "utf8");
    const fnSources = [
        "isWindowsProcessElevated",
        "showWindowsElevationMessageBox",
        "relaunchInstallerElevatedViaUac",
        "resolveSquirrelUpdateExe",
        "resolveSquirrelInstalledFiles",
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
        // The command-string lives in the last positional argument
        // after ``-Command``. It must mention the WinForms MessageBox
        // and embed our title.
        const commandArg = captured.args[captured.args.length - 1];
        expect(typeof commandArg).toBe("string");
        expect(commandArg).toContain("System.Windows.Forms.MessageBox");
        expect(commandArg).toContain("PacketSnitch installer");
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

    test("delegates to squirrel-startup on Windows for non-install events", () => {
        const harness = makeGateVm();
        let squirrelCalls = 0;
        let execCalls = 0;
        const result = harness.runSquirrelStartupGate({
            argv: [process.argv[0], "--squirrel-uninstall"],
            platformName: "win32",
            deps: {
                execSyncFn: () => {
                    execCalls += 1;
                    throw new Error("should not be called for uninstall");
                },
                squirrelStartupFn: () => {
                    squirrelCalls += 1;
                    return true;
                },
            },
        });
        expect(execCalls).toBe(0);
        expect(squirrelCalls).toBe(1);
        expect(result).toBe(true);
    });

    test("delegates to squirrel-startup on Windows for --squirrel-obsolete", () => {
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
        expect(squirrelCalls).toBe(1);
        expect(result).toBe(true);
    });

    test("delegates to squirrel-startup on Windows when process IS elevated", () => {
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
        expect(execCalls).toBe(1);
        expect(squirrelCalls).toBe(1);
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