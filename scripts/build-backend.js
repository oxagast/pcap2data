#!/usr/bin/env node
// OS-aware PyInstaller build for the PacketSnitch backend.
//
// We previously invoked `python3 -m PyInstaller snitch.spec`, which has two
// problems:
//
//   1. PyInstaller writes the analysis script's *absolute* path into the
//      generated spec on every run. Committing the spec back into git then
//      hard-codes whichever machine built last, which silently breaks
//      builds on every other platform.
//   2. The spec was checked in alongside source code, so cross-platform
//      builds would either fail outright or ship a binary built against
//      the wrong paths.
//
// This script invokes PyInstaller directly against `src/backend/snitch.py`
// with command-line arguments tailored to the host OS. There is no
// generated spec file to commit, and each platform gets a binary whose
// embedded paths reflect the machine that actually produced it.
//
// Usage:
//   node scripts/build-backend.js           # build for the current OS
//   node scripts/build-backend.js linux     # force a target
//   node scripts/build-backend.js macos
//   node scripts/build-backend.js windows
//
// The script writes the binary directly to `src/backend/snitch[.exe]` so
// the existing forge.config.js extraResource entries and src/main.js
// lookup logic continue to work unchanged.

"use strict";

const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const PROJECT_ROOT = path.resolve(__dirname, "..");
const BACKEND_DIR = path.join(PROJECT_ROOT, "src", "backend");
const ENTRY_SCRIPT = path.join(BACKEND_DIR, "snitch.py");
const BUILD_WORK_DIR = path.join(PROJECT_ROOT, "build", "pyinstaller");

const TARGETS = {
    linux: { exeName: "snitch", iconFlag: null, consoleFlag: null },
    macos: { exeName: "snitch", iconFlag: null, consoleFlag: null },
    windows: { exeName: "snitch.exe", iconFlag: null, consoleFlag: null },
};

function resolveTarget() {
    const requested = (process.argv[2] || "").toLowerCase();
    if (requested) {
        if (!TARGETS[requested]) {
            console.error(
                `Unknown target '${requested}'. Expected one of: ${Object.keys(TARGETS).join(", ")}.`,
            );
            process.exit(2);
        }
        return requested;
    }
    switch (process.platform) {
        case "win32":
            return "windows";
        case "darwin":
            return "macos";
        case "linux":
        default:
            return "linux";
    }
}

function ensureEntryScript() {
    if (!fs.existsSync(ENTRY_SCRIPT)) {
        console.error(`Backend entry script not found at ${ENTRY_SCRIPT}`);
        process.exit(1);
    }
}

function preflightCheck() {
    ensureEntryScript();
    fs.mkdirSync(BUILD_WORK_DIR, { recursive: true });
}

function buildArgs(target) {
    const targetConfig = TARGETS[target];
    const args = [
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--name",
        targetConfig.exeName,
        "--distpath",
        BACKEND_DIR,
        "--workpath",
        BUILD_WORK_DIR,
        // PyInstaller always writes a `.spec` next to where it runs; route it
        // into the build directory so we never accidentally land a checked-in
        // spec under src/backend/ that hard-codes another machine's paths.
        "--specpath",
        BUILD_WORK_DIR,
    ];

    // Console mode preserves stdout/stderr; we keep it because the GUI
    // streams the backend's log output. Both windows and *nix want this.
    if (targetConfig.consoleFlag) {
        args.push(targetConfig.consoleFlag);
    }

    if (targetConfig.iconFlag) {
        args.push(...targetConfig.iconFlag);
    }

    args.push(ENTRY_SCRIPT);
    return args;
}

function removeExistingBinary(exeName) {
    const target = path.join(BACKEND_DIR, exeName);
    try {
        fs.unlinkSync(target);
        console.log(`[build-backend] removed previous binary at ${target}`);
    } catch (error) {
        if (error && error.code !== "ENOENT") {
            console.warn(
                `[build-backend] could not remove previous binary ${target}: ${error.message}`,
            );
        }
    }
}

function invokePyInstaller(args) {
    console.log(`[build-backend] running: python3 ${args.join(" ")}`);
    const result = spawnSync("python3", args, {
        cwd: PROJECT_ROOT,
        stdio: "inherit",
        env: process.env,
    });
    if (result.error) {
        console.error(`[build-backend] failed to spawn python3: ${result.error.message}`);
        process.exit(1);
    }
    if (result.status !== 0) {
        console.error(`[build-backend] PyInstaller exited with code ${result.status}`);
        process.exit(result.status || 1);
    }
}

function verifyOutput(exeName) {
    const outputPath = path.join(BACKEND_DIR, exeName);
    if (!fs.existsSync(outputPath)) {
        console.error(
            `[build-backend] expected binary was not produced at ${outputPath}`,
        );
        process.exit(1);
    }
    const stats = fs.statSync(outputPath);
    console.log(
        `[build-backend] built ${outputPath} (${(stats.size / 1024 / 1024).toFixed(2)} MiB)`,
    );
}

function main() {
    const target = resolveTarget();
    const targetConfig = TARGETS[target];
    console.log(`[build-backend] target platform: ${target}`);

    preflightCheck();
    removeExistingBinary(targetConfig.exeName);

    const args = buildArgs(target);
    invokePyInstaller(args);
    verifyOutput(targetConfig.exeName);

    console.log(`[build-backend] done.`);
}

main();