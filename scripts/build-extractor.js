#!/usr/bin/env node
// OS-aware PyInstaller build for the snitch_extract archive helper.
//
// Mirrors ``scripts/build-backend.js`` so the bundled archive helper
// (``snitch-extract`` / ``snitch-extract.exe``) lands at the same
// ``src/backend/`` location the Electron main process already looks
// for at runtime. The script is intentionally a sibling rather than a
// flag on build-backend.js because it produces a second binary and
// pulls in two extra deps (cabarchive, py7zr) that the main
// ``snitch.py`` does not need.
//
// Usage:
//   node scripts/build-extractor.js           # build for the current OS
//   node scripts/build-extractor.js linux     # force a target
//   node scripts/build-extractor.js macos
//   node scripts/build-extractor.js windows
//
// The script writes the binary directly to ``src/backend/snitch-extract[.exe]``
// so the existing forge.config.js extraResource entries and
// ``src/main.js`` lookup logic continue to work unchanged.

"use strict";

const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const PROJECT_ROOT = path.resolve(__dirname, "..");
const BACKEND_DIR = path.join(PROJECT_ROOT, "src", "backend");
const ENTRY_SCRIPT = path.join(BACKEND_DIR, "snitch_extract.py");
const BUILD_WORK_DIR = path.join(PROJECT_ROOT, "build", "pyinstaller-extract");
// Slim requirements file containing only the deps ``snitch_extract.py``
// imports (``cabarchive``, ``py7zr``). Kept separate from the full
// ``requirements.txt`` (which pulls in scapy, numpy, geoip2, …) so the
// PyInstaller bundle for the archive helper stays small.
const REQUIREMENTS_FILE = path.join(BACKEND_DIR, "requirements-extract.txt");

const TARGETS = {
    linux: { exeName: "snitch-extract" },
    macos: { exeName: "snitch-extract" },
    windows: { exeName: "snitch-extract.exe" },
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
        console.error(`Archive helper entry script not found at ${ENTRY_SCRIPT}`);
        process.exit(1);
    }
}

function preflightCheck() {
    ensureEntryScript();
    fs.mkdirSync(BUILD_WORK_DIR, { recursive: true });
}

// Install the slim ``requirements-extract.txt`` deps into the active
// Python environment so PyInstaller can import them. Uses
// ``python3 -m pip`` so we pick up the exact interpreter PyInstaller
// will run against; falls through gracefully if the user already has
// the deps and ``pip`` is just being noisy.
function installRequirements() {
    if (!fs.existsSync(REQUIREMENTS_FILE)) {
        console.error(
            `[build-extractor] requirements file not found at ${REQUIREMENTS_FILE}`,
        );
        process.exit(1);
    }
    console.log(
        `[build-extractor] installing Python deps from ${REQUIREMENTS_FILE}`,
    );
    const result = spawnSync(
        "python3",
        ["-m", "pip", "install", "--requirement", REQUIREMENTS_FILE],
        {
            cwd: PROJECT_ROOT,
            stdio: "inherit",
            env: process.env,
        },
    );
    if (result.error) {
        console.error(
            `[build-extractor] failed to spawn pip: ${result.error.message}`,
        );
        process.exit(1);
    }
    if (result.status !== 0) {
        console.error(
            `[build-extractor] pip exited with code ${result.status}`,
        );
        process.exit(result.status || 1);
    }
}

function buildArgs(target) {
    const targetConfig = TARGETS[target];
    return [
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
        "--specpath",
        BUILD_WORK_DIR,
        // Console mode preserves stdout/stderr; the Node side reads
        // both. Both Windows and *nix want this.
        "--console",
        ENTRY_SCRIPT,
    ];
}

function removeExistingBinary(exeName) {
    const target = path.join(BACKEND_DIR, exeName);
    try {
        fs.unlinkSync(target);
        console.log(`[build-extractor] removed previous binary at ${target}`);
    } catch (error) {
        if (error && error.code !== "ENOENT") {
            console.warn(
                `[build-extractor] could not remove previous binary ${target}: ${error.message}`,
            );
        }
    }
}

function invokePyInstaller(args) {
    console.log(`[build-extractor] running: python3 ${args.join(" ")}`);
    const result = spawnSync("python3", args, {
        cwd: PROJECT_ROOT,
        stdio: "inherit",
        env: process.env,
    });
    if (result.error) {
        console.error(`[build-extractor] failed to spawn python3: ${result.error.message}`);
        process.exit(1);
    }
    if (result.status !== 0) {
        console.error(`[build-extractor] PyInstaller exited with code ${result.status}`);
        process.exit(result.status || 1);
    }
}

function verifyOutput(exeName) {
    const outputPath = path.join(BACKEND_DIR, exeName);
    if (!fs.existsSync(outputPath)) {
        console.error(
            `[build-extractor] expected binary was not produced at ${outputPath}`,
        );
        process.exit(1);
    }
    const stats = fs.statSync(outputPath);
    console.log(
        `[build-extractor] built ${outputPath} (${(stats.size / 1024 / 1024).toFixed(2)} MiB)`,
    );
}

function main() {
    const target = resolveTarget();
    const targetConfig = TARGETS[target];
    console.log(`[build-extractor] target platform: ${target}`);

    preflightCheck();
    installRequirements();
    removeExistingBinary(targetConfig.exeName);

    const args = buildArgs(target);
    invokePyInstaller(args);
    verifyOutput(targetConfig.exeName);

    console.log(`[build-extractor] done.`);
}

main();
