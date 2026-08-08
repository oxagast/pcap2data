#!/usr/bin/env node
// Spawn a child process with `LD_LIBRARY_PATH` prepended so that
// manylinux `.libs/` shims (e.g. `libscipy_openblas64_-<hash>.so`) can be
// resolved by the dynamic linker.
//
// Why this is necessary: when CPython imports numpy via an in-process
// `importlib.util.spec_from_file_location(...).loader.exec_module(...)`,
// the loader has already cached the absence of those shims and won't pick
// them up if we only modify `os.environ` from a conftest. They have to be
// on `LD_LIBRARY_PATH` BEFORE the Python interpreter starts.
//
// This wraps `npm run test:backend` and any other tooling that needs the
// shims visible from the very first `dlopen` in the spawned process.
// Mirrors `buildBackendProcessEnv()` in `src/back-comm.js` so the bridge
// and the test runner stay in sync. See also
// /memories/repo/manylinux_libs_ld_library_path.md.

"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");

const PROJECT_ROOT = path.resolve(__dirname, "..");

function listSitePackagesRoots() {
    const roots = [];
    const home = os.homedir();
    const versionRoots = [
        path.join(home, ".local", "lib"),
        path.join("/usr/local/lib64"),
        path.join("/usr/local/lib"),
        path.join(home, ".local", "lib64"),
    ];
    for (const versionRoot of versionRoots) {
        if (!fs.existsSync(versionRoot)) continue;
        let entries = [];
        try {
            entries = fs.readdirSync(versionRoot);
        } catch (_) {
            continue;
        }
        for (const entry of entries) {
            if (!/^python3\.\d+$/.test(entry)) continue;
            roots.push(path.join(versionRoot, entry, "site-packages"));
        }
    }
    for (const sibling of ["lib", "lib64"]) {
        const venvLib = path.join(PROJECT_ROOT, ".venv", sibling);
        if (!fs.existsSync(venvLib)) continue;
        let entries = [];
        try {
            entries = fs.readdirSync(venvLib);
        } catch (_) {
            continue;
        }
        for (const entry of entries) {
            if (!/^python3\.\d+$/.test(entry)) continue;
            roots.push(path.join(venvLib, entry, "site-packages"));
        }
    }
    return roots;
}

function collectLibsDirs() {
    const libs = [];
    const seen = new Set();
    for (const root of listSitePackagesRoots()) {
        if (!fs.existsSync(root)) continue;
        let entries = [];
        try {
            entries = fs.readdirSync(root);
        } catch (_) {
            continue;
        }
        for (const entry of entries) {
            if (!entry.endsWith(".libs")) continue;
            const fullPath = path.join(root, entry);
            let isDir = false;
            try {
                isDir = fs.statSync(fullPath).isDirectory();
            } catch (_) {
                continue;
            }
            if (!isDir) continue;
            if (seen.has(fullPath)) continue;
            seen.add(fullPath);
            libs.push(fullPath);
        }
    }
    return libs;
}

function buildChildEnv() {
    const env = { ...process.env };
    if (process.platform !== "linux") return env;
    const libs = collectLibsDirs();
    if (libs.length === 0) return env;
    const merged = libs.join(path.delimiter);
    env.LD_LIBRARY_PATH = env.LD_LIBRARY_PATH
        ? `${merged}${path.delimiter}${env.LD_LIBRARY_PATH}`
        : merged;
    return env;
}

function spawnChild() {
    const args = process.argv.slice(2);
    if (args.length === 0) {
        process.stderr.write(
            "usage: node scripts/with-libs-path.js <command> [args...]\n",
        );
        process.exit(2);
    }
    const [command, ...commandArgs] = args;
    const env = buildChildEnv();
    const result = require("child_process").spawnSync(command, commandArgs, {
        stdio: "inherit",
        env,
    });
    process.exit(result.status === null ? 1 : result.status);
}

spawnChild();