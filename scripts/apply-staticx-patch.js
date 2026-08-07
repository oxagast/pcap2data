#!/usr/bin/env node
// Idempotent applier for patches/staticx-api.py.patch.
//
// Upstream staticx 0.14.x has a bug in its bootloader-identify probe:
// it calls ``r.check_returncode()`` on the result of running the
// bootloader with ``STATICX_BOOTLOADER_IDENTIFY=1``. The bootloader
// intentionally exits with status 2 in identify mode (no archive
// attached; that's the documented identify protocol), so
// ``check_returncode()`` aborts every build with ``CalledProcessError``.
//
// This script applies patches/staticx-api.py.patch to the installed
// ``staticx/api.py`` to work around the bug. It is safe to re-run on
// every build (a sentinel comment in the patched code marks it as
// already-applied), and it is safe to run when staticx is not
// installed (e.g. macOS / Windows builds): in that case the script
// exits 0 with a no-op message and does nothing.
//
// Behavior:
//   - staticx not importable in the active Python: no-op, exit 0.
//   - Sentinel already present in api.py: no-op, exit 0.
//   - Sentinel absent, patch dry-run succeeds: apply the patch,
//     exit 0.
//   - Sentinel absent, patch dry-run fails because the buggy block
//     was already fixed upstream: log a warning, exit 0 (the build
//     does not need the workaround).
//   - Sentinel absent, patch dry-run fails for any other reason:
//     log an error and exit 1 so the build fails loudly.

"use strict";

const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const PROJECT_ROOT = path.resolve(__dirname, "..");
const PATCH_FILE = path.join(PROJECT_ROOT, "patches", "staticx-api.py.patch");
const SENTINEL = "STATICX_BOOTLOADER_IDENTIFY_PATCH_APPLIED";

function resolveStaticxPackageDir() {
    // Ask Python directly where staticx is installed. This works for
    // system Python, virtualenvs, .venv, or any other layout because
    // we go through the import system rather than guessing paths.
    const probe = spawnSync(
        "python3",
        [
            "-c",
            "import os, staticx; print(os.path.dirname(staticx.__file__))",
        ],
        { cwd: PROJECT_ROOT, stdio: ["ignore", "pipe", "pipe"], env: process.env },
    );
    if (probe.error) {
        console.warn(
            `[apply-staticx-patch] could not spawn python3: ${probe.error.message}`,
        );
        return null;
    }
    if (probe.status !== 0) {
        // staticx not installed (or import error). Treat as a no-op
        // so macOS / Windows builds keep working.
        return null;
    }
    const dir = probe.stdout.toString().trim();
    if (!dir) return null;
    return dir;
}

function main() {
    if (!fs.existsSync(PATCH_FILE)) {
        console.error(
            `[apply-staticx-patch] patch file not found at ${PATCH_FILE}`,
        );
        process.exit(1);
    }

    const packageDir = resolveStaticxPackageDir();
    if (!packageDir) {
        console.log(
            "[apply-staticx-patch] staticx is not installed in the active " +
            "interpreter; nothing to patch",
        );
        return;
    }

    const apiPath = path.join(packageDir, "api.py");
    if (!fs.existsSync(apiPath)) {
        console.warn(
            `[apply-staticx-patch] ${apiPath} does not exist; staticx layout may have changed; skipping`,
        );
        return;
    }

    // Idempotency check: if the sentinel is already present, the patch
    // has been applied. Bail out without invoking ``patch``.
    let apiText;
    try {
        apiText = fs.readFileSync(apiPath, "utf-8");
    } catch (error) {
        console.error(
            `[apply-staticx-patch] failed to read ${apiPath}: ${error.message}`,
        );
        process.exit(1);
    }
    if (apiText.includes(SENTINEL)) {
        console.log(
            `[apply-staticx-patch] ${apiPath} is already patched; skipping`,
        );
        return;
    }

    // Dry-run first. If dry-run succeeds, the patch hasn't been
    // applied yet, so apply it for real.
    const dry = spawnSync(
        "patch",
        ["--dry-run", "-Np0", "-i", PATCH_FILE],
        { cwd: packageDir, stdio: ["ignore", "pipe", "pipe"], env: process.env },
    );
    if (dry.status === 0) {
        const apply = spawnSync(
            "patch",
            ["-Np0", "-i", PATCH_FILE],
            { cwd: packageDir, stdio: "inherit", env: process.env },
        );
        if (apply.error) {
            console.error(
                `[apply-staticx-patch] failed to spawn patch: ${apply.error.message}`,
            );
            process.exit(1);
        }
        if (apply.status !== 0) {
            console.error(
                `[apply-staticx-patch] patch exited with code ${apply.status} after a successful dry-run`,
            );
            process.exit(apply.status || 1);
        }
        // Drop the bytecode cache so any subsequent ``python3`` invocation
        // (PyInstaller, staticx itself) re-reads the patched source.
        try {
            fs.unlinkSync(path.join(packageDir, "__pycache__", "api.cpython-314.pyc"));
        } catch (error) {
            if (error && error.code !== "ENOENT") {
                console.warn(
                    `[apply-staticx-patch] could not remove stale api.pyc: ${error.message}`,
                );
            }
        }
        console.log(
            `[apply-staticx-patch] patched ${apiPath}: bootloader-identify exit-code 2 is now tolerated`,
        );
        return;
    }

    // Dry-run failed. Try reverse-apply: if the file already contains
    // the patched form, reverse-apply would succeed and we should
    // skip the patch (upstream fixed it independently).
    const rev = spawnSync(
        "patch",
        ["--dry-run", "--reverse", "-Np0", "-i", PATCH_FILE],
        { cwd: packageDir, stdio: ["ignore", "pipe", "pipe"], env: process.env },
    );
    if (rev.status === 0) {
        console.warn(
            `[apply-staticx-patch] ${apiPath} already contains the patched logic; ` +
            "upstream staticx appears to have fixed the bug independently. " +
            "Project-local patch is now redundant. Skipping.",
        );
        return;
    }

    // Both forward and reverse dry-runs failed. If the buggy
    // ``r.check_returncode()`` call is gone from the file, upstream
    // has restructured the code (most likely fixed the bug with a
    // different approach); in that case don't fail the build, just
    // warn. If the buggy call is still there but the patch can't
    // apply, that's a real conflict -- the patch is stale and the
    // operator needs to regenerate it.
    const buggyStillPresent = apiText.includes("r.check_returncode()");
    if (!buggyStillPresent) {
        console.warn(
            `[apply-staticx-patch] ${apiPath} no longer contains the buggy ` +
            "``r.check_returncode()`` call that this patch was meant to fix. " +
            "Upstream staticx appears to have restructured the code. " +
            "Project-local patch is no longer applicable. Skipping.",
        );
        return;
    }

    console.error(
        `[apply-staticx-patch] failed to apply ${PATCH_FILE} to ${apiPath}.\n` +
        "The buggy ``r.check_returncode()`` call is still present in the\n" +
        "upstream staticx source, but the surrounding context has drifted\n" +
        "in a way this patch can no longer match. Refresh the patch by\n" +
        "regenerating it from the current upstream source:\n" +
        "    python3 /tmp/gen-staticx-patch.py\n" +
        "or, if upstream has fixed the bug differently, remove the\n" +
        "patch file and delete the call from this script.",
    );
    if (dry.stderr) process.stderr.write(dry.stderr);
    process.exit(1);
}

main();