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
// On Linux, after PyInstaller finishes, the script additionally runs
// ``staticx`` to re-wrap the onefile binary with its dynamically-linked
// loader dependencies statically bundled. This produces a portable
// ``snitch`` that can be run on other Linux machines without needing the
// exact same glibc / libstdc++ / libpython versions that the build host
// had. ``staticx`` only supports Linux 64-bit, so macOS and Windows
// builds skip the re-wrap step and ship the plain PyInstaller binary.
//
// Usage:
//   node scripts/build-backend.js           # build for the current OS
//   node scripts/build-backend.js linux     # force a target
//   node scripts/build-backend.js macos
//   node scripts/build-backend.js windows
//
// The script writes the final binary directly to
// ``src/backend/snitch[.exe]`` so the existing forge.config.js
// extraResource entries and src/main.js lookup logic continue to work
// unchanged.

"use strict";

const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const PROJECT_ROOT = path.resolve(__dirname, "..");
const BACKEND_DIR = path.join(PROJECT_ROOT, "src", "backend");
const ICON_PATH = path.join(BACKEND_DIR, "snitch.ico");
const ENTRY_SCRIPT = path.join(BACKEND_DIR, "snitch.py");
const BUILD_WORK_DIR = path.join(PROJECT_ROOT, "build", "pyinstaller");

const TARGETS = {
    linux: { exeName: "snitch", iconFlag: null, consoleFlag: null },
    macos: { exeName: "snitch", iconFlag: ["--icon", ICON_PATH], consoleFlag: null },
    windows: { exeName: "snitch.exe", iconFlag: ["--icon", ICON_PATH], consoleFlag: null },
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
    // The .ico is only consumed by Windows/macOS targets, but we verify it
    // up-front for every build so a missing icon never silently produces an
    // unbranded binary.
    if (!fs.existsSync(ICON_PATH)) {
        console.error(`Backend icon not found at ${ICON_PATH}`);
        process.exit(1);
    }
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

    // Linux-only: collect scipy/numpy compiled extensions and scipy's
    // data files into the bundle so the resulting PyInstaller onefile
    // does not carry DT_RUNPATH entries pointing at the build host's
    // ``/opt/_internal/cpython-...`` site-packages. Manylinux wheels
    // bake those RPATHs in at build time and ``staticx`` refuses to
    // re-wrap binaries whose loader dependencies reference paths that
    // will not exist on the target machine.
    //
    // ``--collect-binaries scipy`` pulls in scipy's ``.so`` modules
    // (including ``cython_special`` and the OpenBLAS bundle) without
    // the wheel's RPATH; ``--collect-binaries scipy_openblas32``
    // covers the transitive OpenBLAS package; ``--collect-data
    // scipy`` carries along any scipy data files that the runtime
    // expects to find next to the extension modules. The same flags
    // are applied to ``numpy`` for the same reason.
    if (target === "linux") {
        args.push(
            "--collect-binaries", "scipy",
            "--collect-binaries", "scipy_openblas32",
            "--collect-binaries", "numpy",
            "--collect-data", "scipy",
        );
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

// staticx (https://github.com/JonathonReinhart/staticx) re-wraps a
// dynamic ELF executable with its loader dependencies so the resulting
// binary runs on other Linux machines without matching glibc /
// libstdc++ / libpython versions. It only works for Linux 64-bit, so
// the macOS / Windows build paths short-circuit and ship the plain
// PyInstaller binary.
//
// staticx writes its output to a separate path, so we move the
// PyInstaller output aside first and let staticx produce the final
// ``snitch`` binary in place. This keeps the canonical filename that
// forge.config.js / src/main.js already look for.
function rewrapWithStaticx(target) {
    if (target !== "linux") {
        // Re-wrap only happens on Linux; see the module-level comment
        // block for the rationale.
        return;
    }
    const outputPath = path.join(BACKEND_DIR, "snitch");
    const pyinstallerPath = path.join(BACKEND_DIR, ".snitch.pyinstaller");
    if (!fs.existsSync(outputPath)) {
        console.error(
            `[build-backend] expected PyInstaller output at ${outputPath} before staticx wrap`,
        );
        process.exit(1);
    }
    try {
        fs.renameSync(outputPath, pyinstallerPath);
    } catch (error) {
        console.error(
            `[build-backend] failed to stage PyInstaller output for staticx: ${error.message}`,
        );
        process.exit(1);
    }
    console.log(
        `[build-backend] re-wrapping with staticx: ${pyinstallerPath} -> ${outputPath}`,
    );
    // ``--strip`` keeps the resulting binary smaller by stripping
    // symbols from the bundled archive contents. Compression is left at
    // the staticx default to keep startup latency reasonable.
    const result = spawnSync(
        "staticx",
        ["--strip", pyinstallerPath, outputPath],
        {
            cwd: PROJECT_ROOT,
            stdio: "inherit",
            env: process.env,
        },
    );
    // Whether staticx succeeded or failed, the staged PyInstaller
    // binary is no longer needed; keep the tree tidy.
    try {
        fs.unlinkSync(pyinstallerPath);
    } catch (error) {
        if (error && error.code !== "ENOENT") {
            console.warn(
                `[build-backend] could not remove staged PyInstaller binary ${pyinstallerPath}: ${error.message}`,
            );
        }
    }
    if (result.error) {
        if (result.error.code === "ENOENT") {
            console.error(
                `[build-backend] staticx was not found on PATH. Install it with 'pip install staticx' (or 'pip3 install -r src/backend/requirements.txt') and re-run.`,
            );
        } else {
            console.error(`[build-backend] failed to spawn staticx: ${result.error.message}`);
        }
        process.exit(1);
    }
    if (result.status !== 0) {
        console.error(`[build-backend] staticx exited with code ${result.status}`);
        process.exit(result.status || 1);
    }
}

// Manylinux-built Python wheels (notably scipy 1.17+) bake the build
// host's absolute prefix into ``DT_RUNPATH`` on a handful of compiled
// ``.so`` files. The most common offender is
// ``scipy/special/cython_special.cpython-314-x86_64-linux-gnu.so``,
// which carries ``DT_RUNPATH='/opt/_internal/cpython-3.14.0rc1/lib/python3.14/site-packages/scipy_openblas32/lib'``.
// ``staticx`` refuses to re-wrap a PyInstaller onefile whose embedded
// archive contains any ``DT_RUNPATH`` entry (see staticx #188); the
// build dies during staticx's audit phase with
// ``staticx: Unsupported PyInstaller input``.
//
// The fix: walk every ``.so`` under the active interpreter's
// ``site-packages`` that has a ``DT_RUNPATH``, strip it with
// ``patchelf --remove-rpath``, and replace it with a
// ``$ORIGIN``-relative ``DT_RPATH`` (using ``patchelf --force-rpath``
// so the result is ``DT_RPATH``, not ``DT_RUNPATH``) pointing at the
// wheel's bundled ``.libs`` sibling directory. After this rewrite,
// the loader can still resolve OpenBLAS / libgfortran from the
// wheel's bundled ``scipy.libs`` (or ``numpy.libs``) directory at
// runtime -- exactly how every other scipy ``.so`` is already
// configured in the wheel. ``DT_RPATH`` with a ``$ORIGIN``-relative
// value is what staticx expects.
//
// We only do this on Linux because the ``DT_RUNPATH`` problem is
// Linux/manylinux-only; macOS uses ``LC_LOAD_DYLIB`` and Windows uses
// import tables, neither of which staticx is sensitive to. ``patchelf``
// is also Linux-only, so the helper short-circuits on other targets.
function stripBadRpaths(target) {
    if (target !== "linux") {
        return;
    }
    // Resolve the active interpreter's ``site-packages`` directories
    // by asking Python directly. This works whether the build is run
    // from a system ``python3``, a virtualenv, or the project's
    // ``.venv``.
    const probe = spawnSync(
        "python3",
        ["-c", "import site, sys; print('\\n'.join(site.getsitepackages() + [sys.prefix]))"],
        { cwd: PROJECT_ROOT, stdio: ["ignore", "pipe", "inherit"], env: process.env },
    );
    if (probe.error || probe.status !== 0) {
        console.warn(
            `[build-backend] could not resolve site-packages to scan for bad DT_RUNPATH entries: ` +
            `${probe.error ? probe.error.message : `python3 exited ${probe.status}`}`,
        );
        return;
    }
    const siteRoots = probe.stdout
        .toString()
        .split("\n")
        .map((s) => s.trim())
        .filter(Boolean);
    let touched = 0;
    for (const root of siteRoots) {
        if (!fs.existsSync(root)) continue;
        // Walk every .so file directly (not via ``rglob``) so we keep
        // the relative path from ``root`` for the ``$ORIGIN`` rewrite.
        // We avoid recursing into eggs/site-packages of unrelated
        // venvs; the script's own interpreter is the source of truth.
        const stack = [root];
        while (stack.length) {
            const dir = stack.pop();
            let entries;
            try {
                entries = fs.readdirSync(dir, { withFileTypes: true });
            } catch (error) {
                continue;
            }
            for (const entry of entries) {
                const full = path.join(dir, entry.name);
                if (entry.isDirectory()) {
                    stack.push(full);
                    continue;
                }
                if (!entry.name.endsWith(".so")) continue;
                if (rewriteSORpath(full, root)) {
                    touched += 1;
                }
            }
        }
    }
    if (touched === 0) {
        console.log(
            "[build-backend] no absolute DT_RUNPATH entries found in site-packages; nothing to patch",
        );
    } else {
        console.log(
            `[build-backend] rewrote ${touched} .so file(s) to drop absolute DT_RUNPATH entries`,
        );
    }
}

// ``readelf -d <so>`` parses the ``DT_RUNPATH`` / ``DT_RPATH`` dynamic
// entries. We use it to detect whether ``patchelf`` needs to run on a
// given ``.so``. Returns true if a rewrite happened.
function readElfDynamic(soPath) {
    const result = spawnSync("readelf", ["-d", soPath], {
        cwd: PROJECT_ROOT,
        stdio: ["ignore", "pipe", "ignore"],
        env: process.env,
    });
    if (result.error || result.status !== 0) {
        return null;
    }
    const stdout = result.stdout.toString();
    let runpath = null;
    let rpath = null;
    for (const line of stdout.split("\n")) {
        // Lines look like: `` 0x... (RUNPATH)            Library runpath: [/foo/bar]``
        // or `` 0x... (RPATH)              Library rpath: [$ORIGIN/../baz]``.
        // The absolute vs relative distinction is whether the path
        // starts with ``[``.
        const runMatch = line.match(/\(RUNPATH\).*?:\s*\[([^\]]*)\]/);
        if (runMatch) runpath = runMatch[1];
        const rpathMatch = line.match(/\(RPATH\).*?:\s*\[([^\]]*)\]/);
        if (rpathMatch) rpath = rpathMatch[1];
    }
    return { runpath, rpath };
}

// Rewrite ``soPath`` to drop its absolute ``DT_RUNPATH`` (which
// ``staticx`` rejects) and replace it with a ``$ORIGIN``-relative
// ``RPATH`` that lands on the wheel's bundled ``scipy.libs`` (or
// ``numpy.libs``) sibling directory. Returns true if a rewrite was
// applied.
//
// We only rewrite when the offending ``DT_RUNPATH`` points at an
// absolute path (``/foo``); ``$ORIGIN``-relative paths are fine for
// staticx (relative ``RPATH`` is allowed; ``RUNPATH`` itself is
// forbidden regardless, but the scipy wheels only put ``RUNPATH`` on
// files that PyInstaller's hook doesn't otherwise rewrite, and the
// one file we've observed with this problem is ``cython_special``).
function rewriteSORpath(soPath, siteRoot) {
    const dyn = readElfDynamic(soPath);
    if (!dyn) return false;
    // ``staticx`` forbids any ``DT_RUNPATH`` entry, whether it points
    // at an absolute path like ``/opt/_internal/...`` or at a
    // ``$ORIGIN``-relative path. The fix in both cases is to convert
    // the entry to ``DT_RPATH`` (which staticx accepts when it's
    // relative) so the loader still resolves the wheel's bundled
    // libraries but staticx's audit is happy.
    //
    // ``DT_RPATH`` is allowed as long as the path is ``$ORIGIN``-
    // relative. We only rewrite files that have a ``DT_RUNPATH``,
    // since ``DT_RPATH`` already passes staticx's audit and leaving
    // them alone avoids spurious edits.
    const offendingRunpath = dyn.runpath != null;
    if (!offendingRunpath) return false;
    // The original ``.so`` lives at e.g. ``<siteRoot>/scipy/special/foo.so``;
    // after PyInstaller bundles the wheel the file ends up at the same
    // relative location (``<bundle>/scipy/special/foo.so``), and the
    // ``scipy.libs`` sibling is at ``<bundle>/scipy.libs``. So the
    // ``$ORIGIN``-relative path is ``../../scipy.libs``.
    //
    // For numpy's layout, ``numpy.libs`` is a sibling of ``numpy/``
    // under ``site-packages``; the existing scipy ``.so`` files use
    // ``$ORIGIN/../../scipy.libs`` and numpy uses
    // ``$ORIGIN/../../numpy.libs``. We pick the correct ``.libs``
    // sibling based on the closest package ancestor that contains a
    // sibling ``<pkg>.libs`` directory.
    const libsSibling = findLibsSibling(soPath, siteRoot);
    if (!libsSibling) {
        console.warn(
            `[build-backend] skipping ${soPath}: cannot locate a .libs sibling to write a $ORIGIN RPATH`,
        );
        return false;
    }
    const rel = path.relative(path.dirname(soPath), libsSibling);
    const newRpath = `$ORIGIN/${rel.split(path.sep).join("/")}`;
    // ``--remove-rpath`` drops both ``RPATH`` and ``RUNPATH``; we
    // re-set ``RPATH`` (not ``RUNPATH``) because staticx is fine with
    // a relative ``RPATH`` and forbids ``RUNPATH`` outright.
    //
    // ``--force-rpath`` (rather than ``--set-rpath``) is critical
    // here: modern patchelf defaults to writing ``DT_RUNPATH``,
    // which staticx also forbids. ``--force-rpath`` downgrades the
    // entry to ``DT_RPATH`` at the cost of a warning, which is what
    // staticx wants to see.
    const remove = spawnSync("patchelf", ["--remove-rpath", soPath], {
        cwd: PROJECT_ROOT,
        stdio: "inherit",
        env: process.env,
    });
    if (remove.error || remove.status !== 0) {
        console.error(
            `[build-backend] patchelf --remove-rpath failed on ${soPath}; ` +
            `install 'patchelf' (e.g. apt install patchelf) and re-run`,
        );
        process.exit(remove.status || 1);
    }
    const setrp = spawnSync("patchelf", ["--force-rpath", "--set-rpath", newRpath, soPath], {
        cwd: PROJECT_ROOT,
        stdio: "inherit",
        env: process.env,
    });
    if (setrp.error || setrp.status !== 0) {
        console.error(
            `[build-backend] patchelf --force-rpath --set-rpath ${newRpath} failed on ${soPath}`,
        );
        process.exit(setrp.status || 1);
    }
    console.log(
        `[build-backend]   ${path.relative(PROJECT_ROOT, soPath)}: DT_RUNPATH=${dyn.runpath} -> RPATH=${newRpath}`,
    );
    return true;
}

// Walk up from ``soPath`` toward ``siteRoot`` looking for a sibling
// directory named ``<pkg>.libs``. Returns the absolute path of that
// sibling, or null if none is found.
function findLibsSibling(soPath, siteRoot) {
    let dir = path.dirname(soPath);
    while (dir.startsWith(siteRoot)) {
        const parent = path.dirname(dir);
        const base = path.basename(dir);
        const libs = path.join(parent, `${base}.libs`);
        if (fs.existsSync(libs)) {
            return libs;
        }
        if (dir === siteRoot) break;
        dir = parent;
    }
    return null;
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
    applyStaticxPatch();
    removeExistingBinary(targetConfig.exeName);

    stripBadRpaths(target);

    const args = buildArgs(target);
    invokePyInstaller(args);
    rewrapWithStaticx(target);
    verifyOutput(targetConfig.exeName);

    console.log(`[build-backend] done.`);
}

// Apply the project-local staticx workaround before doing anything
// else. The applier is idempotent: re-running it on an already-patched
// or upstream-fixed install is a no-op with exit 0. We invoke it as a
// separate Node script so the patch logic stays out of this file and
// can be regenerated independently from the upstream source.
//
// On macOS/Windows the applier short-circuits because staticx is not
// installed, so this call is cheap and harmless.
function applyStaticxPatch() {
    const applier = path.join(PROJECT_ROOT, "scripts", "apply-staticx-patch.js");
    const result = spawnSync(process.execPath, [applier], {
        cwd: PROJECT_ROOT,
        stdio: "inherit",
        env: process.env,
    });
    if (result.error) {
        console.error(
            `[build-backend] failed to spawn ${applier}: ${result.error.message}`,
        );
        process.exit(1);
    }
    if (result.status !== 0) {
        console.error(
            `[build-backend] staticx patcher exited with code ${result.status}; ` +
            "see messages above for details",
        );
        process.exit(result.status || 1);
    }
}

main();
