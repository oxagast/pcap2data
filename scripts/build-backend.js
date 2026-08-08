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
//   node scripts/build-backend.js --force   # ignore cache, rebuild
//
// The script writes the final binary directly to
// ``src/backend/snitch[.exe]`` so the existing forge.config.js
// extraResource entries and src/main.js lookup logic continue to work
// unchanged.
//
// Incremental build cache (``scripts/build-cache.js``):
// To save time on repeated ``npm run make`` invocations, the script
// computes a SHA-256 cache key over every input that can affect the
// bundled binary (every ``.py`` under ``src/backend/``, the pinned
// dependency versions, the build-pipeline scripts, the resolved
// Python interpreter, and the build argument list). If the key
// matches the previously-built key and ``src/backend/snitch[.exe]``
// still exists with non-zero size, the script skips the entire
// PyInstaller + staticx pipeline and exits. To force a rebuild, pass
// ``--force`` or set ``SNITCH_FORCE_BUILD=1`` / ``FORCE=1`` in the
// environment.

"use strict";

const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const PROJECT_ROOT = path.resolve(__dirname, "..");
const BACKEND_DIR = path.join(PROJECT_ROOT, "src", "backend");
const ICON_PATH = path.join(BACKEND_DIR, "snitch.ico");
const ENTRY_SCRIPT = path.join(BACKEND_DIR, "snitch.py");
const BUILD_WORK_DIR = path.join(PROJECT_ROOT, "build", "pyinstaller");
const CACHE_HELPER = require("./build-cache");

// The full ``src/backend/`` tree is the "backend code" from
// PyInstaller's perspective -- the entry script plus every module it
// imports at runtime. Any edit to any of these files invalidates the
// cache. We also include the pinned dependency versions (a bump in
// ``numpy`` changes the bundled bytecode), the build pipeline scripts
// (their templates affect what PyInstaller produces), and the resolved
// Python interpreter (different interpreters bundle different stdlib
// bytecode). See ``scripts/build-cache.js`` for the full hash inputs.
const SOURCE_ROOTS = ["src/backend"];
const REQUIREMENTS_FILES = ["src/backend/requirements.txt"];
// ``build-extractor.js`` is intentionally NOT included here: it's a
// sibling script that builds a different binary with a different
// entry script and a different requirements file. Mixing the two
// caches would be a layering bug, not a safety net.
const SCRIPT_FILES = [
    "scripts/run_pyinstaller.py",
    "scripts/stage_patched_sos.py",
    "scripts/build-cache.js",
    "scripts/build-backend.js",
];

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
    // We invoke ``scripts/run_pyinstaller.py`` directly instead of
    // ``python3 -m PyInstaller`` because the wrapper consumes the
    // patched-.so cache produced by ``stage_patched_sos.py`` and
    // substitutes ``a.binaries[].src_name`` between Analysis and EXE.
    // Staticx refuses any DT_RUNPATH that ends up in the PyInstaller
    // archive (e.g. ``libabsl_*.so.20260526`` shipped by grpcio /
    // tensorboard / pyarrow); caching and patching those files before
    // bundling is what lets the build finish.
    const targetConfig = TARGETS[target];
    const args = [
        path.join(PROJECT_ROOT, "scripts", "run_pyinstaller.py"),
        "--name",
        targetConfig.exeName,
        "--distpath",
        BACKEND_DIR,
        "--workpath",
        BUILD_WORK_DIR,
        "--manifest",
        path.join(BUILD_WORK_DIR, "patched-sos", "manifest.json"),
        // PyInstaller's run_pyinstaller.py wrapper expects boolean
        // flags matching its CLI, so map from our TARGETS table.
        "--console",
    ];

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

// Run ``stage_patched_sos.py`` before PyInstaller to copy non-writable
// ``.so`` files with ``DT_RUNPATH`` (e.g. ``libabsl_*.so.20260526``
// bundled by grpcio / tensorboard / pyarrow wheels on system Python
// installs) into a writable cache and ``patchelf`` them there. The
// cache is consumed by ``run_pyinstaller.py`` so PyInstaller bundles
// the patched copy instead of the root-owned original. Without this,
// ``staticx`` later aborts with ``staticx: Unsupported PyInstaller
// input ... DT_RUNPATH='$ORIGIN'`` even though our ``stripBadRpaths``
// pass correctly rewrote the same files when they were writable.
function stagePatchedSos(target) {
    if (target !== "linux") {
        // macOS / Windows onefiles do not go through staticx, so the
        // DT_RUNPATH audit never fires and we can skip the cache.
        return;
    }
    const cacheDir = path.join(BUILD_WORK_DIR, "patched-sos");
    const venvPython = path.join(PROJECT_ROOT, ".venv", "bin", "python3");
    const probePython = fs.existsSync(venvPython) ? venvPython : "python3";
    const args = [
        path.join(PROJECT_ROOT, "scripts", "stage_patched_sos.py"),
        "--python",
        probePython,
        "--cache-dir",
        cacheDir,
    ];
    console.log(`[build-backend] staging non-writable patched .so files: python3 ${args.join(" ")}`);
    const result = spawnSync("python3", args, {
        cwd: PROJECT_ROOT,
        stdio: "inherit",
        env: process.env,
    });
    if (result.error) {
        console.error(
            `[build-backend] failed to spawn stage_patched_sos.py: ${result.error.message}`,
        );
        process.exit(1);
    }
    if (result.status !== 0) {
        console.error(
            `[build-backend] stage_patched_sos.py exited with code ${result.status}`,
        );
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
    // Resolve which Python interpreter owns the ``.so`` files we care
    // about. PyInstaller will only bundle files that the active
    // Python can ``import``, so the rewrite pass should mirror that
    // scope. Two cases:
    //
    // 1. The project ships a local ``.venv`` (``${PROJECT_ROOT}/.venv``).
    //    Use it. The venv is hermetic and only contains project
    //    dependencies, so we never touch unrelated system directories
    //    (e.g. on Kali Linux, ``/usr/share/metasploit-framework`` is
    //    reachable through ``/usr/lib/python3/dist-packages`` symlinks
    //    and we should not be modifying those).
    //
    // 2. No project venv. Use whatever ``python3`` is on PATH but
    //    skip any site-packages root the current user can't write
    //    to. This protects root-owned system site-packages and avoids
    //    ``patchelf: Permission denied`` failures.
    //
    // In both cases, we also skip individual ``.so`` files that are
    // not writable (root-owned, read-only mounts, etc.) -- if we
    // can't rewrite them, no point in trying.
    const venvPython = path.join(PROJECT_ROOT, ".venv", "bin", "python3");
    let probePython = "python3";
    if (fs.existsSync(venvPython)) {
        probePython = venvPython;
    }
    const probe = spawnSync(
        probePython,
        [
            "-c",
            // Probe returns three kinds of directories in priority
            // order so we cover the active Python's import scope:
            //  1. ``site.getsitepackages()`` -- the active Python's
            //     system / venv site-packages directories (these are
            //     where wheels and ``pip install`` land by default).
            //  2. ``site.getusersitepackages()`` -- ``pip install --user``
            //     installs (typically under ``~/.local/lib/...``).
            //  3. ``sys.prefix`` is intentionally NOT included: on a
            //     venv it would point at ``.venv`` itself, which is
            //     not a package directory and would cause the walk to
            //     recurse into ``.venv/bin/`` (and on system Python
            //     it would point at ``/usr``). Use ``site.getsitepackages``
            //     only -- it already covers the real package roots.
            "import site, sys; print('\\n'.join(site.getsitepackages() + [site.getusersitepackages()]))",
        ],
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
    let skippedUnreadable = 0;
    let skippedUnwritable = 0;
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
                if (error.code === "EACCES" || error.code === "EPERM") {
                    skippedUnreadable += 1;
                    continue;
                }
                throw error;
            }
            for (const entry of entries) {
                const full = path.join(dir, entry.name);
                if (entry.isDirectory()) {
                    stack.push(full);
                    continue;
                }
                if (entry.isSymbolicLink()) {
                    // A few wheels ship as a directory symlink (e.g.
                    // ``cv2 -> opencv_python_headless`` on Fedora).
                    // Resolve the link to see whether the target is
                    // actually a directory we should walk into. We
                    // do NOT filter by resolved path here -- any
                    // target inside the active Python's package
                    // roots is in scope; the per-file ``W_OK`` and
                    // ``DT_RUNPATH`` checks below keep us from
                    // touching anything we shouldn't.
                    let targetStat;
                    try {
                        targetStat = fs.statSync(full);
                    } catch (error) {
                        // Broken symlink; skip silently.
                        continue;
                    }
                    if (targetStat.isDirectory()) {
                        stack.push(full);
                    }
                    continue;
                }
                if (!/\.so(\.\d+)*$/.test(entry.name)) continue;
                try {
                    fs.accessSync(full, fs.constants.W_OK);
                } catch (error) {
                    // Root-owned ``.so`` or read-only mount; nothing
                    // we can do. PyInstaller won't be able to bundle
                    // it anyway, so a silent skip is fine. This is
                    // the path that catches root-owned system
                    // extensions on Kali (e.g. ``pg_ext.so`` inside
                    // ``/usr/share/metasploit-framework/...``).
                    skippedUnwritable += 1;
                    continue;
                }
                if (rewriteSORpath(full, root)) {
                    touched += 1;
                }
            }
        }
    }
    if (skippedUnreadable > 0) {
        console.log(
            `[build-backend] skipped ${skippedUnreadable} unreadable site-packages ` +
            `directory(ies); the active Python (${probePython}) can reach but ` +
            `the build user cannot list them`,
        );
    }
    if (skippedUnwritable > 0) {
        console.log(
            `[build-backend] skipped ${skippedUnwritable} non-writable .so file(s); ` +
            `these are root-owned and not part of the build environment`,
        );
    }
    if (touched === 0) {
        console.log(
            `[build-backend] no DT_RUNPATH entries to rewrite in the active Python's ` +
            `site-packages (probe: ${probePython})`,
        );
    } else {
        console.log(
            `[build-backend] rewrote ${touched} .so file(s) to drop DT_RUNPATH entries`,
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

    // Decide what DT_RPATH value to write. Two cases:
    //
    // 1. The existing DT_RUNPATH is ``$ORIGIN``-relative (e.g. just
    //    ``$ORIGIN``, ``$ORIGIN/lib``, ``$ORIGIN/../foo``). In that
    //    case we preserve the value verbatim. The loader's behavior
    //    is identical whether the entry is ``DT_RUNPATH`` or
    //    ``DT_RPATH``; only the dynamic tag changes, and staticx is
    //    happy because it accepts ``$ORIGIN``-relative ``DT_RPATH``.
    //    This handles libraries like ``libabsl_*.so`` (Abseil, pulled
    //    in by gRPC / tensorboard / etc.) whose DT_RUNPATH points at
    //    their own directory for self-contained dependency lookup.
    //
    // 2. The existing DT_RUNPATH is absolute (e.g. scipy's
    //    ``cython_special.so`` with ``/opt/_internal/cpython-.../scipy_openblas32/lib``).
    //    An absolute path is meaningless on the target machine, so
    //    we redirect to the wheel's bundled ``<pkg>.libs`` directory
    //    via ``$ORIGIN``. We pick the closest ``<pkg>.libs`` sibling
    //    by walking up from the ``.so`` toward the site-packages root.
    let newRpath;
    if (dyn.runpath.startsWith("$ORIGIN")) {
        newRpath = dyn.runpath;
    } else {
        const libsSibling = findLibsSibling(soPath, siteRoot);
        if (!libsSibling) {
            console.warn(
                `[build-backend] skipping ${path.relative(PROJECT_ROOT, soPath)}: ` +
                `absolute DT_RUNPATH with no .libs sibling to redirect to`,
            );
            return false;
        }
        const rel = path.relative(path.dirname(soPath), libsSibling);
        newRpath = `$ORIGIN/${rel.split(path.sep).join("/")}`;
    }
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

// Set the binary's mode to ``0755`` (``rwxr-xr-x``) so deb/rpm
// packaging tools and direct installs land it with the standard
// permissions for a system executable. PyInstaller (and staticx
// on Linux) sometimes tighten the mode to ``0700`` or leave it at
// the build user's umask, which makes the resulting ``snitch``
// or ``snitch-extract`` unreadable to non-root users when packaged
// into ``/usr/lib/packetsnitch/`` and then symlinked or copied to
// ``/usr/bin/``. The Windows path is a no-op because ``fs.chmod``
// only honours the executable bit on Windows and we already gate
// this on non-Windows.
function chmodBinary(exeName) {
    if (process.platform === "win32") {
        return;
    }
    const outputPath = path.join(BACKEND_DIR, exeName);
    if (!fs.existsSync(outputPath)) {
        return;
    }
    fs.chmodSync(outputPath, 0o755);
    const stats = fs.statSync(outputPath);
    console.log(
        `[build-backend] chmod 0755 ${outputPath} (now ${(stats.mode & 0o777).toString(8)})`,
    );
}

function main() {
    // Consume ``--force`` from ``process.argv`` BEFORE we call
    // ``resolveTarget()`` so a stray ``--force`` in argv[2] doesn't
    // get mistaken for a target name (e.g. ``node build-backend.js
    // --force`` without a target should fall through to the platform
    // default, not error out with "Unknown target '--force'").
    const forceFlag = CACHE_HELPER.consumeForceFlag();
    const forceEnv = CACHE_HELPER.forceRequestedViaEnv();
    const force = forceFlag || forceEnv;

    const target = resolveTarget();
    const targetConfig = TARGETS[target];
    console.log(`[build-backend] target platform: ${target}`);
    if (forceFlag) {
        console.log("[build-backend] --force requested; ignoring cache");
    } else if (forceEnv) {
        console.log(
            "[build-backend] FORCE=1 / SNITCH_FORCE_BUILD=1 requested; ignoring cache",
        );
    }

    // Compute the cache key before doing any side-effectful work so a
    // cache hit can short-circuit cleanly. ``buildArgs()`` is pure
    // (reads TARGETS + ICON_PATH only), so we can call it here and
    // reuse the same flag list both for the cache key and the actual
    // ``spawnSync`` later. This way a change in ``--collect-binaries
    // scipy`` invalidates the cache without us having to thread that
    // flag separately.
    const plannedArgs = buildArgs(target);
    const venvPython = path.join(PROJECT_ROOT, ".venv", "bin", "python3");
    const probePython = fs.existsSync(venvPython) ? venvPython : "python3";
    const cacheKey = CACHE_HELPER.computeCacheKey({
        projectRoot: PROJECT_ROOT,
        sourceRoots: SOURCE_ROOTS,
        requirementsFiles: REQUIREMENTS_FILES,
        scriptFiles: SCRIPT_FILES,
        // ``plannedArgs`` is the actual ``run_pyinstaller.py``
        // invocation we'd hand to ``spawnSync``. Different targets
        // already differ in their entry script / collect-binaries
        // list; folding the whole array into the key means we never
        // miss an invalidation when those flags change. We truncate
        // at the entry-script position so we don't hash the absolute
        // path of the local checkout (which would invalidate the
        // cache the moment someone moves their repo).
        buildArgs: {
            target,
            args: plannedArgs.slice(0, plannedArgs.indexOf(ENTRY_SCRIPT)),
        },
        python: probePython,
        target,
    });
    const cacheKeyPath = path.join(BUILD_WORK_DIR, `${targetConfig.exeName}.cache-key`);
    const binaryPath = path.join(BACKEND_DIR, targetConfig.exeName);
    const decision = CACHE_HELPER.shouldRebuild({
        cacheKey,
        cacheKeyPath,
        binaryPath,
        force,
    });
    if (!decision.rebuild) {
        const stats = fs.statSync(binaryPath);
        console.log(
            `[build-backend] cache hit (key=${cacheKey.slice(0, 12)}...); ` +
            `skipping rebuild. existing binary at ${binaryPath} ` +
            `(${(stats.size / 1024 / 1024).toFixed(2)} MiB, mtime=${stats.mtime.toISOString()})`,
        );
        console.log("[build-backend] done.");
        return;
    }
    console.log(
        `[build-backend] cache miss (reason: ${decision.reason}; key=${cacheKey.slice(0, 12)}...); rebuilding`,
    );

    preflightCheck();
    applyProjectPatches();
    removeExistingBinary(targetConfig.exeName);

    stripBadRpaths(target);
    stagePatchedSos(target);

    const args = buildArgs(target);
    invokePyInstaller(args);
    rewrapWithStaticx(target);
    verifyOutput(targetConfig.exeName);
    chmodBinary(targetConfig.exeName);

    // Persist the cache key only after every step (PyInstaller +
    // staticx + chmod) succeeded. If any of them crashed, the next
    // invocation will re-run the full pipeline -- which is exactly
    // what we want.
    CACHE_HELPER.writeCacheKey(cacheKeyPath, cacheKey);
    console.log(`[build-backend] wrote cache key to ${cacheKeyPath}`);

    console.log(`[build-backend] done.`);
}

// Apply all project-local patches under ``patches/`` before doing
// anything else. The applier (``scripts/apply-patches.js``) is
// idempotent: re-running it on already-applied or upstream-fixed
// installs is a no-op with exit 0. Each patch is a unified diff
// with magic ``# cwd:`` / ``# python:`` directives at the top, so
// the applier can locate target files across venvs, node_modules,
// and other dynamic layouts without needing GNU ``patch`` on PATH
// (which makes this Windows-friendly).
function applyProjectPatches() {
    const applier = path.join(PROJECT_ROOT, "scripts", "apply-patches.js");
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
            `[build-backend] patch applier exited with code ${result.status}; ` +
            "see messages above for details",
        );
        process.exit(result.status || 1);
    }
}

main();
