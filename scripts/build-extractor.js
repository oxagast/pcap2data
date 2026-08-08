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
// On Linux, after PyInstaller finishes, the script additionally runs
// ``staticx`` to re-wrap the onefile binary with its dynamically-linked
// loader dependencies statically bundled. This produces a portable
// ``snitch-extract`` that can be run on other Linux machines without
// matching glibc / libstdc++ / libpython versions that the build host
// had. ``staticx`` only supports Linux 64-bit, so macOS and Windows
// builds skip the re-wrap step and ship the plain PyInstaller binary.
//
// Usage:
//   node scripts/build-extractor.js           # build for the current OS
//   node scripts/build-extractor.js linux     # force a target
//   node scripts/build-extractor.js macos
//   node scripts/build-extractor.js windows
//
// The script writes the final binary directly to
// ``src/backend/snitch-extract[.exe]`` so the existing
// forge.config.js extraResource entries and ``src/main.js`` lookup
// logic continue to work unchanged.

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
// Python environment so PyInstaller can import them.
//
// We prefer the project's ``.venv`` if one exists -- pip on
// externally-managed system Pythons (PEP 668, e.g. Kali/Debian) will
// refuse to install without ``--break-system-packages``, which is
// risky and not portable. The venv is hermetic and already holds
// every dependency the build needs. If no venv is present we fall
// back to the system ``python3`` and pass ``--break-system-packages``
// so the build still works on a fresh Kali box where the user has
// not set up a venv.
function installRequirements() {
    if (!fs.existsSync(REQUIREMENTS_FILE)) {
        console.error(
            `[build-extractor] requirements file not found at ${REQUIREMENTS_FILE}`,
        );
        process.exit(1);
    }
    const venvPython = path.join(PROJECT_ROOT, ".venv", "bin", "python3");
    const useVenv = process.platform !== "win32" && fs.existsSync(venvPython);
    const python = useVenv ? venvPython : "python3";
    const pipArgs = ["-m", "pip", "install", "--requirement", REQUIREMENTS_FILE];
    if (!useVenv) {
        pipArgs.push("--break-system-packages");
    }
    console.log(
        `[build-extractor] installing Python deps from ${REQUIREMENTS_FILE} using ${python}`,
    );
    const result = spawnSync(
        python,
        pipArgs,
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
    // We invoke ``scripts/run_pyinstaller.py`` directly instead of
    // ``python3 -m PyInstaller`` because the wrapper consumes the
    // patched-.so cache produced by ``stage_patched_sos.py`` and
    // substitutes ``a.binaries[].src_name`` between Analysis and EXE.
    // See the matching comment in ``build-backend.js`` for the full
    // rationale (libabsl DT_RUNPATH='$ORIGIN' from system wheels).
    return [
        path.join(PROJECT_ROOT, "scripts", "run_pyinstaller.py"),
        "--name",
        targetConfig.exeName,
        "--distpath",
        BACKEND_DIR,
        "--workpath",
        BUILD_WORK_DIR,
        "--manifest",
        path.join(BUILD_WORK_DIR, "patched-sos", "manifest.json"),
        // Console mode preserves stdout/stderr; the Node side reads
        // both. Both Windows and *nix want this.
        "--console",
        // Linux-only: collect scipy/numpy compiled extensions so the
        // PyInstaller onefile does not carry DT_RUNPATH entries that
        // point at the build host's ``/opt/_internal/cpython-...``
        // site-packages. ``staticx`` refuses to re-wrap binaries
        // whose loader dependencies reference paths that won't exist
        // on the target machine. The ``snitch-extract`` helper does
        // not actually import scipy/numpy at runtime, but PyInstaller
        // still walks the full dependency graph for hidden imports
        // and pulls these in transitively; forcing them to be
        // collected with no DT_RUNPATH keeps the staticx wrap clean.
        ...(target === "linux"
            ? [
                "--collect-binaries", "scipy",
                "--collect-binaries", "scipy_openblas32",
                "--collect-binaries", "numpy",
                "--collect-data", "scipy",
            ]
            : []),
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
    console.log(`[build-extractor] staging non-writable patched .so files: python3 ${args.join(" ")}`);
    const result = spawnSync("python3", args, {
        cwd: PROJECT_ROOT,
        stdio: "inherit",
        env: process.env,
    });
    if (result.error) {
        console.error(
            `[build-extractor] failed to spawn stage_patched_sos.py: ${result.error.message}`,
        );
        process.exit(1);
    }
    if (result.status !== 0) {
        console.error(
            `[build-extractor] stage_patched_sos.py exited with code ${result.status}`,
        );
        process.exit(result.status || 1);
    }
}

// staticx re-wrap for the snitch-extract binary. See the matching
// ``rewrapWithStaticx`` block in scripts/build-backend.js for the
// full rationale; in short: staticx only works on Linux 64-bit, so we
// only invoke it when the active target is Linux and otherwise leave
// the plain PyInstaller binary in place.
function rewrapWithStaticx(target) {
    if (target !== "linux") {
        return;
    }
    const outputPath = path.join(BACKEND_DIR, "snitch-extract");
    const pyinstallerPath = path.join(BACKEND_DIR, ".snitch-extract.pyinstaller");
    if (!fs.existsSync(outputPath)) {
        console.error(
            `[build-extractor] expected PyInstaller output at ${outputPath} before staticx wrap`,
        );
        process.exit(1);
    }
    try {
        fs.renameSync(outputPath, pyinstallerPath);
    } catch (error) {
        console.error(
            `[build-extractor] failed to stage PyInstaller output for staticx: ${error.message}`,
        );
        process.exit(1);
    }
    console.log(
        `[build-extractor] re-wrapping with staticx: ${pyinstallerPath} -> ${outputPath}`,
    );
    const result = spawnSync(
        "staticx",
        ["--strip", pyinstallerPath, outputPath],
        {
            cwd: PROJECT_ROOT,
            stdio: "inherit",
            env: process.env,
        },
    );
    try {
        fs.unlinkSync(pyinstallerPath);
    } catch (error) {
        if (error && error.code !== "ENOENT") {
            console.warn(
                `[build-extractor] could not remove staged PyInstaller binary ${pyinstallerPath}: ${error.message}`,
            );
        }
    }
    if (result.error) {
        if (result.error.code === "ENOENT") {
            console.error(
                `[build-extractor] staticx was not found on PATH. Install it with 'pip install staticx' (or 'pip3 install -r src/backend/requirements-extract.txt') and re-run.`,
            );
        } else {
            console.error(`[build-extractor] failed to spawn staticx: ${result.error.message}`);
        }
        process.exit(1);
    }
    if (result.status !== 0) {
        console.error(`[build-extractor] staticx exited with code ${result.status}`);
        process.exit(result.status || 1);
    }
}

// Manylinux wheels bake the build host's absolute prefix into
// ``DT_RUNPATH`` on a handful of compiled ``.so`` files (notably
// ``scipy/special/cython_special.cpython-314-x86_64-linux-gnu.so``,
// which carries ``DT_RUNPATH='/opt/_internal/cpython-3.14.0rc1/.../scipy_openblas32/lib'``).
// ``staticx`` refuses to re-wrap a PyInstaller onefile whose embedded
// archive contains any ``DT_RUNPATH`` entry (see staticx #188); the
// build dies during staticx's audit phase.
//
// We rewrite every ``.so`` with a ``DT_RUNPATH`` to use a
// ``$ORIGIN``-relative ``DT_RPATH`` (using ``patchelf --force-rpath``)
// pointing at the wheel's bundled ``.libs`` sibling directory. After
// this rewrite, the loader can still resolve OpenBLAS / libgfortran
// from the wheel's bundled ``scipy.libs`` (or ``numpy.libs``)
// directory at runtime. ``DT_RPATH`` with a ``$ORIGIN``-relative
// value is what staticx expects; ``DT_RUNPATH`` is forbidden outright
// regardless of whether the path is absolute or relative.
//
// Linux-only because the ``DT_RUNPATH`` problem is Linux/manylinux
// only; macOS uses ``LC_LOAD_DYLIB`` and Windows uses import tables.
// ``patchelf`` is also Linux-only, so the helper short-circuits on
// other targets. ``snitch-extract`` does not import scipy/numpy at
// runtime, but PyInstaller's hidden-import walk can still drag them
// in from the build environment; this rewrite keeps staticx happy in
// that case. If no offending ``.so`` files are present in the
// environment, the helper is a no-op.
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
            `[build-extractor] could not resolve site-packages to scan for bad DT_RUNPATH entries: ` +
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
            `[build-extractor] skipped ${skippedUnreadable} unreadable site-packages ` +
            `directory(ies); the active Python (${probePython}) can reach but ` +
            `the build user cannot list them`,
        );
    }
    if (skippedUnwritable > 0) {
        console.log(
            `[build-extractor] skipped ${skippedUnwritable} non-writable .so file(s); ` +
            `these are root-owned and not part of the build environment`,
        );
    }
    if (touched === 0) {
        console.log(
            `[build-extractor] no DT_RUNPATH entries to rewrite in the active Python's ` +
            `site-packages (probe: ${probePython})`,
        );
    } else {
        console.log(
            `[build-extractor] rewrote ${touched} .so file(s) to drop DT_RUNPATH entries`,
        );
    }
}

// Parses ``readelf -d`` output for ``DT_RUNPATH`` / ``DT_RPATH``
// entries. Returns ``{ runpath, rpath }`` (each possibly null).
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
        const runMatch = line.match(/\(RUNPATH\).*?:\s*\[([^\]]*)\]/);
        if (runMatch) runpath = runMatch[1];
        const rpathMatch = line.match(/\(RPATH\).*?:\s*\[([^\]]*)\]/);
        if (rpathMatch) rpath = rpathMatch[1];
    }
    return { runpath, rpath };
}

// Rewrites ``soPath`` to drop its absolute ``DT_RUNPATH`` and replace
// it with a ``$ORIGIN``-relative ``RPATH`` pointing at the wheel's
// ``.libs`` sibling directory. Returns true if a rewrite was applied.
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
                `[build-extractor] skipping ${path.relative(PROJECT_ROOT, soPath)}: ` +
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
            `[build-extractor] patchelf --remove-rpath failed on ${soPath}; ` +
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
            `[build-extractor] patchelf --force-rpath --set-rpath ${newRpath} failed on ${soPath}`,
        );
        process.exit(setrp.status || 1);
    }
    console.log(
        `[build-extractor]   ${path.relative(PROJECT_ROOT, soPath)}: DT_RUNPATH=${dyn.runpath} -> RPATH=${newRpath}`,
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
            `[build-extractor] expected binary was not produced at ${outputPath}`,
        );
        process.exit(1);
    }
    const stats = fs.statSync(outputPath);
    console.log(
        `[build-extractor] built ${outputPath} (${(stats.size / 1024 / 1024).toFixed(2)} MiB)`,
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
        `[build-extractor] chmod 0755 ${outputPath} (now ${(stats.mode & 0o777).toString(8)})`,
    );
}

function main() {
    const target = resolveTarget();
    const targetConfig = TARGETS[target];
    console.log(`[build-extractor] target platform: ${target}`);

    preflightCheck();
    applyProjectPatches();
    installRequirements();
    removeExistingBinary(targetConfig.exeName);

    stripBadRpaths(target);
    stagePatchedSos(target);

    const args = buildArgs(target);
    invokePyInstaller(args);
    rewrapWithStaticx(target);
    verifyOutput(targetConfig.exeName);
    chmodBinary(targetConfig.exeName);

    console.log(`[build-extractor] done.`);
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
            `[build-extractor] failed to spawn ${applier}: ${result.error.message}`,
        );
        process.exit(1);
    }
    if (result.status !== 0) {
        console.error(
            `[build-extractor] patch applier exited with code ${result.status}; ` +
            "see messages above for details",
        );
        process.exit(result.status || 1);
    }
}

main();
