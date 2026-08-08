// Shared incremental-build cache helper for the PacketSnitch PyInstaller
// build pipeline.
//
// ``scripts/build-backend.js`` and ``scripts/build-extractor.js`` both
// run PyInstaller (and, on Linux, staticx) to produce a onefile binary
// from ``src/backend/``. Each invocation is expensive (often 2-5
// minutes) because PyInstaller's ``Analysis`` step walks the full
// dependency graph and staticx re-wraps the result with bundled loader
// dependencies. If nothing about the backend code has changed since
// the previous build, all of that work is redundant.
//
// This module computes a deterministic cache key over every input that
// can affect the bundled binary:
//
//   1. The contents of every ``.py`` file under ``src/backend/`` (the
//      entry script plus every module the runtime imports).
//   2. The pinned dependency versions in the relevant
//      ``requirements*.txt`` file. Wheel contents change between
//      versions, so a bump must invalidate the cache.
//   3. The build scripts themselves (``run_pyinstaller.py``,
//      ``stage_patched_sos.py``, the calling ``build-*.js`` script).
//      A change to the spec-rendering template or the DT_RUNPATH
//      rewrite logic changes what PyInstaller produces.
//   4. The build arguments (target platform, ``--collect-binaries``
//      list, icon path). Different args produce different bundles.
//   5. The Python interpreter used for the build. Different interpreters
//      bundle different stdlib bytecode and different wheel binaries.
//
// The cache key is a single SHA-256 hex digest of all of the above. We
// store it in ``<workDir>/<binaryName>.cache-key`` next to the binary
// so each target (``snitch`` vs ``snitch-extract``) has its own
// independent cache.
//
// API:
//
//   const { computeCacheKey, shouldRebuild } = require("./build-cache");
//   const cacheKey = computeCacheKey({ ... });
//   if (shouldRebuild({ cacheKey, ... })) {
//       // full rebuild
//   } else {
//       console.log("[build] cache hit, skipping rebuild");
//       process.exit(0);
//   }
//
// Force-rebuild overrides (any one of these forces a rebuild even when
// the cache key matches):
//
//   - ``--force`` flag in ``process.argv`` (consumed by the calling
//     script via ``forceRequested()``).
//   - ``SNITCH_FORCE_BUILD=1`` environment variable.
//   - The existing binary is missing or empty (e.g. the user deleted
//     ``src/backend/snitch`` by hand).

"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

// Walk ``root`` recursively and emit every regular file's absolute
// path. Excludes ``__pycache__`` directories (compiled bytecode we
// neither write nor ship) and broken symlinks. Stable order: we
// ``sort()`` every directory listing so the resulting file list is
// deterministic across filesystems / platforms.
function listFilesRecursive(root) {
    const out = [];
    const stack = [root];
    while (stack.length) {
        const dir = stack.pop();
        let entries;
        try {
            entries = fs.readdirSync(dir, { withFileTypes: true });
        } catch (error) {
            if (error.code === "ENOENT") continue;
            // EACCES on a system site-packages subdir (unlikely under
            // src/backend/, but possible if a user mounts their repo
            // somewhere exotic) -- skip silently. The cache key will
            // still be deterministic for the files we *can* read.
            if (error.code === "EACCES" || error.code === "EPERM") continue;
            throw error;
        }
        entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
        for (const entry of entries) {
            const full = path.join(dir, entry.name);
            if (entry.isDirectory()) {
                if (entry.name === "__pycache__") continue;
                if (entry.name === ".git") continue;
                stack.push(full);
                continue;
            }
            if (entry.isSymbolicLink()) {
                // Follow directory symlinks (e.g. ``cv2`` -> another
                // package on Fedora). For files, just take the link
                // itself; the linker doesn't dereference Python module
                // symlinks in practice.
                let targetStat;
                try {
                    targetStat = fs.statSync(full);
                } catch (error) {
                    continue;
                }
                if (targetStat.isDirectory()) {
                    stack.push(full);
                }
                continue;
            }
            if (entry.isFile()) {
                out.push(full);
            }
        }
    }
    out.sort();
    return out;
}

// Hash a list of files into a single SHA-256 digest. We stream each
// file through ``createHash().update()`` rather than reading them into
// memory so very large source trees (we're at ~40 .py files today,
// but the decoders/ directory could grow) don't blow up Node's heap.
function hashFiles(files) {
    const hash = crypto.createHash("sha256");
    for (const file of files) {
        // Include the path so two files with identical contents but
        // different names still produce different hashes.
        hash.update(file);
        hash.update("\0");
        let fd;
        try {
            fd = fs.openSync(file, "r");
        } catch (error) {
            // Skip unreadable files. The build will fail loudly later
            // if the missing file actually mattered; the cache key
            // stays stable across runs that hit the same ENOENT.
            continue;
        }
        try {
            const stream = fs.createReadStream(file, { fd, highWaterMark: 64 * 1024 });
            // ``stream`` is synchronous enough for our purposes --
            // hash.update() is buffered -- but we wait for ``end`` to
            // be safe on slow filesystems.
            let buf = Buffer.alloc(64 * 1024);
            let pos = 0;
            let bytesRead;
            // Node's sync fs.read on the fd is the simplest way to
            // hash a file deterministically without juggling stream
            // events. Files in ``src/backend/`` are tiny (<200 KB)
            // so this is cheap.
            const stat = fs.fstatSync(fd);
            const total = stat.size;
            while (pos < total) {
                bytesRead = fs.readSync(fd, buf, 0, buf.length, pos);
                if (bytesRead <= 0) break;
                hash.update(buf.slice(0, bytesRead));
                pos += bytesRead;
            }
        } finally {
            fs.closeSync(fd);
        }
    }
    return hash;
}

// ``computeCacheKey({ projectRoot, sourceRoots, requirementsFiles,
// scriptFiles, buildArgs, python })`` -> hex SHA-256 string.
//
// - ``sourceRoots``: array of directories to walk for backend source
//   (``[src/backend]`` for the main binary).
// - ``requirementsFiles``: array of ``requirements*.txt`` paths whose
//   pinned versions matter (deps change between releases).
// - ``scriptFiles``: array of build-pipeline scripts whose contents
//   affect the output (``run_pyinstaller.py``, ``stage_patched_sos.py``,
//   the calling ``build-*.js``).
// - ``buildArgs``: anything else the caller wants to fold in. We JSON-
//   stringify a stable representation so order matters but is
//   reproducible.
// - ``python``: absolute path to the Python interpreter used for the
//   build. Different interpreters (system vs ``.venv``) bundle
//   different stdlib bytecode, so this is part of the key.
//
// Returns a hex SHA-256 digest of the form
// ``"<sha256>"``. The leading component marker (a short prefix
// identifying which input it belongs to) is folded into the digest so
// we don't have to keep the prefix table separately when comparing
// two keys.
function computeCacheKey({
    projectRoot,
    sourceRoots = [],
    requirementsFiles = [],
    scriptFiles = [],
    buildArgs = null,
    python = null,
    target = null,
}) {
    const hash = crypto.createHash("sha256");

    // 1. Source roots: hash every file under each root, in order.
    for (const root of sourceRoots) {
        const abs = path.resolve(projectRoot, root);
        hash.update(`source-root:${abs}\0`);
        if (!fs.existsSync(abs)) continue;
        const files = listFilesRecursive(abs);
        hash.update(`source-files:${files.length}\0`);
        hash.update(hashFiles(files).digest());
    }

    // 2. Requirements files: read the pinned versions directly. We
    // include the full file contents because line ordering / comments
    // can shift between regenerations and we'd rather over-invalidate
    // than under-invalidate.
    for (const reqPath of requirementsFiles) {
        const abs = path.resolve(projectRoot, reqPath);
        hash.update(`requirements:${abs}\0`);
        try {
            hash.update(fs.readFileSync(abs));
        } catch (error) {
            // Missing requirements file: still hash a marker so the
            // cache key changes if the file appears later.
            hash.update(`missing:${error.code || "ERR"}`);
        }
        hash.update("\0");
    }

    // 3. Build pipeline scripts: same as requirements. If the operator
    // edits ``run_pyinstaller.py`` to add a new ``--collect-binaries``
    // flag, the cache must invalidate.
    for (const scriptPath of scriptFiles) {
        const abs = path.resolve(projectRoot, scriptPath);
        hash.update(`script:${abs}\0`);
        try {
            hash.update(fs.readFileSync(abs));
        } catch (error) {
            hash.update(`missing:${error.code || "ERR"}`);
        }
        hash.update("\0");
    }

    // 4. Build args (target, collect-binaries list, icon path, ...):
    // stringify with stable key ordering so two equivalent builds
    // produce the same key regardless of object iteration order.
    if (buildArgs) {
        hash.update("build-args:");
        hash.update(stableStringify(buildArgs));
        hash.update("\0");
    }

    // 5. Python interpreter: include the resolved path. Different
    // venvs / system Pythons have different stdlib bytecode, which
    // PyInstaller bundles verbatim.
    if (python) {
        hash.update("python:");
        try {
            hash.update(fs.realpathSync(python));
        } catch (error) {
            hash.update(python);
        }
        hash.update("\0");
    }

    // 6. Target platform (linux/macos/windows): macOS / Windows
    // bundles are platform-specific by construction; Linux bundles
    // get staticx re-wrapped with Linux loader deps.
    if (target) {
        hash.update(`target:${target}\0`);
    }

    return hash.digest("hex");
}

// ``JSON.stringify`` with sorted keys, recursively. We avoid pulling
// in a dependency for this -- ``JSON.stringify`` already handles
// strings, numbers, booleans, null, arrays, and plain objects, which
// is everything we feed it.
function stableStringify(value) {
    if (value === null || typeof value !== "object") {
        return JSON.stringify(value);
    }
    if (Array.isArray(value)) {
        return "[" + value.map(stableStringify).join(",") + "]";
    }
    const keys = Object.keys(value).sort();
    const parts = [];
    for (const key of keys) {
        parts.push(JSON.stringify(key) + ":" + stableStringify(value[key]));
    }
    return "{" + parts.join(",") + "}";
}

// Returns true if a CLI flag like ``--force`` is present anywhere in
// ``process.argv`` (excluding ``node`` and the script path). Removes
// the flag from ``process.argv`` so downstream tooling doesn't see
// it twice.
function consumeForceFlag(argv = process.argv) {
    const idx = argv.indexOf("--force");
    if (idx === -1) return false;
    argv.splice(idx, 1);
    return true;
}

// Returns true if any of the env-var force flags are set. We accept a
// handful of common conventions because users have muscle memory for
// each:
//
//   - ``SNITCH_FORCE_BUILD=1`` -- our project-specific override; what
//     CI / docs recommend.
//   - ``FORCE=1`` -- the standard GNU make convention, often set by
//     wrappers that re-run make with ``make FORCE=1``.
//
// Both must be exactly ``"1"``; any other value (e.g. ``"true"``,
// ``"yes"``) is ignored so an unset variable in the environment
// doesn't accidentally force a rebuild.
function forceRequestedViaEnv(env = process.env) {
    return env.SNITCH_FORCE_BUILD === "1" || env.FORCE === "1";
}

// Decide whether the caller should perform a full rebuild. Returns
// ``{ rebuild, reason, cacheKey }`` where ``reason`` is a short
// human-readable string suitable for logging.
//
// ``{ cacheKey, cacheKeyPath, binaryPath, force }``:
//
//   - ``cacheKey``: hex digest returned by ``computeCacheKey``.
//   - ``cacheKeyPath``: where the previous key is stored on disk
//     (``<workDir>/<binaryName>.cache-key``).
//   - ``binaryPath``: path to the existing binary; an empty or
//     missing binary forces a rebuild regardless of the cache key.
//   - ``force``: ``true`` if the user asked for a force-rebuild via
//     ``--force`` or the env vars above.
function shouldRebuild({
    cacheKey,
    cacheKeyPath,
    binaryPath,
    force = false,
}) {
    if (force) {
        return { rebuild: true, reason: "force flag set", cacheKey };
    }
    // Missing or empty binary -> must rebuild. This catches the case
    // where the operator deleted ``src/backend/snitch`` by hand or
    // where the previous build crashed mid-write and left a zero-byte
    // stub behind.
    if (!binaryPath || !fs.existsSync(binaryPath)) {
        return { rebuild: true, reason: "binary missing", cacheKey };
    }
    let stat;
    try {
        stat = fs.statSync(binaryPath);
    } catch (error) {
        return { rebuild: true, reason: `binary unreadable: ${error.code}`, cacheKey };
    }
    if (stat.size === 0) {
        return { rebuild: true, reason: "binary empty", cacheKey };
    }
    if (!fs.existsSync(cacheKeyPath)) {
        return { rebuild: true, reason: "no previous cache key", cacheKey };
    }
    let previous;
    try {
        previous = fs.readFileSync(cacheKeyPath, "utf8").trim();
    } catch (error) {
        return { rebuild: true, reason: `cache key unreadable: ${error.code}`, cacheKey };
    }
    if (previous !== cacheKey) {
        return { rebuild: true, reason: "cache key changed", cacheKey };
    }
    return { rebuild: false, reason: "cache hit", cacheKey };
}

// Persist ``cacheKey`` to ``cacheKeyPath``. Called after a successful
// build so the next invocation can short-circuit.
function writeCacheKey(cacheKeyPath, cacheKey) {
    fs.mkdirSync(path.dirname(cacheKeyPath), { recursive: true });
    fs.writeFileSync(cacheKeyPath, cacheKey + "\n");
}

module.exports = {
    computeCacheKey,
    shouldRebuild,
    writeCacheKey,
    consumeForceFlag,
    forceRequestedViaEnv,
    // Exported for tests / debugging.
    listFilesRecursive,
    stableStringify,
};
