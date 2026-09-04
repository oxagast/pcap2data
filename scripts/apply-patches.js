#!/usr/bin/env node
// Cross-platform idempotent applier for unified-diff patches under
// ``patches/``. Designed to work on Linux, macOS, and Windows without
// requiring GNU ``patch`` on PATH.
//
// Why this exists
// ---------------
// 1. GNU ``patch`` is not available on Windows by default, so a
//    ``patch -Np0`` step in ``npm run patch`` would break Windows
//    builds even though Windows builds don't actually need the rpm
//    spec patch (it's only used by the Linux maker).
// 2. GNU ``patch`` returns exit code 1 when a hunk is already
//    applied, which trips up idempotent re-runs of ``npm run patch``.
// 3. The staticx workaround lives in a Python package whose install
//    path is dynamic (system Python, venv, .venv, etc.); GNU patch's
//    ``+++`` path resolution is fragile across those layouts.
//
// What it does
// ------------
// Walks every ``patches/*.patch`` file, parses the unified diff, and
// applies each hunk to the target file. Each patch declares its
// working directory via a ``# cwd:`` magic comment in its first 5
// lines (see below). For patches that need a dynamic cwd (e.g. the
// staticx one, which lives in whatever site-packages the active
// interpreter exposes), the cwd can be a literal ``python:<expr>``
// directive that the applier resolves by running ``python3 -c``.
//
// Idempotency:
//   * If a hunk's ``pre`` (lines starting with '-') matches the file
//     at the expected offset, apply the patch.
//   * If a hunk's ``post`` (lines starting with '+') matches instead,
//     the patch is already applied; skip with exit 0.
//   * If neither matches, treat the patch as stale or out-of-date and
//     fail the build so the operator regenerates it.
//
// Patch directives
// ----------------
// Recognized magic comments at the top of each patch file:
//
//     # cwd: <path>           cwd for patch application. Path may be
//                             absolute, or relative to the project root.
//                             May use ``${VAR}`` for environment
//                             substitution. Default: project root.
//     # target: <path>        The file to patch, relative to cwd.
//                             Default: the ``+++`` path from the
//                             first hunk, with ``-p<N>`` stripping.
//     # strip: <N>            Number of leading components to strip
//                             from ``+++`` paths when deriving the
//                             target file. Default: 0.
//     # python: <expr>        Resolve cwd by running ``python3 -c``
//                             with this expression; the last line of
//                             stdout is used as the cwd path. Skipped
//                             if the interpreter is not available or
//                             staticx is not importable. Mutually
//                             exclusive with ``# cwd:``.
//     # require-import: <m>   (Used with ``# python:``.) Only attempt
//                             to resolve cwd if this module is
//                             importable; otherwise treat as no-op.
//
// Both directives are inert comments (lines starting with ``#``), so
// the file is still a valid unified diff that GNU ``patch`` could
// apply if anyone runs it manually.

"use strict";

const fs = require("fs");
const path = require("path");

const PROJECT_ROOT = path.resolve(__dirname, "..");
const PATCHES_DIR = path.join(PROJECT_ROOT, "patches");

// ---------------------------------------------------------------------------
// Unified-diff parser
// ---------------------------------------------------------------------------

/**
 * Parse a unified-diff text into an array of hunks. Each hunk has
 * { startOld, lenOld, startNew, lenNew, body } where ``body`` is an
 * array of strings with leading ``+``/``-``/`` `` markers preserved.
 *
 * Throws on malformed input.
 */
function parseUnifiedDiff(text) {
    const lines = text.split(/\r?\n/);
    const hunks = [];
    let i = 0;

    // Skip preamble: everything before the first "@@" line. The
    // preamble may contain ``# cwd:`` directives that the caller
    // will have already extracted; we still need to walk past them.
    while (i < lines.length && !lines[i].startsWith("@@")) i++;

    while (i < lines.length) {
        const header = lines[i];
        const m = header.match(
            /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/,
        );
        if (!m) {
            throw new Error(
                `malformed hunk header at line ${i + 1}: ${JSON.stringify(header)}`,
            );
        }
        const startOld = parseInt(m[1], 10);
        const lenOld = m[2] != null ? parseInt(m[2], 10) : 1;
        const startNew = m[3] != null ? parseInt(m[3], 10) : 1;
        const lenNew = m[4] != null ? parseInt(m[4], 10) : 1;
        i++;

        const body = [];
        let consumedOld = 0;
        let consumedNew = 0;
        while (i < lines.length) {
            const line = lines[i];
            // End of this hunk: next "@@" header or end of input.
            if (line.startsWith("@@")) break;
            if (line.startsWith("---") || line.startsWith("+++")) {
                // File header for the next hunk; treat as end of this one.
                break;
            }
            if (line === "") {
                // A blank line that isn't marked with `` `` is technically
                // ambiguous in unified diffs. Most generators emit ``\n``
                // (no space) as a blank context line; we accept it as such.
                body.push(" ");
                consumedOld += 1;
                consumedNew += 1;
                i++;
                continue;
            }
            const marker = line[0];
            if (marker === "+") {
                body.push(line);
                consumedNew += 1;
            } else if (marker === "-") {
                body.push(line);
                consumedOld += 1;
            } else if (marker === " ") {
                body.push(line);
                consumedOld += 1;
                consumedNew += 1;
            } else if (line.startsWith("\\ No newline")) {
                // "No newline at end of file" marker; ignore for line counting.
                body.push(line);
            } else {
                throw new Error(
                    `unexpected hunk body line at offset ${i}: ${JSON.stringify(line)}`,
                );
            }
            i++;
        }

        // Sanity-check that the body actually contains the number of
        // old/new lines the header claimed. This catches truncated
        // patches early. Note: some patches in the wild have hunk
        // headers whose line counts are off by one because the
        // generator miscounted blank lines; GNU patch tolerates
        // these with "fuzz". We don't enforce exact counts -- we
        // only fail if the body is genuinely empty or has zero of
        // either old or new lines, which would indicate a
        // catastrophic parse failure.
        if (
            consumedOld === 0 ||
            consumedNew === 0
        ) {
            throw new Error(
                `hunk header claimed ${lenOld} old / ${lenNew} new lines ` +
                `but body has ${consumedOld} / ${consumedNew}`,
            );
        }

        hunks.push({ startOld, lenOld, startNew, lenNew, body });
    }

    return hunks;
}

/**
 * Reduce a hunk body to the list of lines that should appear in the
 * "old" (pre-patch) version of the file. These are the ``-`` and `` ``
 * lines with their markers stripped.
 */
function hunkOldLines(hunk) {
    const out = [];
    for (const line of hunk.body) {
        if (line.startsWith("+")) continue;
        if (line.startsWith("\\")) continue; // "\ No newline" marker
        // Strip the leading marker char (always one char: '-', ' ',
        // or '\\' for the "No newline" line which we already filtered).
        out.push(line.slice(1));
    }
    return out;
}

/**
 * Reduce a hunk body to the "new" (post-patch) lines.
 */
function hunkNewLines(hunk) {
    const out = [];
    for (const line of hunk.body) {
        if (line.startsWith("+")) {
            out.push(line.slice(1));
        } else if (line.startsWith(" ")) {
            out.push(line.slice(1));
        }
        // "-": drop; "\\": ignore.
    }
    return out;
}

/**
 * Find the first index ``i`` in ``haystack`` such that
 * ``haystack.slice(i, i + needle.length) === needle``. If
 * ``preferredStart`` is in range, prefer that offset (this matches
 * GNU patch's behavior of honoring the @@ header's line number when
 * it works, only falling back to a search otherwise).
 */
function findMatch(haystack, needle, preferredStart) {
    if (needle.length === 0) {
        return preferredStart >= 0 && preferredStart <= haystack.length
            ? preferredStart
            : 0;
    }
    const tryAt = (i) =>
        i >= 0 &&
        i + needle.length <= haystack.length &&
        haystack
            .slice(i, i + needle.length)
            .every((line, k) => line === needle[k]);
    if (tryAt(preferredStart)) return preferredStart;
    // Linear search fallback. Most patches have very few hunks and
    // small context windows; this is more than fast enough.
    for (let i = 0; i <= haystack.length - needle.length; i++) {
        if (tryAt(i)) return i;
    }
    return -1;
}

/**
 * Apply a parsed hunk to ``fileText``. Returns one of:
 *   * { status: "applied",     newText } - hunk was applied
 *   * { status: "already",     newText } - hunk was already applied
 *   * { status: "conflict",    newText, detail } - patch cannot apply
 */
function applyHunk(hunk, fileText) {
    const fileLines = fileText.split(/\r?\n/);
    const oldLines = hunkOldLines(hunk);
    const newLines = hunkNewLines(hunk);

    // 1-indexed -> 0-indexed
    const preferredOld = hunk.startOld - 1;
    const preferredNew = hunk.startNew - 1;

    const oldIdx = findMatch(fileLines, oldLines, preferredOld);
    if (oldIdx >= 0) {
        const before = fileLines.slice(0, oldIdx);
        const after = fileLines.slice(oldIdx + oldLines.length);
        return {
            status: "applied",
            newText: before.concat(newLines, after).join("\n"),
        };
    }

    const newIdx = findMatch(fileLines, newLines, preferredNew);
    if (newIdx >= 0) {
        return { status: "already", newText: fileText };
    }

    return {
        status: "conflict",
        newText: fileText,
        detail:
            `hunk @@ -${hunk.startOld},${hunk.lenOld} ` +
            `+${hunk.startNew},${hunk.lenNew} @@ did not match either the ` +
            `pre-patch or post-patch lines; the file's contents have drifted ` +
            `from what the patch was generated against`,
    };
}

// ---------------------------------------------------------------------------
// Patch directive parsing
// ---------------------------------------------------------------------------

/**
 * Read magic ``# key: value`` directives from the preamble of a
 * patch file. Returns both the directives map and the cleaned diff
 * text (with the directive lines stripped) so we can hand the diff
 * to the parser without the preamble confusing it.
 */
function extractDirectives(text) {
    const directives = {};
    const cleaned = [];
    const lines = text.split(/\r?\n/);
    let sawHunkHeader = false;
    for (const line of lines) {
        if (!sawHunkHeader && line.startsWith("@@")) {
            sawHunkHeader = true;
        }
        if (
            !sawHunkHeader &&
            (line.startsWith("# cwd:") ||
                line.startsWith("# target:") ||
                line.startsWith("# strip:") ||
                line.startsWith("# python:") ||
                line.startsWith("# require-import:"))
        ) {
            const idx = line.indexOf(":");
            const key = line.slice(1, idx).trim();
            const value = line.slice(idx + 1).trim();
            directives[key] = value;
            continue;
        }
        cleaned.push(line);
    }
    return { directives, cleanedText: cleaned.join("\n") };
}

/**
 * Substitute ``${VAR}`` references in a directive value using the
 * current ``process.env``. Missing variables raise an explicit error
 * so the operator notices instead of getting a silent path bug.
 */
function substituteEnv(value) {
    return value.replace(/\$\{([^}]+)\}/g, (_, name) => {
        if (!(name in process.env)) {
            throw new Error(
                `patch directive references undefined environment variable: ${name}`,
            );
        }
        return process.env[name];
    });
}

// ---------------------------------------------------------------------------
// Patch application
// ---------------------------------------------------------------------------

/**
 * Resolve the working directory for a patch. Honors ``# python:``
 * directives by running the active Python interpreter (if any) and
 * asking it where a module lives. Honors ``# require-import:`` by
 * skipping the patch entirely when the named module is missing.
 *
 * Returns ``null`` if the patch should be skipped (no-op); throws if
 * the directive is malformed; returns the resolved absolute path
 * otherwise.
 */
function resolvePatchCwd(directives) {
    const pythonExpr = directives.python;
    const requireImport = directives["require-import"];

    if (pythonExpr) {
        // Try to find a Python interpreter. ``python3`` is the modern
        // default; on Windows the launcher alias ``py`` is also common.
        // The probe is a no-op if no interpreter is on PATH; we don't
        // want a missing Python to fail the build on, e.g., Windows
        // hosts that only build the GUI frontend.
        const interpreters = ["python3", "python", "py"];
        let probe = null;
        // Build the prelude: import any modules the patch directive
        // says it needs (``require-import``) plus ``os`` (most
        // expressions use ``os.path.dirname(...)``).
        const preludeParts = ["import os"];
        if (requireImport) {
            preludeParts.push(`import ${requireImport}`);
        }
        const prelude = preludeParts.join("; ");
        for (const interp of interpreters) {
            const result = require("child_process").spawnSync(
                interp,
                ["-c", `${prelude}; print(${pythonExpr})`],
                {
                    cwd: PROJECT_ROOT,
                    stdio: ["ignore", "pipe", "pipe"],
                    env: process.env,
                },
            );
            if (result.error && result.error.code === "ENOENT") {
                continue;
            }
            if (result.status === 0) {
                probe = result;
                break;
            }
            // Interpreter ran but raised (e.g. ModuleNotFoundError).
            // We can't tell from exit code alone whether the failure
            // was "no such module" (patch is no-op) or "syntax error"
            // (build should fail). Be conservative: treat non-zero
            // exit as "interpreter exists but module missing" and
            // skip silently. The patch's whole purpose is to handle
            // the missing module case.
            if (
                requireImport &&
                result.stderr &&
                /ModuleNotFoundError|ImportError/.test(result.stderr.toString())
            ) {
                return null;
            }
            // Some other failure; record the probe and fall through.
            probe = result;
            break;
        }
        if (!probe) {
            // No Python interpreter on PATH at all. Treat as a no-op
            // so Windows GUI builds (which don't need this patch)
            // keep working.
            return null;
        }
        if (probe.status !== 0) {
            // Last-resort error reporting.
            if (probe.stderr) {
                process.stderr.write(probe.stderr);
            }
            throw new Error(
                `failed to resolve patch cwd via python: directive; ` +
                `python exited with code ${probe.status}`,
            );
        }
        const resolved = probe.stdout.toString().trim();
        if (!resolved) return null;
        return path.resolve(resolved);
    }

    if (directives.cwd) {
        const expanded = substituteEnv(directives.cwd);
        if (path.isAbsolute(expanded)) {
            return path.resolve(expanded);
        }
        return path.resolve(PROJECT_ROOT, expanded);
    }

    // Default cwd: project root.
    return PROJECT_ROOT;
}

/**
 * Resolve the target file path for a patch. Honors ``# target:`` and
 * ``# strip:`` directives; otherwise derives from the patch's first
 * hunk ``+++`` header with ``-p<strip>``.
 */
function resolveTargetPath(patchText, directives, cwd) {
    if (directives.target) {
        return path.resolve(cwd, substituteEnv(directives.target));
    }

    const strip = directives.strip ? parseInt(directives.strip, 10) : 0;
    const m = patchText.match(/^\+\+\+ (\S+)/m);
    if (!m) {
        throw new Error("patch is missing a +++ header");
    }
    let rel = m[1];
    if (strip > 0) {
        const parts = rel.split("/");
        if (parts.length <= strip) {
            throw new Error(
                `strip=${strip} is larger than the +++ path component count`,
            );
        }
        rel = parts.slice(strip).join("/");
    }
    return path.resolve(cwd, rel);
}

/**
 * Apply one patch file. Returns one of:
 *   * { skipped: true,  reason }  - patch should not run here
 *   * { applied: true,  filePath } - patch was applied
 *   * { already: true,  filePath } - patch was already applied
 *   * { failed:  true,  detail }   - patch could not be applied
 */
function applyPatch(patchPath) {
    const raw = fs.readFileSync(patchPath, "utf-8");
    const { directives, cleanedText } = extractDirectives(raw);

    let cwd;
    try {
        cwd = resolvePatchCwd(directives);
    } catch (error) {
        return { failed: true, detail: error.message };
    }
    if (cwd === null) {
        return {
            skipped: true,
            reason:
                "skipping: required Python module not importable / no interpreter on PATH",
        };
    }

    let targetPath;
    try {
        targetPath = resolveTargetPath(raw, directives, cwd);
    } catch (error) {
        return { failed: true, detail: error.message };
    }

    if (!fs.existsSync(targetPath)) {
        return {
            skipped: true,
            reason: `skipping: target file does not exist at ${targetPath}`,
        };
    }

    const hunks = parseUnifiedDiff(cleanedText);
    if (hunks.length === 0) {
        return { failed: true, detail: "patch contains no hunks" };
    }

    let currentText = fs.readFileSync(targetPath, "utf-8");
    let modified = false;
    let alreadyCount = 0;
    const failures = [];

    for (const hunk of hunks) {
        const result = applyHunk(hunk, currentText);
        if (result.status === "applied") {
            currentText = result.newText;
            modified = true;
        } else if (result.status === "already") {
            alreadyCount += 1;
        } else {
            failures.push(result.detail);
        }
    }

    if (failures.length > 0) {
        return {
            failed: true,
            detail: failures.join("\n"),
        };
    }

    if (modified) {
        fs.writeFileSync(targetPath, currentText, "utf-8");
        return { applied: true, filePath: targetPath };
    }

    return { already: true, filePath: targetPath, hunks: alreadyCount };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function main() {
    const specificPatch = process.argv[2];

    if (specificPatch) {
        // Resolve relative paths (e.g. "patches/foo.patch") against PROJECT_ROOT
        const patchPath = path.isAbsolute(specificPatch)
            ? specificPatch
            : path.resolve(PROJECT_ROOT, specificPatch);
        const label = path.relative(PROJECT_ROOT, patchPath);
        let result;
        try {
            result = applyPatch(patchPath);
        } catch (error) {
            console.error(
                `[apply-patches] ${label}: unexpected error: ${error.message}`,
            );
            process.exit(1);
        }
        if (result.failed) {
            console.error(
                `[apply-patches] ${label}: FAILED\n  ${result.detail}`,
            );
            process.exit(1);
        } else if (result.skipped) {
            console.log(`[apply-patches] ${label}: ${result.reason}`);
        } else if (result.applied) {
            console.log(`[apply-patches] ${label}: applied → ${result.filePath}`);
        } else if (result.already) {
            console.log(
                `[apply-patches] ${label}: already applied (${result.hunks} hunk${result.hunks === 1 ? "" : "s"} no-op)`,
            );
        }
        return;
    }

    if (!fs.existsSync(PATCHES_DIR)) {
        console.error(`patches directory not found at ${PATCHES_DIR}`);
        process.exit(1);
    }

    const entries = fs
        .readdirSync(PATCHES_DIR, { withFileTypes: true })
        .filter((entry) => entry.isFile() && entry.name.endsWith(".patch"))
        .map((entry) => entry.name)
        .sort();

    if (entries.length === 0) {
        console.log(`[apply-patches] no .patch files in ${PATCHES_DIR}`);
        return;
    }

    let hadFailure = false;
    for (const name of entries) {
        const patchPath = path.join(PATCHES_DIR, name);
        const label = path.relative(PROJECT_ROOT, patchPath);
        let result;
        try {
            result = applyPatch(patchPath);
        } catch (error) {
            console.error(
                `[apply-patches] ${label}: unexpected error: ${error.message}`,
            );
            hadFailure = true;
            continue;
        }
        if (result.failed) {
            console.error(
                `[apply-patches] ${label}: FAILED\n  ${result.detail}`,
            );
            hadFailure = true;
        } else if (result.skipped) {
            console.log(`[apply-patches] ${label}: ${result.reason}`);
        } else if (result.applied) {
            console.log(`[apply-patches] ${label}: applied → ${result.filePath}`);
        } else if (result.already) {
            console.log(
                `[apply-patches] ${label}: already applied (${result.hunks} hunk${result.hunks === 1 ? "" : "s"
                } no-op)`,
            );
        }
    }

    if (hadFailure) process.exit(1);
}

main();