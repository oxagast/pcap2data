"use strict";

// Loads, trains, caches the shell-Markov model. Companion to markov.js.
//
// Design note: the renderer's webpack config (webpack.renderer.config.js)
// doesn't polyfill Node's ``path``/``fs`` modules, so this file
// deliberately avoids top-level requires on either. The caller
// passes them in via the ``deps`` option. In the main process we
// pass `require('path')` / `require('fs')` directly; in the renderer
// the loader is used only as a wrapper around the IPC bridge to
// ``window.markovapi``, which exposes ``getCachedShellMarkov`` /
// ``trainAndCacheShellMarkov`` already implemented in the main
// process. Splitting it this way keeps the renderer bundle from
// pulling in node core modules.

const { ShellMarkov, cleanLines } = require("./markov");

const DEFAULT_MODEL_FILENAME = "shell_markov_model.json";
const DEFAULT_ORDER = 4;
const DEFAULT_ALPHA = 0.05;

// `deps` shape: { path, fs, modelFilename?, order?, alpha? }
//   path : Node `path` module (main process). Required.
//   fs   : Node `fs` module (main process). Required.
function cachedModelPath(deps, userDataDir) {
    return deps.path.join(userDataDir, deps.modelFilename || DEFAULT_MODEL_FILENAME);
}

function getCachedShellMarkov(opts) {
    const deps = opts && opts.deps;
    const userDataDir = opts && opts.userDataDir;
    if (!deps || !userDataDir || !deps.path || !deps.fs) return Promise.resolve(null);
    return new Promise((resolve) => {
        const p = cachedModelPath(deps, userDataDir);
        deps.fs.readFile(p, "utf8", (err, json) => {
            if (err) {
                resolve(null);
                return;
            }
            try {
                const d = JSON.parse(json);
                resolve(ShellMarkov.fromDict(d));
            } catch (_e) {
                // Corrupt cache — drop and fall through to retrain later.
                resolve(null);
            }
        });
    });
}

function trainAndCacheShellMarkov(opts) {
    const deps = opts && opts.deps;
    const userDataDir = opts && opts.userDataDir;
    const corpusPath = opts && opts.corpusPath;
    if (!deps || !userDataDir || !corpusPath || !deps.path || !deps.fs) {
        return Promise.reject(
            new Error("trainAndCacheShellMarkov: deps/path/fs/userDataDir/corpusPath required"),
        );
    }
    const order = deps.order || DEFAULT_ORDER;
    const alpha = (deps.alpha != null) ? deps.alpha : DEFAULT_ALPHA;
    return new Promise((resolve, reject) => {
        deps.fs.readFile(corpusPath, "utf8", (err, corpus) => {
            if (err) {
                reject(err);
                return;
            }
            // Defer the train work to a setImmediate tick so the
            // caller never blocks the renderer main thread on what
            // can be a multi-tens-of-ms loop.
            setImmediate(() => {
                try {
                    const cmds = cleanLines(corpus);
                    const model = new ShellMarkov(order, alpha).train(cmds);
                    const target = cachedModelPath(deps, userDataDir);
                    deps.fs.mkdir(userDataDir, { recursive: true }, (mkErr) => {
                        if (mkErr && mkErr.code !== "EEXIST") {
                            try {
                                console.warn("[markov-loader] mkdir failed:", mkErr.message);
                            } catch (_e) { /* ignore */ }
                        }
                        const json = JSON.stringify(model.toDict());
                        deps.fs.writeFile(target, json, (wErr) => {
                            if (wErr) {
                                try {
                                    console.warn("[markov-loader] writeFile failed:", wErr.message);
                                } catch (_e) { /* ignore */ }
                            }
                            resolve(model);
                        });
                    });
                } catch (innerErr) {
                    reject(innerErr);
                }
            });
        });
    });
}

module.exports = {
    getCachedShellMarkov,
    trainAndCacheShellMarkov,
    cachedModelPath,
};
