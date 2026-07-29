# PacketSnitch notes

## Backend build (PyInstaller)

- The backend is packaged with PyInstaller via `scripts/build-backend.sh`
  (not `snitch.spec`). The script picks the right binary name per OS
  (`snitch.exe` on Windows, `snitch` elsewhere) and routes the auto-
  generated `.spec` into `build/pyinstaller/` so it never lands in the
  repo with absolute paths baked in. The npm scripts in `package.json`
  invoke the bash wrapper (`build:backend`, `build:backend:linux`,
  `build:backend:macos`, `build:backend:windows`).
- `forge.config.js` `extraResource` is platform-aware: Windows uses
  `src/backend/snitch.exe`, Linux/macOS use `src/backend/snitch`.
- `src/main.js` already had the matching two-candidate lookup at
  `process.resourcesPath/snitch[.exe]` (it works for both layouts).
## Test environment

- Two pre-existing test suites (`consent_overlay.test.js`,
  `metrics_tab_tracking.test.js`) fail to load because they require
  `jsdom` which is not installed. They are environment failures, not
  regressions — they have never passed in this codebase. Confirmed by
  running `npm run test:frontend` with my changes stashed: same two
  suites fail, same 2-line `Cannot find module 'jsdom'` error.
- The summary stats weaving tests (`tests/summary_stats_weaving.test.js`)
  load source from `src/ui/main-frontend.js` via `vm.createContext` and
  stub functions like `normalizeSummaryMarkdownHeadings` and
  `getCurrentCompactedAnalysisSummary`. When the real code gains new
  helpers (e.g. `prependSummaryHeading`), tests must add stubs for
  those helpers in `extraContext` and load the new helpers via
  `loadFunction`/`loadConstant` in `helperSource`.

## Summary distillation & heading

- The "# PacketSnitch's Summary" heading MUST be prepended exactly once
  per report. Earlier code embedded it inside
  `normalizeSummaryMarkdownHeadings`, which was called per context-
  scoped entry, so multi-entry reports printed the heading repeatedly.
  The fix: `normalizeSummaryMarkdownHeadings` only normalizes; callers
  (`renderSummaryMarkdownPreview`, `getSummaryMarkdownForExport`) call
  `prependSummaryHeading(...)` once at the top.
- The export-time LLM distiller, the compaction prompt, the per-stream
  prompt, and the data-tools LLM summarizer all carry a "SQUELCH NO-OP
  DATA" instruction telling the model to omit failed decoders, parsers,
  lookups, and empty conversions from the report.
- `pushDistilledSummaryIntoSummaryTab` uses `unshift` (not `push`) so
  the consolidated distilled summary sits at the TOP of the running
  summary stream, with prior context-scoped entries preserved below it.
