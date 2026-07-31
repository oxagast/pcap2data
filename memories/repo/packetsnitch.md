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

## Metrics transport (self-signed TLS)

- The metrics flush in `src/main.js` (`flushMetricsQueue`) posts
  events to `getAppSettings().privacy.metricsEndpointUrl` via
  `undiciFetch`. The production endpoint shares its self-signed cert
  with the catalog/theme server, so undici's strict TLS verification
  must be bypassed for HTTPS metrics endpoints.
- The gate is the same locked flag the theme server uses:
  `getAppSettings().general.allowInsecureTlsEndpoints` (always
  `true`, set in `DEFAULT_SETTINGS.general` and re-emitted by
  `normalizeSettings`, so user edits cannot turn it off).
- Helpers: `isMetricsAllowInsecureTls()` reads the flag,
  `getInsecureMetricsDispatcher(timeoutMs)` returns a cached undici
  `Agent` with `connect: { rejectUnauthorized: false }`. The cache is
  keyed by timeout so multiple timeouts don't share dispatchers.
- `flushMetricsQueue` attaches the dispatcher only when the protocol
  is `https:`. Plain HTTP URLs never get a dispatcher. Failures that
  match `/self.?signed|unable to verify|depth_zero|certificate|ssl|tls/i`
  surface as `isTlsError: true` in the return value so callers can
  show a "self-signed cert" hint.
- The `metrics:status` IPC handler exposes `endpointProtocol`,
  `insecureTls`, and `allowInsecureTls` to the renderer. The
  Privacy/Metrics diagnostics row in `src/index.html` shows a "TLS"
  pill (`settings-api-keys-metrics-tls-status`) that reads
  "Self-signed allowed" when the dispatcher is in use.
- Activity log lines for the metrics flush include `insecureTls=true|false`
  to make cert issues visible in `activity-log.txt`.
- Regression tests live in `tests/metrics_insecure_tls.test.js`. The
  tests use `vm.runInContext` (like `themes_subtab.test.js`) to extract
  the three main-process helpers and stub `Agent`, `undiciFetch`,
  `app`, `appendActivityLogLine`, `getMetricsPrivacy`, and
  `getAppSettings`. Because `normalizeSettings` locks the flag to true,
  tests that need to exercise the flag=false path patch
  `context.getAppSettings` directly.
