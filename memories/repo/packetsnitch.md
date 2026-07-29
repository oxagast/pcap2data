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
- Stale `snitch.spec` files were deleted from the repo root and
  `tests/`. Do not reintroduce them — PyInstaller always rewrites the
  spec with the building machine's absolute entry-script path.