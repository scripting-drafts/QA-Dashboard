# Porting notes

All three releases—Linux, Windows, and macOS—are Electron applications. The
Electron core is shared; only shell integration is platform-specific.

## Shared core

- `electron/main.js`: window lifecycle, module routing, IPC.
- `electron/backend.js`: fixed CLI arguments and streaming.
- `electron/preload.js`: narrow `contextBridge` API.
- `renderer/`: compact Overview and Sentinel module views.
- `assets/qa-dashboard-*`: shared brush-enso brand mark, launcher icon, and PNGs.

Keep module names, window sizes, and single-instance behavior unchanged across
platforms. QA SIEM is a separate project and is not part of this core.

## Linux (this branch)

- No tray or top-bar icon.
- `qa-dashboard.desktop` opens the Overview and is used as the favourite.
- The QA Sentinels `.desktop` file opens the Database window directly.
- All launches share one Electron instance and focus existing windows.

## Windows (later)

- No tray icon; use Start-menu and desktop shortcuts.
- The main shortcut opens the Overview; module shortcuts use `--module=...`.
- Keep the single-instance module routing.

## macOS (later)

- No menu-bar icon; the Dock/app icon opens the Overview.
- Package as an app bundle and add per-module shortcuts or URL schemes.
- Keep the same preload, backend, and renderer code.
