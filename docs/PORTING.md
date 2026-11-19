# Porting notes

All three releases—Linux, Windows, and macOS—are Electron applications. The
Electron core is shared; only shell integration is platform-specific.

## Shared core

- `electron/main.js`: window lifecycle, module routing, IPC.
- `electron/backend.js`: fixed CLI arguments and streaming.
- `electron/preload.js`, `electron/preload-settings.js`: narrow `contextBridge` APIs.
- `renderer/`: compact Overview, Sentinel module views, and the settings window.
- `assets/qa-dashboard-*`: shared brush-enso brand mark, launcher icon, and PNGs.

Keep module names, window sizes, and single-instance behavior unchanged across
platforms.

## Linux (this branch)

- No tray or top-bar icon.
- `qa-dashboard.desktop` reopens the last active window and tab and is used as
  the favourite.
- The QA Sentinels `.desktop` file opens the Sentinels Overview window directly.
- All launches share one Electron instance and focus existing windows.

## Windows (later)

- No tray icon; use Start-menu and desktop shortcuts.
- The main shortcut reopens the last active view; module shortcuts use
  `--module=...`.
- Keep the single-instance module routing.

## macOS (later)

- No menu-bar icon; the Dock/app icon reopens the last active view.
- Package as an app bundle and add per-module shortcuts or URL schemes.
- Keep the same preloads, backend, and renderer code.
