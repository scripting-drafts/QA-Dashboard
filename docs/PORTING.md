# Porting notes

All three releases—Linux, Windows, and macOS—are Electron applications. The
Electron core is shared; only shell integration is platform-specific.

## Shared core

- `electron/main.js`: window lifecycle, module routing, IPC.
- `electron/backend.js`: fixed CLI arguments, streaming, SIEM HTTP.
- `electron/preload.js`: narrow `contextBridge` API.
- `renderer/`: compact Overview and module views.
- `assets/qa-dashboard-*`: shared brush-enso brand mark, launcher icon, and PNGs.

Keep module names, window sizes, single-instance behavior, and the token
boundary unchanged across platforms.

## Linux (this branch)

- No tray or top-bar icon.
- `qa-dashboard.desktop` opens the Overview and is used as the favourite.
- Per-app `.desktop` files open QA Sentinels or SIEM directly.
- All launches share one Electron instance and focus existing windows.

## Windows (later)

- No tray icon; use Start-menu and desktop shortcuts.
- The main shortcut opens the Overview; module shortcuts use `--module=...`.
- Keep the single-instance module routing.

## macOS (later)

- No menu-bar icon; the Dock/app icon opens the Overview.
- Package as an app bundle and add per-module shortcuts or URL schemes.
- Keep the same preload, backend, and renderer code.
