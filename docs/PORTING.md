# Porting notes

All three releases—Linux, Windows, and macOS—are Electron applications. The
Electron core is shared; only shell integration is platform-specific.

## Shared core

- `electron/main.js`: window lifecycle, module routing, IPC.
- `electron/backend.js`: fixed CLI arguments, streaming, SIEM HTTP.
- `electron/preload.js`: narrow `contextBridge` API.
- `renderer/`: compact Overview and module views.
- `assets/qa-dashboard-*`: shared ouroboros brand mark, launcher icon, and PNGs.

Keep module names, window sizes, single-instance behavior, and the token
boundary unchanged across platforms.

## Linux (this branch)

- Monochrome ouroboros GNOME Shell top-bar icon in `gnome-extension/`.
- `install.sh` / `uninstall.sh` manage the extension and per-app launchers.
- Click opens `qa-dashboard --module=overview`; no menu and no Quit item.

## Windows (later)

- Replace the GNOME extension with a tray icon whose click opens the Overview.
- Do not attach a context menu; keep the single-instance module routing.
- Add shortcuts that launch `--module=sentinels`, `--module=malware`, and
  `--module=siem`.

## macOS (later)

- Use a menu-bar status item with a template (monochrome) image; its action
  opens the Overview without a dropdown.
- Package as an app bundle and add per-module shortcuts or URL schemes.
- Keep the same preload, backend, and renderer code.
