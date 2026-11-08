# Porting notes

The Electron core is platform-neutral and should be reused on Windows and
macOS. Only the shell integration belongs to a platform branch.

## Shared core

- `electron/main.js`: window lifecycle, module routing, IPC.
- `electron/backend.js`: fixed CLI arguments, streaming, SIEM HTTP.
- `electron/preload.js`: narrow `contextBridge` API.
- `renderer/`: compact Overview and module views.

Keep module names, window sizes, single-instance behavior, and the token
boundary unchanged across platforms.

## Linux (this branch)

- Monochrome GNOME Shell top-bar icon in `gnome-extension/`.
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
