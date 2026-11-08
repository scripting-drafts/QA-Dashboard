# Architecture

QA Dashboard is an Electron application with a narrow IPC boundary. The three
engines stay independent: the dashboard only invokes their CLI or local API.

## Process boundaries

| Layer | Responsibility |
| --- | --- |
| Main process (`electron/main.js`) | Window lifecycle, IPC, child processes, local SIEM HTTP |
| Backend (`electron/backend.js`) | Config resolution, fixed argv builders, streaming, HTTP |
| Preload (`electron/preload.js`) | Minimal `contextBridge` API; no Node in the renderer |
| Renderer (`renderer/`) | Compact Overview window and module-specific windows |

The renderer has `nodeIntegration: false`, `contextIsolation: true`, and
`sandbox: true`. It never receives the SIEM bearer token; HTTP requests are made
in the main process.

## Overview layout

The Overview uses a centered ouroboros lockup above the title. The status,
Refresh, and Settings controls sit in the hero row. Each module card carries its
own primary and secondary action, so there is no separate quick-actions panel.

## Sentinels

The main process resolves `qa` and its repository root, then runs fixed actions:
`status`, `cycle`, `findings`, `logs`, and `evidence`. Output streams to the
renderer over `event` messages. Arbitrary commands are not exposed.

## Malware Scan

The renderer sends scan options. The backend builds an argument vector with
`--json`, `--fail-on none`, and a final `--` before the target. Child output is
streamed line by line; the renderer parses JSONL findings and summaries. Process
groups are terminated on Stop.

## SIEM

`electron/backend.js` reads the token file and requests `/healthz`,
`/api/v1/stats`, `/api/v1/alerts`, and `/api/v1/events`. Alert acknowledgement
posts to `/api/v1/alerts/ack`. The dashboard button opens the web dashboard with
`shell.openExternal`.

## Top-bar icon and launchers

The top-bar icon is a small GNOME Shell extension, `qa-dashboard@local`. It uses
the monochrome ouroboros mark and launches `qa-dashboard --module=overview` on
click. There is no dropdown menu and no Quit item. The extension ships in
`gnome-extension/legacy` for GNOME 42–44 and `gnome-extension/modern` for GNOME
45+; `install.sh` selects the matching one. The shell extension replaces the
Electron tray, whose AppIndicator single click opened an empty menu.

The brand mark is a near-closed ouroboros ring with a rounded head, a cut-out
eye, and a tapered tail. `assets/qa-dashboard.svg` is the transparent
symbol used by the top bar and as the renderer mask;
`assets/qa-dashboard-icon.svg` is the dark rounded launcher icon. The 256 and
512 PNG exports provide the Electron window icon and later platform packaging.

Each module has its own window, and windows are cascaded so they do not open
directly on top of each other. Closing a module closes that window; the top-bar
icon remains available. A single application instance manages all windows.

Per-app `.desktop` files call `qa-dashboard --module=sentinels`,
`--module=malware`, or `--module=siem`. There is no separate QA Dashboard suite
desktop entry; the top-bar icon is the unified entry point.

The GNOME integration is Linux-specific. Windows and macOS releases replace only
this shell access layer; the Electron core and module windows stay unchanged.
See `docs/PORTING.md`.

## Configuration

`~/.config/qa-desktop/config.json` stores command overrides, repository roots,
the SIEM URL, and token-file path. It is written mode `0600`. Tokens are read at
request time and are never written to this file or exposed to the renderer.

## Testing

`npm test` covers argument construction, status parsing, config permissions, and
the HTTP client. Electron smoke screenshots can be produced with:

```bash
npm start -- --module=overview --screenshot=/tmp/qa-overview.png
npm start -- --module=malware --screenshot=/tmp/qa-malware.png
```
