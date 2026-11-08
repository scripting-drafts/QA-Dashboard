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

## Launchers and single instance

There is no tray or top-bar icon. `qa-dashboard.desktop` opens the compact
Overview and is also the desktop favourite; `install.sh` migrates an existing
QA Sentinels favourite to it. Per-app `.desktop` files call
`qa-dashboard --module=sentinels`, `--module=malware`, or `--module=siem` for
standalone module buttons.

All launches share one Electron instance. A second launch forwards its module
argument to the running process; an existing window is restored and focused,
otherwise it is created. Closing all windows exits the process, so the next
launcher click starts a fresh instance.

The brand mark is a near-closed ouroboros ring with a rounded head, a cut-out
eye, and a tapered tail. `assets/qa-dashboard.svg` is the simple transparent
symbol; `assets/qa-dashboard-detailed.svg` adds contour and scale detail for the
Overview header. `assets/qa-dashboard-icon.svg` is the dark rounded launcher
icon. The 256 and 512 PNG exports provide the Electron window icon and later
platform packaging.

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
