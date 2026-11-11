# Architecture

QA Dashboard is an Electron application with a narrow IPC boundary. The two
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

The Overview uses a centered brush-enso lockup above the title. Module cards
carry their open actions; the Overview has no Refresh or Settings controls.
The main Dashboard window uses its default 980x640 size. The content column
uses the full window width; maximizing a window expands its tables, card grid,
and module panels to the available work area. Only the Database window shows
the `sentinels.db` state pill in the top-right; all other windows hide it.
The visual language is a TaiG-inspired teal palette. The light variant uses
flat white surfaces without shadows or glows; the dark variant keeps the cyan
edge glows, glassy gradients, and layered shadows. Both follow the desktop color
setting, including the native window decoration.

## QA Sentinels

The main process resolves `qa` and its repository root, then runs fixed actions:
`status`, `cycle`, `findings`, and `query`. The QA Sentinels Database window is
a read-only SQL console over `sentinels.db`. It opens on the all-findings base
view, with search, severity, status, and since filters. Status is single-select,
while multiple severity choices are alternatives. The SQL box runs one
read-only `SELECT`/`WITH`/`EXPLAIN` statement; Clear returns
to the base view. Result column headers sort the loaded rows in place without
re-running the query. Category presets remain available to the CLI only. The newest cycle with new
findings is loaded silently to mark NEW rows; full cycle summaries remain in
the Runs category. The QA Sentinels engine enforces the read-only rule and row
limit; the dashboard only builds an argument vector and never opens the
database itself. The Overview window contains the status grid and the ticket
board as tabs; it is opened from the QA Dashboard Overview card. The Database
window exposes only the filters, SQL box, and result panels. A cycle runs
automatically only as a fallback: when the installed Sentinel systemd timer or
user cron block is absent, `sentinelsCycleMinutes` (10 minutes by default)
drives it. When a Sentinel scheduler is present, that scheduler owns the cycle.
There is no manual cycle button. A single `qa logs --all-layers
--follow` process runs in the background for the lifetime of the dashboard and
fills a bounded in-memory buffer. The Overview window's Logs button only opens
or focuses its viewer; opening it replays the buffered tail and then follows
live lines, so closing and reopening the window never restarts the command.
Output streams to that window over `event` messages. Arbitrary commands are not
exposed; SQL is passed as one argv item and validated by the Sentinels process.

## SIEM

`electron/backend.js` reads the token file and requests `/healthz`,
`/api/v1/stats`, `/api/v1/alerts`, and `/api/v1/events`. Alert acknowledgement
posts to `/api/v1/alerts/ack`. The dashboard button opens the web dashboard with
`shell.openExternal`.

## Launchers and single instance

There is no tray or top-bar icon. `qa-dashboard.desktop` opens the compact
Overview and is also the desktop favourite; `install.sh` migrates an existing
QA Sentinels favourite to it. Per-app `.desktop` files call
`qa-dashboard --module=sentinels` or `--module=siem` for standalone module
buttons.

All launches share one Electron instance. A second launch forwards its module
argument to the running process; an existing window is restored and focused,
otherwise it is created. When the app is restored after a full minimize, it
brings the Dashboard forward unless the restore came from a module launcher.
Desktop entries set `StartupNotify=false` so single-instance handoff cannot
leave a stuck busy pointer. Closing all windows exits the process, so the next
launcher click starts a fresh instance.

The brand mark is the brush-enso artwork, converted to a transparent alpha mask
at `assets/qa-dashboard-enso.png`. CSS tints it for the active light or dark
theme and for the Overview gradient. The favourite/dock icon has full-colour
light and dark tile variants. A hidden `qa-dashboard-theme@local` Shell
extension switches the favourite and other QA launcher icons with the chosen
appearance and adds no top-bar item.

## Settings and auto-refresh

Settings open from a module window and are scoped to that module: Sentinels
command and root, or SIEM URL and token file. Saving one module leaves the
other configuration keys untouched.

The main process refreshes Sentinels status and the SIEM snapshot every 10
seconds and broadcasts the results to the Overview and the relevant module
windows. The Database window is query-driven and refreshes when a category, the Refresh
button, or the optional SQL statement is run.

## Configuration

`~/.config/qa-dashboard/config.json` stores command overrides, repository roots,
the SIEM URL, token-file path, and the Sentinel fallback cycle interval. It is
written mode `0600`. Tokens are read at request time and are never written to
this file or exposed to the renderer.

## Testing

`npm test` covers argument construction, status parsing, config permissions, and
the HTTP client. Electron smoke screenshots can be produced with:

```bash
npm start -- --module=overview --screenshot=/tmp/qa-overview.png
npm start -- --module=sentinels --screenshot=/tmp/qa-sentinels.png
npm start -- --module=sen-overview --screenshot=/tmp/qa-sen-overview.png
```
