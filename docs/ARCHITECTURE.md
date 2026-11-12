# Architecture

QA Dashboard is an Electron application with a narrow IPC boundary. The
dashboard only invokes the Sentinels CLI; it never opens the database itself.
QA SIEM is a separate standalone project and is out of scope for this
application.

## Process boundaries

| Layer | Responsibility |
| --- | --- |
| Main process (`electron/main.js`) | Window lifecycle, IPC, child processes |
| Backend (`electron/backend.js`) | Config resolution, fixed argv builders, streaming |
| Preload (`electron/preload.js`) | Minimal `contextBridge` API; no Node in the renderer |
| Renderer (`renderer/`) | Compact Overview window and module-specific windows |

The renderer has `nodeIntegration: false`, `contextIsolation: true`, and
`sandbox: true`.

## Overview layout

The Overview uses a centered brush-enso lockup above the title. Module cards
carry their open actions; the Overview has no Refresh or Settings controls.
QA Sentinels, Database, and Tickets are separate module cards, with Database
in the middle.
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
re-running the query. The table sidebar lists every database table with its
row count and columns; selecting one loads and runs a limited `SELECT *`.
Category presets remain available to the CLI only. The newest cycle with new
findings is loaded silently to mark NEW rows; full cycle summaries remain in
the Runs category. The QA Sentinels engine enforces the read-only rule and row
limit; the dashboard only builds an argument vector and never opens the
database itself. The QA Sentinels Overview window contains the status grid
and is opened from the QA Sentinels card. The separate Tickets window contains
the ticket board and is opened from the Tickets card. The Database window
exposes a collapsible table sidebar, collapsed by default, plus filters, the
SQL box, and result panels. A cycle runs
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

The Rules button opens `renderer/rules.html` and the Documentation button opens
`renderer/docs.html`; both are standalone documents in the system browser rather
than application windows.

QA SIEM is not part of this application. It remains a separate standalone
program with its own repository, service, API, and web dashboard.

## Launchers and single instance

There is no tray or top-bar icon. `qa-dashboard.desktop` opens the compact
Overview and is also the desktop favourite; `install.sh` migrates an existing
QA Sentinels favourite to it. The per-app `.desktop` file calls
`qa-dashboard --module=sentinels` for the standalone Database window. There is
no SIEM launcher or SIEM window in this application.

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

Settings open from a Sentinels window and cover the command, repository root,
cycle, and retention. The Database window shares the Sentinels configuration.

The main process refreshes Sentinels status for the Overview every 10 seconds.
The Database window is query-driven and refreshes when a category, the Refresh
button, or the optional SQL statement is run.

## Configuration

`~/.config/qa-dashboard/config.json` stores Sentinel command overrides,
repository roots, and the fallback cycle interval. It is written mode `0600`.
No SIEM credentials or endpoints are stored by this application.

## Testing

`npm test` covers argument construction, status parsing, ticket handling, and
config permissions. Electron smoke screenshots can be produced with:

```bash
npm start -- --module=overview --screenshot=/tmp/qa-overview.png
npm start -- --module=sentinels --screenshot=/tmp/qa-sentinels.png
npm start -- --module=sen-overview --screenshot=/tmp/qa-sen-overview.png
```
