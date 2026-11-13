# QA Dashboard

**A modular Electron desktop interface for QA Sentinels on Linux.**

![https://github.com/scripting-drafts/QA-Dashboard/blob/main/docs/screenshots/overview.png]

QA Dashboard is a graphical front end for the existing QA Sentinels command-line
tool. It does not implement monitoring, evidence collection, crash correlation,
or ticket generation itself. It invokes the `qa` CLI and reads the files that
QA Sentinels produces.

Malware Scan and SIEM are not part of this application. QA SIEM is a separate
standalone project with its own service, API, and web dashboard.

## Stack

| Item | Current implementation |
| --- | --- |
| Runtime | Electron |
| Language | JavaScript, HTML, CSS |
| Main process | `electron/main.js` |
| Backend | `electron/backend.js` |
| Preload bridge | `electron/preload.js` |
| Renderer | `renderer/index.html`, `renderer/app.js`, `renderer/style.css` |
| External engine | QA Sentinels `qa` CLI |
| Database access | Read-only `qa query` calls |
| Version | `0.2.0` |

Linux is the current target. The Electron core is portable; Windows and macOS
porting notes are in `docs/PORTING.md`.

## Windows and modules

The application uses independent windows instead of one tabbed suite.

| Window | Purpose |
| --- | --- |
| **QA Dashboard** | Compact Overview with QA Sentinels, Database, and Ticket workflow cards |
| **QA Sentinels Overview** | Status grid, Logs action, Documentation action |
| **QA Sentinels Database** | Read-only SQL console over `sentinels.db` |
| **QA Sentinels Tickets** | Ticket buckets, refresh, open folder, Rules |
| **QA Sentinels Logs** | Live `qa logs --all-layers --follow` stream |

`Ticket Rules` and `Documentation` open as standalone HTML pages in the system
browser:

- `renderer/rules.html`
- `renderer/docs.html`

### Supported module arguments

```text
overview
sentinels
sen-overview
tickets
findings
logs
```

`findings` is an alias for the Tickets window. The former `malware`, `siem`,
and `record` modules no longer exist.

## QA Sentinels integration

QA Dashboard resolves the `qa` executable and repository root from configuration,
environment, or common locations:

- Configured `sentinelsBin` and `sentinelsRoot`
- `QA_SENTINELS_BIN` and `QA_SENTINELS_ROOT`
- `~/QA-Sentinels`
- `~/Quality-Assurance-Sentinels`
- `/opt/QA-Sentinels`
- `/opt/Quality-Assurance-Sentinels`

Available capabilities:

- Read `qa status` and display parsed values.
- Auto-refresh status every 10 seconds in the Overview and Sentinels Overview.
- Run read-only `qa query` calls against `sentinels.db`.
- Read ticket directories and open ticket files.
- Stream live logs into the Logs window.
- Keep the newest cycle markers for Database highlighting.

The installed Sentinel systemd timer or user cron owns the routine cycle. The
Dashboard keeps a fallback cycle timer only when neither scheduler is present.
There is no manual cycle button.

The Dashboard does not expose a general shell. Commands use fixed argument
vectors. Arbitrary commands are not accepted.

## Database

The Database window is a read-only SQL console for `sentinels.db`.

Features:

- One `SELECT`, `WITH`, or `EXPLAIN` statement per run.
- Search, severity, status, and since filters.
- Sortable result columns.
- Row detail panel.
- Collapsible Tables sidebar, collapsed by default.
- Table row counts and column names.
- Result limits from 100 to 10,000 rows.
- Category base view for all findings.

The renderer never opens the database. SQL is passed as one argument to
`qa query`, and the Sentinels engine enforces the read-only rule and row limit.

## Tickets

The Tickets window reads the QA Sentinels ticket directories:

```text
raise/
raised/
rejected/
standby/
```

It can refresh the lists, open the tickets folder, and open individual tickets.
The Rules action opens the standalone rules reference.

## Configuration

Configuration is stored at:

```text
~/.config/qa-dashboard/config.json
```

If `XDG_CONFIG_HOME` is set, it is stored under:

```text
$XDG_CONFIG_HOME/qa-dashboard/config.json
```

The file is written with mode `0600`.

Current fields:

| Field | Purpose |
| --- | --- |
| `sentinelsBin` | Path to the `qa` executable |
| `sentinelsRoot` | Path to the QA Sentinels repository |
| `sentinelsCycleMinutes` | Dashboard fallback cycle interval |
| `sentinelsCycleHours` | Raise-gate cadence |
| `sentinelsDraftsRetentionDays` | Draft retention |
| `sentinelsRaiseLookbackDays` | Raise-gate evidence lookback |
| `sentinelsEventRetentionDays` | Event retention |
| `sentinelsSamplesRetentionDays` | Sample retention |
| `sentinelsProcRetentionDays` | Process snapshot retention |
| `sentinelsInventoryRetentionDays` | Inventory retention |

Settings open from the QA Sentinels Overview window. The Database and Tickets
windows do not show the Settings button.

There are no Malware Scan or SIEM configuration fields.

## Requirements

- Node.js and npm
- A Linux desktop session
- QA Sentinels and its `qa` CLI installed separately
- Optional: the Sentinel systemd timer or user cron schedule

Python, GTK4, PyGObject, ClamAV, YARA, and a QA SIEM service are not required.

## Installation

```bash
./install.sh
```

The default prefix is `~/.local`. Override it with `PREFIX`.

The installer:

1. Stops an existing Electron instance and any legacy QA Desktop process.
2. Copies the Electron application and dependencies.
3. Installs the `qa-dashboard` command.
4. Installs the Dashboard and QA Sentinels desktop launchers.
5. Installs the light and dark application icons.
6. Installs the documentation.
7. Installs the hidden GNOME theme extension.
8. Removes legacy QA Desktop/Python launchers and tray autostart entries.

### Desktop launchers

| Desktop entry | Module |
| --- | --- |
| QA Dashboard | Overview |
| QA Sentinels | Database |

There is no tray, top-bar icon, combined suite launcher, Malware Scan launcher,
or SIEM launcher.

### Uninstallation

```bash
./uninstall.sh
```

Add `--purge-config` to remove the user configuration as well.

## Running from the repository

```bash
npm start
npm start -- --module=overview
npm start -- --module=sentinels
npm start -- --module=sen-overview
npm start -- --module=tickets
npm start -- --module=logs
```

The installed launcher can also be used:

```bash
qa-dashboard
qa-dashboard --module=sentinels
```

## Security and process execution

The renderer runs with:

- `nodeIntegration: false`
- `contextIsolation: true`
- `sandbox: true`

The preload exposes a narrow `contextBridge` API. External commands are started
as argument lists, not shell strings. Standard output and standard error are
streamed into the interface. Active commands can be cancelled.

The Dashboard does not read or store SIEM tokens, because SIEM is not part of
this application. The only credentials involved are those managed by QA
Sentinels itself.

## Tests

```bash
npm test
```

The current tests cover:

- Fixed Sentinels argument construction
- Query argument construction
- Status output parsing
- Configuration round-trips and permissions
- Sentinels settings normalization and mirroring
- Ticket bucket listing and path safety
- Sentinel scheduler detection

There are no GTK, tray, Malware Scan, or SIEM tests.

## Project structure

```text
QA-Dashboard/
├── assets/
│   ├── qa-dashboard-enso.png
│   ├── qa-dashboard-1024.png
│   ├── qa-dashboard-256.png
│   ├── qa-dashboard-512.png
│   └── qa-dashboard-light-*.png
├── bin/
│   └── qa-dashboard
├── docs/
│   ├── ARCHITECTURE.md
│   └── PORTING.md
├── electron/
│   ├── backend.js
│   ├── main.js
│   └── preload.js
├── gnome-extension/
│   └── theme/
├── renderer/
│   ├── app.js
│   ├── docs.html
│   ├── index.html
│   ├── rules.html
│   └── style.css
├── tests/
│   └── backend.test.js
├── install.sh
├── uninstall.sh
├── Makefile
├── package.json
└── README.md
```

## Relationship to the former QA Desktop

The former QA Desktop was a GTK4/Python application with Sentinels, Malware
Scan, SIEM, and a StatusNotifierItem tray. That implementation is gone.

Only legacy cleanup remains in `install.sh` and `uninstall.sh`: they still stop
old `qadesk` processes and remove `qa-desktop` binaries, libraries, icons,
desktop entries, and tray autostart files. No QA Desktop source code,
Malware Scan module, SIEM module, or tray implementation is present.

The Sentinels integration is the only former module that survived, and it has
been rewritten as an Electron interface with a new Database and independent
Tickets window.

# History

Current application version: **0.2.0**, defined in `package.json`.

Lead Developer - Gerard Sala
- LinkedIn: https://www.linkedin.com/in/gerard-sala/
- GitHub: https://github.com/scripting-drafts

# License

The MIT License (MIT)

Copyright (c) 2026 Gerard Sala
