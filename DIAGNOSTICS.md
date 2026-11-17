# QA Dashboard diagnostics build

The `-logs` packages are an additive `0.5.9` variant with verbose diagnostics
enabled. The normal packages omit the diagnostics module entirely. The `-logs`
packages are for testing only and contain no license code, activation, or
device limit.

## Log location

- Windows: `%APPDATA%\QA Dashboard\logs\qa-dashboard.log`
- macOS: `~/Library/Logs/QA Dashboard/qa-dashboard.log`
- Linux: `~/.config/QA Dashboard/logs/qa-dashboard.log`

Open **About → Open diagnostics log** to reveal the file. The log rotates at
10 MB to `qa-dashboard.log.1`.

## What is logged

- App version, Electron/Chromium/Node versions, OS, architecture, locale.
- App paths, user-data path, command-line arguments, and `QA_*` environment
  variables.
- Main-process console output and IPC/config views.
- Renderer console messages, preload errors, failed loads, unresponsive
  renderers, and render-process crashes.
- Sentinels command lines, working directories, PIDs, exit codes, and captured
  stdout/stderr.
- Child-process exits and uncaught exceptions.

## Enable diagnostics in the normal build

```bash
QA_DIAGNOSTICS=1 <app> --diagnostics
```

The normal `0.5.9` packages have diagnostics off by default.

## Sharing logs

Logs may contain local paths, command lines, SQL query text, and Sentinels
output. Review the file before sharing. Do not include credentials, personal
data, or production evidence.
