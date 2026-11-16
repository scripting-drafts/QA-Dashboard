# Privacy and data handling — QA Dashboard

QA Dashboard is a local front end for QA Sentinels. It does not send telemetry,
analytics, or crash reports, and it does not contact a license server.

## What stays local

- Configuration: `~/.config/qa-dashboard/config.json` (mode `0600`).
- QA Sentinels workspace: the configured repository root, typically
  `~/QA-Sentinels`.
- Database: `sentinels.db` under the workspace.
- Tickets, reports, evidence bundles, logs, and samples: under the workspace.
- Optional QA Sentinels settings: `<root>/config/settings.json`.

QA Sentinels can collect host data such as process names, command lines,
journal records, hardware details, and crash context. That data remains local
unless you explicitly share it. Review evidence bundles before sending them to
a vendor or attaching them to a public issue.

## What the Dashboard reads

The renderer never opens the database. It invokes fixed `qa` commands and reads
ticket files through the main process. The Sentinels engine enforces read-only
queries and row limits.

## Retention

Retention is configured in QA Sentinels Settings: drafts, raise lookback,
events, samples, process snapshots, and inventory. Setting a value to `0`
disables pruning for that category. The Dashboard does not upload or copy
retained data.

## Credentials

QA Dashboard does not store SIEM tokens or vendor credentials. Tokens managed by
QA Sentinels or QA SIEM remain in their own configuration.
