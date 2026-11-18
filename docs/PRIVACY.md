# Privacy and data handling — QA Sentinels

QA Sentinels is a local monitoring and evidence system. It does not send
telemetry or upload captured data.

## What it collects

- CPU, memory, kernel, process, and hardware samples.
- Journal warnings/errors and crash records.
- LSM state, package state, inventory diffs, and optional fault-core context.
- Network state: interfaces, addresses, routes, DNS, listener sockets, firewall
  summaries, tunnel state and traffic counters. SSIDs, BSSIDs, WireGuard keys
  and peer endpoints are hashed; Netplan and firewall rules are hashed, not
  copied.
- Reports, tickets, evidence bundles, and logs under the workspace.

Captured data can include usernames, command lines, hostnames, network
addresses/routes, process names, and crash context. Treat evidence bundles as
sensitive.

## Where it stays

- Workspace: `~/QA-Sentinels` by default, or `QA_SENTINELS_HOME`.
- Database: `<workspace>/sentinels.db`.
- Evidence, reports, tickets, journals, and logs under the workspace.
- Settings: `<workspace>/config/settings.json`.

The QA Dashboard reads this data locally. It does not upload it.

## Retention

Retention is controlled by settings and environment variables for events,
samples, process snapshots, inventory, network runs, drafts, and raise lookback.
A value of `0` disables pruning for that category. Evidence bundles are files; remove them
according to your retention policy.

## Sharing

Review reports, tickets, and evidence bundles before sending them to a vendor or
attaching them to a public issue. Redact command lines, paths, usernames, and
host identifiers when they are not needed for diagnosis.

## Credentials

QA Sentinels does not require SIEM tokens or vendor credentials. Optional QA SIEM
tokens remain in QA SIEM's own configuration.
