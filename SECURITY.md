# Security policy

Report vulnerabilities privately to the maintainer through the repository's
security advisory feature. Do not open a public issue with exploit details.

## Scope

- Electron main/preload/renderer boundary
- Fixed-argument execution of the `qa` CLI
- Read-only database access and ticket path handling
- License & Legal document allowlist and report export

## Expectations

Keep the renderer sandboxed, keep IPC narrow, validate document IDs against the
manifest, and never expose a general filesystem or shell API. The Legal window
must remain read-only except for the user-selected report export.
