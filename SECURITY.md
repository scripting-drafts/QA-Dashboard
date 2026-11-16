# Security policy

Report vulnerabilities privately to the maintainer through the repository's
security advisory feature. Do not open a public issue with exploit details.

## Scope

- Electron main/preload/renderer boundary
- Fixed-argument execution of the `qa` CLI
- Read-only database access and ticket path handling

## Expectations

Keep the renderer sandboxed, keep IPC narrow, and never expose a general
filesystem or shell API.
