# Cross-platform contract

QA Sentinels keeps the Linux collector set and adds Windows and macOS
backends behind one platform contract. The Linux package and Debian files are
unchanged.

## Supported targets

- Linux: existing Ubuntu 22.04–26.10 baseline.
- Windows 11 x64/ARM64.
- macOS 13+ Intel/Apple Silicon.

## Current status

Working on Windows/macOS source checkouts:

- `qa init`, `qa platform`, `qa platform --collect`, `qa cycle`, `qa status`,
  `qa query`, `qa findings`, `qa legal`, `qa compat`, `qa preflight`.
- Read-only snapshots for host, processes, services, network, security,
  crashes, updates, startup items and hardware.
- Platform findings for Defender/firewall/BitLocker/TPM, Gatekeeper/SIP/
  FileVault/firewall, and application/bugcheck/panic reports.
- Portable `platform_snapshots` storage and the `platform` query category.

Still being ported to full parity: boot classification, deep hardware,
per-finding network rules, fault-core/CPU-affinity rules, ETW/DTrace depth,
ticket/report/evidence parity, native installers and scheduler integration.
Linux packages and Debian files are unchanged.

## Platform contract

`sentinels/platform/` selects a backend at runtime:

- `linux.py` — exposes the existing Linux collectors.
- `windows.py` — CIM, Event Log, SCM, NetTCPIP, Defender/Firewall/BitLocker/TPM.
- `macos.py` — launchd, `ps`, `ifconfig`/`netstat`/`scutil`, `spctl`/`csrutil`/
  `fdesetup`, DiagnosticReports, `system_profiler`.

Every backend reports capabilities as `supported`, `degraded`,
`needs_permission` or `planned`. `qa platform` prints the host, capabilities and
the finding-family matrix. `qa platform --collect` runs a read-only snapshot.

## Finding equivalence

`sentinels/platform/findings.py` maps every rule family to a Windows and macOS
family. A platform equivalent may be weaker (`degraded`) or still in progress
(`planned`), but it is never silently dropped. Unknown rules map to `unassigned`
and retain the raw rule with process/event evidence.

Examples:

| Linux | Windows | macOS |
|---|---|---|
| `hardware.storage.smart` | SMART/WMI storage | SMART/IOKit storage |
| `network.route.default_missing` | IP Helper routes | `netstat`/`route` |
| `lsm.selinux.permissive` | Defender/ASR posture | SIP/TCC posture |
| `crash.faultcore` | WER/bugcheck | panic/`.ips` reports |
| `faultcore.*` | CPU affinity/core parking | CPU affinity |

## Privileges

- Windows: service/LocalSystem for services, Event Log and security state;
  unprivileged UI.
- macOS: root LaunchDaemon for protected state; unprivileged UI. Full Disk
  Access may be required. Endpoint Security is a separate Apple entitlement and
  is not part of the first port.

## Packaging

Windows uses a bundled Python runtime and `qa.cmd`/`qa.ps1`; macOS uses a
bundled Python runtime and a LaunchDaemon. Both ship the same SQLite schema,
evidence format, query engine and legal register.
