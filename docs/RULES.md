# QA Sentinels rules and checks

This register describes every finding rule and operational check implemented by
QA Sentinels `1.4.2`. Rules are code, not policy prose: the linked module is the
authoritative implementation.

## Severity model

| Severity | Meaning | Automatic action |
|---|---|---|
| `critical` | Crash ownership, data-integrity, security, hardware, or fault-core condition requiring review | May queue a layer-2 deep trace when `QA_DEEP_AUTO=1`; boot findings are not traced |
| `error` | A service, route, privilege, or expected system state is broken | Ticket drafting; no automatic deep trace |
| `warning` | Degraded, non-critical, stale, or coverage-limited state | Ticket drafting; no automatic deep trace |
| `info` | Preflight, status, or capability check only | Not stored as a finding |

Findings are deduplicated by fingerprint. Repeated journal rules are grouped by
a stable signature and show an occurrence count. `critical` findings do not
automatically submit tickets; drafts remain human-reviewed.

## Journal and kernel rules

Implemented in `sentinels/detect.py`.

| Rule | Severity | Trigger |
|---|---|---|
| `kernel.hardware` | critical | MCE, machine check, hardware error, EDAC, or RAS message |
| `kernel.oops` | critical | Kernel panic, oops, BUG, general protection fault, soft/hard lockup, hung task, or watchdog BUG |
| `memory.oom` | critical | Out-of-memory or OOM-kill message |
| `gpu.xid` | critical | NVIDIA Xid or GPU has fallen off the bus |
| `nvrm.error` | error | NVRM error, fatal, assertion, video-memory, or OOM condition |
| `systemd.service_start` | error | `Failed to start`; grouped |
| `systemd.unmount` | error | `Failed unmounting` / `Failed to unmount`; grouped |
| `systemd.unit_stop` | error | `Failed to stop`; grouped |
| `systemd.shutdown` | error | Failed finalize, kill, send, wait, enqueue, isolate, or switch; grouped |
| `kernel.kho` | warning | KHO lowmem scratch failure or kexec handover disabled; grouped |
| `kernel.bluetooth` | warning | Bluetooth hci0 firmware download, frame, feature, or MSFT-read errors; grouped |
| `gpu.drm.timeout` | warning | NVIDIA DRM `Flip event timeout` or `nv_drm` `*ERROR*`; grouped |
| `kernel.nohz` | warning | `NOHZ tick-stop error`; grouped, applies to warning or error journal priority |
| `journal.critical` | warning | Unmatched journal event already classified `critical` |

Unmatched `warning` journal entries are ignored. Unmatched `error` entries are
ignored; unmatched `critical` entries become `journal.critical`.

## Crash rules

Implemented in `sentinels/detect.py`.

| Rule | Severity | Trigger |
|---|---|---|
| `crash.faultcore` | critical | Crash with `faultcore_involved=1` |
| `crash.affinity_unknown` | warning | Browser-like crash whose fault-core involvement cannot be determined |

Crash findings include the stored `component`, CPU affinity, fault-core verdict,
and held/outdated package context when available.

## Resource and pressure rules

Implemented in `sentinels/detect.py`.

| Rule | Severity | Trigger | Default threshold |
|---|---|---|---|
| `memory.low` | critical | Available memory percentage below limit | `QA_MEM_AVAILABLE_ALERT_PCT=5` |
| `memory.pressure` | warning | PSI memory full `avg300` at or above limit | `QA_PSI_MEMORY_FULL_ALERT=10` |
| `io.pressure` | warning | PSI io some `avg300` at or above limit | `QA_IO_PRESSURE_ALERT=50` |
| `thermal.high` | warning | Hottest thermal zone at or above limit | `QA_TEMP_ALERT_C=90` |

Sample rules are fingerprinted per 10-minute bucket.

## Boot rule

Implemented in `sentinels/boot.py`.

| Rule | Severity | Trigger |
|---|---|---|
| `boot.unclean` | critical | Previous boot ended without `systemd-shutdown` (`ended_clean=0`) |

The detail includes captured startup/shutdown markers, coredump/GPU/I/O/MCE/OOM/
panic/thermal/watchdog counts, pstore state, and kexec status. Boot findings are
never sent to layer 2 because the boot has already ended.

## Fault-core rules

Implemented in `sentinels/faultcore.py`; only active when fault-core monitoring is
enabled and CPUs are configured.

| Rule | Severity | Trigger |
|---|---|---|
| `faultcore.topology.absent` | warning | Configured physical core is no longer present |
| `faultcore.topology.changed` | warning | Logical CPU mapping differs from the configured core |
| `faultcore.retired.online` | critical | `retired` mode but a fault CPU is online |
| `faultcore.lab.offline` | warning | `lab` mode but all fault CPUs are offline |
| `faultcore.isolation.missing` | warning | Missing `isolcpus`, `nohz_full`, `rcu_nocbs`, or sysfs isolation |
| `faultcore.isolation.unfenced` | critical | `system.slice` or `user.slice` cpuset still includes the fault core |
| `faultcore.lab.slice_missing` | warning | `faultlab.slice` is absent or does not contain the fault core |
| `faultcore.irq.affinity` | warning | IRQ affinity still includes the fault core |
| `faultcore.ab.divergence` | critical | Faultlab A/B verdict `DIVERGENCE` |
| `faultcore.ab.hw_suspect` | warning | Faultlab A/B verdict `HW-SUSPECT` |
| `faultcore.ab.control_unstable` | warning | Faultlab A/B verdict `CONTROL-UNSTABLE` |

## Hardware rules

Implemented in `sentinels/hardware.py`.

| Rule | Severity | Trigger | Default threshold |
|---|---|---|---|
| `hardware.edac.dimm_ue` | critical | Any DIMM uncorrected error |
| `hardware.edac.ue` | critical | Any EDAC uncorrected error |
| `hardware.edac.ce` | warning | Corrected errors at or above limit | `QA_HARDWARE_CE_ALERT=1` |
| `hardware.aer.fatal` | critical | Any PCIe AER fatal error |
| `hardware.aer.nonfatal` | critical | Any PCIe AER non-fatal error |
| `hardware.aer.correctable` | warning | Correctable AER at or above limit | `QA_HARDWARE_AER_CE_ALERT=1` |
| `hardware.apei.pstore` | warning | pstore summary contains an error signature |
| `hardware.apei.journal` | warning | APEI/GHES/MCE journal contains an error signature |
| `hardware.storage.smart` | critical | SMART overall health failed |
| `hardware.storage.temperature` | warning | Drive temperature at or above limit | `QA_HARDWARE_STORAGE_TEMP_ALERT_C=50` |
| `hardware.storage.media` | critical | NVMe media errors greater than zero |
| `hardware.storage.wear` | warning | NVMe percentage used at or above limit | `QA_HARDWARE_NVME_USED_ALERT=1` |
| `hardware.storage.spare` | warning | Available spare below limit | `QA_HARDWARE_NVME_SPARE_ALERT=100` |
| `hardware.storage.critical_warning` | critical | NVMe critical warning is set |
| `hardware.storage.reallocated` | warning | Reallocated sectors greater than zero |
| `hardware.storage.pending` | warning | Pending sectors greater than zero |
| `hardware.storage.uncorrectable` | critical | Uncorrectable sectors greater than zero |
| `hardware.gpu.ecc_uncorrected` | critical | Non-zero uncorrected GPU ECC |
| `hardware.gpu.retired_pages` | critical | Pending retired GPU pages |
| `hardware.gpu.temperature` | warning | GPU temperature at or above limit | `QA_HARDWARE_GPU_TEMP_ALERT_C=65` |
| `hardware.gpu.throttle` | warning | GPU throttle currently active |
| `hardware.bmc.sel` | critical / warning | Redfish or IPMI SEL entry at critical / warning severity |
| `hardware.thermal.sensor` | warning | Sensor at or above the lower of its critical point and limit | `QA_HARDWARE_SENSOR_TEMP_ALERT_C=70` |
| `hardware.vendor.log` | warning | Configured firmware/BMC log contains an error signature |
| `hardware.vendor.missing` | critical | No readable vendor log is configured |
| `hardware.coverage` | warning | A required hardware source is limited or unavailable |

Storage checks may report `needs-root`; this is coverage, not an automatic
failure. CXL-specific rasdaemon probes are skipped when no CXL device exists.

## LSM rules

Implemented in `sentinels/lsm.py`.

| Rule | Severity | Trigger |
|---|---|---|
| `lsm.none` | critical | No active LSM is listed |
| `lsm.apparmor.disabled` | warning | AppArmor is present but not enabled |
| `lsm.apparmor.no_profiles` | warning | AppArmor has no readable profiles |
| `lsm.selinux.permissive` | warning | SELinux is permissive, not enforcing |
| `lsm.yama.ptrace_scope` | warning | `kernel.yama.ptrace_scope=0` |
| `lsm.lockdown.none` | warning | Lockdown LSM is active with mode `none` |
| `lsm.ima.policy_missing` | warning | Integrity LSM is active but no IMA policy exists |
| `lsm.state_unreadable` | warning | LSM state cannot be read |
| `lsm.state_changed` | warning | LSM state digest changed from baseline |
| `lsm.apparmor.denial` | warning | AppArmor denials at or above limit | `QA_LSM_DENIAL_ALERT=1` |
| `lsm.selinux.denial` | warning | SELinux denials at or above limit | `QA_LSM_DENIAL_ALERT=1` |

Stale state-based LSM findings are resolved automatically when the condition
clears.

## Security rules

Implemented in `sentinels/security.py`. Policy allowlists and elevation-parent
rules are in `config/security-policy.json`.

| Rule | Severity | Trigger |
|---|---|---|
| `security.root_user_path` | critical | Root process executable or cwd is in a user-writable path |
| `security.root_cmdline_user_path` | critical | Root command line references a user-writable path |
| `security.root_writable_exe` | critical | Root executable is writable by a non-root user |
| `security.root_from_user_parent` | critical | Root process has a non-root parent that is not an allowed elevator |
| `security.root_elevated_session` | warning | Root process has a non-root login uid |
| `security.deleted_exe` | critical for root / warning for non-root | Executable is deleted or anonymous |
| `security.unexpected_uid_user_path` | critical | Non-allowed uid executes user-writable code |
| `security.user_code_tmp` | warning | Non-allowed uid executes from `/tmp`, `/var/tmp`, or `/dev/shm` |
| `security.nonroot_caps` | warning | Non-root process has capabilities outside the policy |
| `security.root_owned_user_state` | warning | Root-owned entries exist under QA state paths |
| `security.audit_root_exec` | critical | Audit exec as root from a user session or user path |
| `security.audit_unexpected_user_exec` | error | Non-allowed uid executes user-writable code |
| `security.audit_priv_change` | critical / warning | Privilege event; critical when euid=0 and auid is a user |
| `security.audit_unavailable` | warning | auditd/ausearch is unavailable or unreadable |

Process-path findings are resolved automatically when the process disappears.
Audit findings depend on the QA audit rules in `root/audit/qa-security.rules`.

## Network rules

Implemented in `sentinels/network.py`. Delta rules compare with the previous
network run.

| Rule | Severity | Trigger |
|---|---|---|
| `network.netplan.permissions` | warning | Netplan file is group/other accessible |
| `network.firewall.ufw_inactive` | warning | UFW is enabled in config but the service is inactive |
| `network.firewall.disabled` | warning | Firewall required by config but none is active |
| `network.interface.down` | error / warning | An uplink is down (error); another addressed interface is down (warning) |
| `network.route.default_missing` | error | A previous default route disappeared |
| `network.vpn.down` | warning | A tunnel disappeared or is not up |
| `network.dns.no_upstream` | warning | Default route exists but no upstream DNS server is configured |
| `network.interface.errors` | warning | Receive/transmit error counter increment | `QA_NETWORK_ERROR_DELTA_ALERT=1` |
| `network.tcp.retrans` | warning | TCP retransmission ratio at or above limit | `QA_NETWORK_TCP_RETRANS_ALERT_PCT=5` |
| `network.conntrack.high` | warning | Conntrack usage at or above limit | `QA_NETWORK_CONNTRACK_ALERT_PCT=90` |

`network.firewall.disabled` is only emitted when
`QA_NETWORK_FIREWALL_REQUIRED=1`. TCP retransmission checks require at least
`QA_NETWORK_TCP_MIN_SEGMENTS=100` outbound segments.

## Portable platform rules (WIP)

Implemented in `sentinels/platform_cycle.py` for Windows and macOS.

| Platform | Rule | Severity | Trigger |
|---|---|---|---|
| Windows | `security.defender_disabled` | critical | Defender antivirus disabled |
| Windows | `security.defender_realtime_off` | error | Defender real-time protection disabled |
| Windows | `security.firewall_disabled` | error | A firewall profile is disabled |
| Windows | `security.bitlocker_off` | warning | BitLocker protection is off |
| Windows | `security.tpm_not_ready` | error | TPM is not ready |
| Windows | `crash.bugcheck` | critical | Bugcheck event 1001 |
| Windows | `crash.application` | warning | Other application crash event |
| macOS | `security.gatekeeper_disabled` | critical | Gatekeeper disabled |
| macOS | `security.sip_disabled` | critical | System Integrity Protection disabled |
| macOS | `security.filevault_off` | warning | FileVault is off |
| macOS | `security.firewall_disabled` | error | Application firewall disabled |
| macOS | `crash.report` | warning | Diagnostic crash report present |

## Runtime and deep-trace checks

Implemented in `sentinels/deep.py` and `sentinels/detect.py`.

| Rule / check | Severity | Trigger |
|---|---|---|
| `deep.ebpf.stale` | warning | A built eBPF loader/object does not match the running kernel or has changed since build |
| eBPF not built | info | `qa status` / `qa preflight`; not a finding by itself |
| layer-2 path unit | info | `qa-sentinel-deep.path` state, root deployment, pending requests |
| deep runs | info | Complete/dry-run/pending layer-2 runs |

`deep.ebpf.stale` resolves automatically after `root/ebpf/build.sh` produces a
matching build stamp. Missing eBPF files are treated as a deployment state, not
a finding.

## Shutdown capture checks

Implemented in `sentinels/shutdown.py`. These are capture patterns; the replay
path classifies the resulting event and queues it through the normal journal
rules.

| Capture rule | Pattern |
|---|---|
| `shutdown.service_start` | `Failed to start` |
| `shutdown.unmount` | `Failed unmounting` / `Failed to unmount` |
| `shutdown.unit_stop` | `Failed to stop` |
| `shutdown.systemd` | Failed finalize, kill, send, wait, enqueue, isolate, or switch |

## Operational checks without finding severity

- `qa preflight` checks the C sampler, journal read access, coredump access,
  crontab, free disk, fault-core integration, Ubuntu compatibility,
  unprivileged posture, fault-core triage directory, network inventory, layer-2
  state, and eBPF build state.
- `qa status` reports last sample/ingest/crash-feed/inventory/hardware/LSM/network
  times, hardware tier, fault-core state, inventory, evidence, ticket drafts,
  triage, layer-1 counts, boots, shutdown capture, correlation, raise gate,
  holds, notifications, layer-2, eBPF, and posture.
- `qa compat --strict` checks the supported Ubuntu baseline.
- `qa legal --check` checks the legal register and document set.
- `qa platform` reports platform capabilities and finding namespaces.
- `qa crosscheck` compares drafts on disk with currently reproducible issues and
  reports drift; it is a review signal, not a severity finding.
- `qa hardware check` reports missing required tools and scoped-out sources; it
  exits non-zero for a missing required source.

## Rule lifecycle

1. Collect: journal, crashes, samples, hardware, LSM, security, network, boot and
   fault-core data.
2. Classify: apply the rule tables above; attach fingerprint, severity, subject,
   detail, and case association.
3. Deduplicate: update an existing fingerprint's `last_ts`/count; create a new
   finding only for a new fingerprint.
4. Escalate: critical findings may queue a layer-2 request, respecting
   `QA_DEEP_AUTO` and `QA_DEEP_REQUEST_COOLDOWN_S`.
5. Draft: findings become vendor/local ticket drafts; nothing is submitted
   automatically.
6. Notify: staged `raise/` tickets and ready correlations can queue desktop
   notifications; draft digests are intentionally silent.
7. Resolve: hardware, LSM, security, runtime and coverage findings resolve when
   their condition clears; boot and journal findings remain for review.
