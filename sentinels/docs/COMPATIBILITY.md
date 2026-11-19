# Compatibility

QA Sentinels targets Ubuntu LTS and interim releases through 26.10.

## Baseline

- Ubuntu 22.04.5 LTS (tested)
- Python 3.10+
- SQLite 3.37+
- systemd 249+ (cron remains supported)
- Linux kernel 5.15+
- C11 compiler and `make` for the sampler

The Python implementation uses the standard library only. The C sampler and
optional eBPF tracer are rebuilt on the host.

## Upgrade path

| Release | Status |
|---|---|
| 22.04 LTS | baseline, tested |
| 24.04 LTS | supported |
| 26.04 LTS | supported |
| 26.10 | supported |

Ubuntu 24.10, 25.04, and 25.10 are end-of-life and are not PPA targets.

## Verify a host

```bash
./bin/qa compat
./bin/qa compat --strict
./bin/qa preflight
```

`compat` reports the Ubuntu release, Python, SQLite, systemd and kernel against
the documented minimums. `--strict` exits non-zero outside the baseline.
`preflight` includes the same compatibility check.

## Upgrade procedure

1. Back up `var/`, `config/`, and `evidence/`.
2. Run `./bin/qa compat --strict`.
3. Run `python3 -m unittest discover -s tests`.
4. Rebuild the sampler: `make -C src install`.
5. Reinstall the scheduler: `sudo ./root/install-system.sh --takeover`
   (or keep the cron schedule).
6. Rebuild optional eBPF/perf artifacts for the new kernel.
7. Run `./bin/qa preflight` and `./bin/qa cycle`.

## Release-specific notes

- **Python 3.13/3.14:** the code avoids removed `distutils`/`imp` APIs and uses
  stable `argparse`, `sqlite3`, `urllib`, `ssl`, and `datetime` interfaces.
- **systemd:** unit files use directives available in 249 and later. Keep the
  capability-scoped `qa-sentinel.service` rather than running the cycle as root.
  Ubuntu 24.04 (Noble) ships systemd 255 and 26.04 (Resolute) ships 259; both
  are tested. Newer versions remain supported by the 249+ baseline until a
  release-specific check is needed.
- **SysV / openipmi:** `openipmi` is an LSB/SysV init script, not a native
  systemd unit. The cutoff is inferred from systemd itself, not from a release
  version supplied at install time: systemd 249 (jammy) keeps the SysV/openipmi
  path, while systemd 250+ (all later releases, including Noble, Resolute and
  Stonking) assumes the generator is unavailable. On those systems, `Failed to start LSB:` is ignored and inventory
  records `sysv-failed/openipmi.service` instead of a systemd failure. IPMI is
  read through `ipmitool`; `openipmi` is not required.
- **eBPF:** the tracer is kernel-specific. `qa deep` checks the build stamp and
  refuses a stale object; rebuild after every kernel change.
- **LSM:** the root LSM helper is optional and reports unavailable securityfs
  state instead of inventing it.
- **Network:** `ip` and `ss` are required for full coverage; `resolvectl`,
  `nmcli`, `iw`, `wg`, `nft`, `iptables-save` and `firewall-cmd` are optional
  and recorded as unavailable or needs-root, never as a failed cycle.
- **NVIDIA/lockdown:** do not add `lockdown=integrity` unless all required
  modules are signed; the installer does not enable it by default.

## Limits

The project does not vendor a Python runtime or kernel modules. A release
upgrade must be validated on the target host because journal, coredump, perf,
AppArmor, IMA, and firmware interfaces can change.
