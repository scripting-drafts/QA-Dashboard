# QA VM (Windows 11 Pro)

Per-machine MSI is pushed over qemu-guest-agent; no SMB/SSH/share.
Provision: `bash scripts/qa-vm/provision.sh` (`--media-only`, `--recreate`).
Deploy: `bash scripts/qa-vm/deploy.sh <app.msi> [--clean]`
Guest: `qa` admin, RDP on, NAT network, TPM 2.0 + Secure Boot.
Result: `C:\qa\deploy.json`; installer log `C:\qa\msi.log`.
Baseline: create `qa-baseline` after a clean tools install; `--clean` reverts to it.
Credentials live in `~/qa-vm/creds/vm.env` (600, never commit).
Runner labels: `self-hosted`, `linux`, `x64`, `qa-vm`.
