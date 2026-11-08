# QA Desktop
Modular GTK4 desktop suite for **Quality Assurance Sentinels**, **Malware Scan**, and **QA SIEM**.
Each module drives the existing CLI or local HTTP API; engines and data formats stay unchanged.
Install with `./install.sh` (or `./install.sh` with `PREFIX=/usr/local`).
Launch **QA Desktop** for the suite, or the three per-module menu entries.
Sentinels runs `qa status`, `cycle`, `findings`, `logs`, and `evidence`.
Malware Scan streams JSONL findings, supports optional ClamAV/YARA, and can quarantine.
SIEM reads health, stats, alerts, and events; alert acknowledgement uses the protected token file.
Settings select module availability and override auto-detected command, repository, URL, and token paths.
Requires Python 3, PyGObject, GTK 4.6+, and the installed engines; no shell execution.
