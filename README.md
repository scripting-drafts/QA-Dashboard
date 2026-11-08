# QA Desktop
Modular GTK4 desktop suite for **Quality Assurance Sentinels**, **Malware Scan**, and **QA SIEM**.
Access is a single small top-bar tray icon; no application-menu icons are installed.
Tray menu: Open QA Desktop, Sentinels, Malware Scan, SIEM, Quit.
Install with `./install.sh`; it enables the Ubuntu AppIndicators extension and registers an autostart tray.
Each module drives the existing CLI or local HTTP API; engines and data formats stay unchanged.
Sentinels runs `qa status`, `cycle`, `findings`, `logs`, and `evidence`.
Malware Scan streams JSONL findings, supports optional ClamAV/YARA, and can quarantine.
SIEM reads health, stats, alerts, and events; alert acknowledgement uses the protected token file.
Settings select module availability and override auto-detected command, repository, URL, and token paths.
