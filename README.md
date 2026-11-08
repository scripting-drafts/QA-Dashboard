# QA Desktop
Modular GTK4 desktop applications for **Quality Assurance Sentinels**, **Malware Scan**, and **QA SIEM**.
Per-app launchers open one module without the suite sidebar: QA Sentinels, Malware Scan, QA SIEM.
A small friendly top-bar tray icon lists the same three apps: Sentinels, Malware Scan, SIEM, Quit.
Install with `./install.sh`; it enables the Ubuntu AppIndicators extension and registers an autostart tray.
Each app drives the existing CLI or local HTTP API; engines and data formats stay unchanged.
Sentinels runs `qa status`, `cycle`, `findings`, `logs`, and `evidence`.
Malware Scan streams JSONL findings, supports optional ClamAV/YARA, and can quarantine.
SIEM reads health, stats, alerts, and events; alert acknowledgement uses the protected token file.
Settings override auto-detected commands, repository paths, SIEM URL, and token path.
