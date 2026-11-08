# QA Dashboard
Electron dashboard for **QA Sentinels**, **Malware Scan**, and **QA SIEM**.
A compact **Overview** is the default; each module opens in its own window, reachable from the monochrome tray icon.
Per-app launchers open the corresponding module window.
Install with `./install.sh`; it installs Electron locally and registers the tray autostart.
The tray menu has no Quit option; close individual windows and the tray stays available.
Sentinels runs the existing `qa` CLI and streams status, findings, logs, and evidence output.
Malware Scan streams JSONL findings, coverage metrics, optional ClamAV/YARA, and quarantine data.
SIEM reads health, alerts, and events through the protected local API token.
Requires Node.js, npm, and the existing QA tools; settings override auto-detected paths.
