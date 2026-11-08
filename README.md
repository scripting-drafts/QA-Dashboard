# QA Dashboard
Electron dashboard for **QA Sentinels**, **Malware Scan**, and **QA SIEM** in one window with an Overview and module views.
A monochrome dashboard tray icon opens the unified QA Dashboard.
Per-app launchers open the same dashboard focused on Sentinels, Malware Scan, or SIEM.
Install with `./install.sh`; it installs Electron locally and registers the tray autostart.
The tray menu has no Quit option; close the window to keep the dashboard in the tray.
Sentinels runs the existing `qa` CLI and streams status, findings, logs, and evidence output.
Malware Scan streams JSONL findings, coverage metrics, optional ClamAV/YARA, and quarantine data.
SIEM reads health, alerts, and events through the protected local API token.
Requires Node.js, npm, and the existing QA tools; settings override auto-detected paths.
