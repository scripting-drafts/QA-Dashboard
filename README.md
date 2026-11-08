# QA Dashboard
Electron dashboard for **QA Sentinels**, **Malware Scan**, and **QA SIEM**.
Linux, Windows, and macOS releases all use this Electron core.
A compact **Overview** is the default; click the monochrome ouroboros top-bar icon to open it.
The top-bar icon has no menu; per-app launchers open each module window directly.
Install with `./install.sh` (Node.js, npm, GNOME Shell); it installs the `qa-dashboard@local` extension.
Close windows normally; there is no Quit item.
Sentinels runs the existing `qa` CLI and streams status, findings, logs, and evidence output.
Malware Scan streams JSONL findings, coverage metrics, optional ClamAV/YARA, and quarantine data.
SIEM reads health, alerts, and events through the protected local API token; settings override paths.
