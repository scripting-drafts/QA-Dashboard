# QA Dashboard
Electron dashboard for **QA Sentinels**, **Malware Scan**, and **QA SIEM**.
A compact **Overview** is the default; click the monochrome GNOME top-bar icon to open it.
The top-bar icon has no menu; per-app launchers open each module window directly.
Install with `./install.sh`; it installs Electron and the `qa-dashboard@local` GNOME extension.
Close windows normally; there is no Quit item. Linux targets GNOME; Windows/macOS ports come later.
Sentinels runs the existing `qa` CLI and streams status, findings, logs, and evidence output.
Malware Scan streams JSONL findings, coverage metrics, optional ClamAV/YARA, and quarantine data.
SIEM reads health, alerts, and events through the protected local API token.
Requires Node.js, npm, GNOME Shell, and the existing QA tools; settings override auto-detected paths.
