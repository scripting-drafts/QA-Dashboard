# QA Dashboard
Electron dashboard for **QA Sentinels**, **Malware Scan**, and **QA SIEM**.
Linux, Windows, and macOS releases all use this Electron core.
Use the **QA Dashboard** favourite or standalone launcher to open the compact Overview.
Module launchers in the applications menu open Sentinels, Malware Scan, or SIEM directly.
Install with `./install.sh` (Node.js, npm); it installs the dashboard and module launchers.
There is no tray or top-bar icon; repeated launches focus the Dashboard window.
Sentinels runs the existing `qa` CLI and streams status, findings, logs, and evidence output.
Malware Scan streams JSONL findings, coverage metrics, optional ClamAV/YARA, and quarantine data.
SIEM reads health, alerts, and events through the protected local API token; settings override paths.
