# QA Dashboard
Electron dashboard for **QA Sentinels** and **QA SIEM**.
Linux, Windows, and macOS releases use this Electron core with a TaiG-inspired teal interface that follows the desktop light/dark setting, including the favourite icon.
Use the **QA Dashboard** favourite or standalone launcher to open the compact Overview.
Module launchers in the applications menu open QA Sentinels or SIEM directly.
Install with `./install.sh` (Node.js, npm); it installs the dashboard and module launchers.
No tray or top-bar icon; repeated launches focus the Dashboard; QA Sentinels Overview and SIEM auto-refresh every 10 seconds. The installed Sentinel systemd timer or cron owns the cycle; the Dashboard keeps a 10-minute in-app fallback only when neither exists.
Settings are module-specific; QA Sentinels logs run in the background and stream to their own window. QA Sentinels runs the existing `qa` CLI.
QA Sentinels opens a read-only Database for `sentinels.db` with a table sidebar, SQL console, filters, and an all-findings base view; its Overview window merges status and the ticket board in tabs.
SIEM reads health, alerts, and events through the protected local API token.
