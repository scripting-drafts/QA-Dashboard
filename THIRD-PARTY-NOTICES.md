# Third-party notices — QA Dashboard

QA Dashboard is licensed under the MIT License. See `LICENSE`.

QA Dashboard bundles Electron for the desktop runtime. Electron includes
Chromium, Node.js, and other third-party components. The full Electron license
and Chromium third-party notice ship with the application:

- `node_modules/electron/dist/LICENSE` — Electron, MIT
- `node_modules/electron/dist/LICENSES.chromium.html` — Chromium and third-party components
- `node_modules/electron/LICENSE` — Electron package license

In an installed Debian package these are additionally installed as
`/usr/share/doc/qa-dashboard/electron-LICENSE` and
`/usr/share/doc/qa-dashboard/chromium-LICENSES.html`.

## Components

| Component | Scope | License | Notice |
| --- | --- | --- | --- |
| QA Dashboard | project | MIT | `LICENSE` |
| Electron 45.2.3 | shipped | MIT | `node_modules/electron/dist/LICENSE` |
| Chromium (Electron 45.2.3) | shipped | BSD-3-Clause and third-party licenses | `node_modules/electron/dist/LICENSES.chromium.html` |
| Node.js 24.22.2 (Electron runtime) | shipped | MIT, Copyright Node.js contributors | Electron distribution; https://github.com/nodejs/node/blob/main/LICENSE |
| npm build dependencies | build | MIT, ISC, Apache-2.0 | `package-lock.json`, package metadata |
| QA Dashboard artwork | asset | MIT | `assets/` |
| GNOME theme extension | shipped | MIT | `gnome-extension/` |

## Attribution conventions

Copyright notices and license texts of bundled components are preserved. QA
Dashboard does not relicense third-party code. When upgrading Electron,
re-check the bundled `LICENSES.chromium.html` and the Electron `LICENSE`.

## Trademarks

Electron, Chromium, Ubuntu, Launchpad, GNOME, and other names are trademarks of
their respective owners. They are used descriptively. No affiliation or
endorsement is claimed.
