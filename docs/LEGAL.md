# Legal and release policy — QA Dashboard

This document is an inventory and release checklist, not legal advice.

## Required artifacts

- `LICENSE` — full MIT text.
- `THIRD-PARTY-NOTICES.md` — bundled Electron/Chromium, Node.js, and build dependencies.
- `legal/manifest.json` — machine-readable compliance register.
- `debian/copyright` — Debian copyright and license stanzas.
- `docs/PRIVACY.md` — local data handling and retention.
- `CONTRIBUTING.md` — inbound licensing and DCO.
- `SECURITY.md` — private vulnerability reporting.

## Before every release

1. Run `npm test` and `qa-license-scanner validate legal/manifest.json`.
2. Update `lastReviewed`, `reviewedVersion`, and `reviewedComponents`.
3. Confirm the source installer and the `.deb` include `LICENSE`,
   `THIRD-PARTY-NOTICES.md`, `docs/LEGAL.md`, and `legal/manifest.json`.
4. Re-check the Electron and Chromium notices after an Electron upgrade.
5. Run the third-party scanner against the repository and review blocked or
   unknown findings.
6. Re-read the trademark, export, and accessibility notes below.

## Trademarks and affiliation

QA Dashboard is an independent project by Gerard Sala. Ubuntu, Canonical,
Launchpad, Debian, GNOME, Electron, Chromium, Node.js, and other names are
trademarks of their respective owners and are used descriptively.

The `ppa:toomanypatterns/qa-dashboard` and
`ppa:toomanypatterns/qa-sentinels` archives are distribution channels. They are
not an endorsement by Ubuntu, Canonical, Debian, GNOME, the Electron project,
or the Chromium project. No affiliation or endorsement is claimed.

## Export and cryptography

QA Dashboard adds no cryptographic code of its own. The bundled Electron and
Chromium runtime include standard TLS and cryptographic functionality. This is
mass-market desktop software distributed publicly; it contains no
export-controlled implementation, and no export notification has been filed.
Reassess the classification before distributing in jurisdictions that require
notification.

## Accessibility

Baseline review completed: semantic HTML landmarks and headings, labelled form
controls, ARIA roles for tabs, filters, dialogs, and status messages, visible
keyboard focus outlines, keyboard-reachable dialog actions, and light/dark
palettes with contrast-aware tokens. No formal WCAG 2.2 audit or screen-reader
certification is claimed. Repeat the review if public-sector distribution is
targeted.

## Distribution notes

- MIT requires the copyright and permission notice to accompany copies.
- Electron and Chromium carry their own third-party notices; do not strip
  `electron-LICENSE` or `chromium-LICENSES.html` from an installed package.
- The register is validated with the QA License Scanner schema. The standalone
  viewer lives in the separate private QA-License-Legal repository.

## Review cadence

Review on every release and at least annually. The register should report no
pending review items and no version drift before a package is published.
