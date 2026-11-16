# Legal and release policy — QA Dashboard

This document is an inventory and release checklist, not legal advice.

## Required artifacts

- `LICENSE` — full MIT text.
- `THIRD-PARTY-NOTICES.md` — bundled Electron/Chromium and build dependencies.
- `legal/manifest.json` — machine-readable compliance register.
- `debian/copyright` — Debian copyright and license stanzas.
- `docs/PRIVACY.md` — local data handling and retention.
- `CONTRIBUTING.md` — inbound licensing and DCO.
- `SECURITY.md` — private vulnerability reporting.

## Before every release

1. Run `npm test`; the legal tests fail if a required artifact or packaging
   reference is missing.
2. Validate `legal/manifest.json` with `qa-license-scanner validate`.
3. Update `lastReviewed`, `reviewedVersion`, and `reviewedComponents` after
   reviewing component versions.
4. Re-check Electron/Chromium notices after an Electron upgrade.
5. Confirm the `.deb` installs `LICENSE`, `THIRD-PARTY-NOTICES.md`, the legal
   manifest, and the Electron/Chromium license texts under `/usr/share/doc`.
6. Review pending items: export/cryptography, trademark/affiliation, and
   accessibility if targeting public-sector distribution.
7. Run the third-party scanner against the repository and review blocked or
   unknown findings.

## Review cadence

Review on every release and at least annually. The Legal window warns when the
manifest version or Electron baseline is stale.

## Distribution notes

- The PPA is a shared Launchpad archive; no Ubuntu, Canonical, GNOME, Electron,
  or Chromium endorsement is claimed.
- MIT requires the copyright and permission notice to accompany copies.
- Electron and Chromium carry their own third-party notices; do not strip them.
- The application includes cryptographic functionality through Electron and
  Chromium. Confirm export/import notification obligations for the jurisdictions
  where you distribute it.
