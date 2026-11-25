# QA Dashboard pre-release

Version: 0.5.16
Status: Unsigned test build. Not for sale. Do not redistribute.
Date: 2026-11-25

## What this build is

- Packaging and UI test build of the Electron Dashboard.
- Compatible with QA Sentinels 1.5.1, including the network/connectivity tier and ticket attribution.
- No commercial license code, activation, TPM/Secure Enclave binding, or device limit.
- No seller entity, EULA, privacy policy, or storefront is included.
- QA Sentinels is Linux-only at this stage. On Windows and macOS the Dashboard
  starts, but Sentinels-backed views will report that the CLI is unavailable.

## Test targets

- Windows 11 x64 or ARM64.
- macOS 13 or later, Intel or Apple Silicon.

Windows 10 and macOS 12 or earlier are unsupported.

## Windows install

Use either the per-user installer or the portable ZIP:

1. Installer: run `QA-Dashboard-Setup-0.5.16-<arch>.exe`.
2. Portable: unzip `QA-Dashboard-0.5.16-<arch>-win.zip` and run
   `QA Dashboard.exe`.
3. SmartScreen will warn because the build is unsigned. Choose **More info**,
   then **Run anyway**.
4. The installer is per-user and does not require administrator rights.

## macOS install

Use the DMG when it is available, or the ZIP:

1. DMG: open `QA-Dashboard-0.5.16-<arch>-mac.dmg` and drag **QA Dashboard**
   to **Applications**.
2. ZIP: unzip `QA-Dashboard-0.5.16-<arch>-mac.zip` and drag
   **QA Dashboard.app** to **Applications**.
3. The build is unsigned and not notarized. On first launch, right-click the app
   and choose **Open**, or run:
   `xattr -dr com.apple.quarantine "/Applications/QA Dashboard.app"`
4. Launch **QA Dashboard** from Applications.

## Smoke test

- [ ] `--version` prints `0.5.16` and exits.
- [ ] App launches without a crash.
- [ ] Overview, Database, Tickets, and Sentinels windows open.
- [ ] Settings opens and saves.
- [ ] About shows version `0.5.16`.
- [ ] Closing all windows exits the process.
- [ ] No commercial license prompt appears.
- [ ] On Linux with QA Sentinels 1.5.1, Overview shows network tier/state.
- [ ] On Windows/macOS, the Sentinels state clearly reports unavailable.

## Reporting

Record the OS version, architecture, artifact name, and the first error or
screenshot. Do not include personal data, credentials, or production evidence.

## Checksums

Verify the artifact against `SHA256SUMS` before installing.
