# Downloads

## Linux

The Linux packages remain in their dedicated PPAs:

```bash
sudo add-apt-repository ppa:toomanypatterns/qa-dashboard
sudo add-apt-repository ppa:toomanypatterns/qa-sentinels
sudo apt update
sudo apt install qa-dashboard qa-sentinels
```

The PPAs also publish Ubuntu 26.10 (stonking) builds. They are untested
previews, are not part of the default release set, and should not be used for
production. Use 22.04, 24.04, or 26.04 for tested deployments.

`qa-dashboard` recommends `qa-sentinels`; the engine remains a separate
package. The Debian packaging and PPA paths are unchanged by the umbrella
repository.

## Windows

Pre-release test builds:

- `QA-Dashboard-<version>-x64-win.zip`
- `QA-Dashboard-<version>-arm64-win.zip`
- `QA-Dashboard-<version>-x64-win-logs.zip`
- `QA-Dashboard-<version>-arm64-win-logs.zip`

The Windows build is unsigned until an OV/Azure signing identity is configured.
QA Sentinels is bundled in the QA Set installer, not installed separately.

## macOS

Pre-release test builds:

- `QA-Dashboard-<version>-x64-mac.zip`
- `QA-Dashboard-<version>-arm64-mac.zip`
- `QA-Dashboard-<version>-x64-mac-logs.zip`
- `QA-Dashboard-<version>-arm64-mac-logs.zip`

The macOS build is unsigned and not notarized until a Developer ID is
configured. QA Sentinels is bundled in the QA Set installer.

## Versions

See `contracts/versions.json` for the Dashboard, Sentinels, Electron and Python
versions shipped by a release. Test builds remain downloadable beside the
signed/notarized GA artifacts when signing is enabled.
