# Dedicated QA PPAs

QA Sentinels and QA Dashboard are published in separate `toomanypatterns`
archives:

```text
qa-sentinels   ppa:toomanypatterns/qa-sentinels
qa-dashboard   ppa:toomanypatterns/qa-dashboard
```

`ppa:toomanypatterns/ubuntu-backup` remains the archive for Ubuntu Backup and
does not carry the QA packages. The Dashboard Recommends the engine; both
packages remain separately installable.

## One-time Launchpad setup

The Launchpad account is `toomanypatterns`. The signing key is already
registered:

```text
F104A3F1CE9A23540AEB8F24F31978E49E85DDCA
```

Install the upload tools:

```bash
sudo apt install dput devscripts
```

Keep one profile per archive in `~/.dput.cf`:

```ini
[ubuntu-backup]
fqdn = ppa.launchpad.net
method = ftp
incoming = ~toomanypatterns/ubuntu/ubuntu-backup/
login = anonymous
allow_unsigned_uploads = 0

[qa-sentinels]
fqdn = ppa.launchpad.net
method = ftp
incoming = ~toomanypatterns/ubuntu/qa-sentinels/
login = anonymous
allow_unsigned_uploads = 0

[qa-dashboard]
fqdn = ppa.launchpad.net
method = ftp
incoming = ~toomanypatterns/ubuntu/qa-dashboard/
login = anonymous
allow_unsigned_uploads = 0
```

## Build source packages

PPAs accept source uploads, not binary `.deb` files. From each repository:

```bash
(cd ~/QA-Sentinels && dpkg-buildpackage -S -sa)
(cd ~/QA-Dashboard && dpkg-buildpackage -S -sa)
```

This produces `.dsc`, source tarballs and `_source.changes` in the parent
directories. The Dashboard source tarball intentionally includes
`node_modules` because Launchpad build machines have no network access; the
binary package bundles Electron.

Sign the changes files with the registered key if `dpkg-buildpackage` did not:

```bash
debsign -kF104A3F1CE9A23540AEB8F24F31978E49E85DDCA \
  ~/qa-sentinels_1.4.1_source.changes
debsign -kF104A3F1CE9A23540AEB8F24F31978E49E85DDCA \
  ~/qa-dashboard_0.5.9_source.changes
```

## Upload

Each package goes to its own archive:

```bash
dput qa-sentinels ~/qa-sentinels_1.4.1_source.changes
dput qa-dashboard ~/qa-dashboard_0.5.9_source.changes
```

The release scripts enforce this automatically:

```bash
(cd ~/QA-Sentinels && scripts/release.sh)
(cd ~/QA-Dashboard && scripts/release.sh)
```

`dput` refuses a second upload of the same `.changes` file unless forced. Use
`dput -f qa-sentinels …` or `dput -f qa-dashboard …` when retrying after a
Launchpad rejection.

Watch the build queues:

```text
https://launchpad.net/~toomanypatterns/+archive/ubuntu/qa-sentinels/+packages
https://launchpad.net/~toomanypatterns/+archive/ubuntu/qa-dashboard/+packages
```

When both packages show `Published`, install:

```bash
sudo add-apt-repository ppa:toomanypatterns/qa-sentinels
sudo add-apt-repository ppa:toomanypatterns/qa-dashboard
sudo apt update
sudo apt install qa-sentinels
sudo apt install qa-dashboard
```

## Separate and combined installs

```bash
# Engine only
sudo apt install qa-sentinels

# Engine + GUI
sudo apt install qa-sentinels qa-dashboard

# GUI only (no engine; dashboard has nothing to read)
sudo apt install --no-install-recommends qa-dashboard
```

`qa-dashboard` Recommends `qa-sentinels`; `qa-sentinels` is standalone and
does not depend on the Dashboard. Removing the engine leaves the GUI
installed but non-functional.

## Published Ubuntu series

Both PPAs publish the same upstream base version across the tested series.
Stonking previews use the same base version only when rebuilt explicitly.

| Series | Release | Status |
|---|---|---|
| `jammy` | 22.04 LTS | tested baseline |
| `noble` | 24.04 LTS | supported |
| `resolute` | 26.04 LTS | supported |
| `stonking` | 26.10 | published, untested preview |

`devel` is not a PPA series or a support status. Use the codename for the
release; `add-apt-repository` selects it automatically.

Enable `jammy`, `noble`, and `resolute` in each Launchpad PPA before uploading.
Stonking is not part of the default release set. The script builds it only
when `SERIES=stonking` is passed explicitly, and it refuses to build if a
requested series is missing.

No runtime testing on 26.10 is planned in the near term. Launchpad build
success is not runtime testing. Treat stonking packages as preview builds and
use 22.04, 24.04, or 26.04 for tested deployments. Stonking will lag the
tested series until a preview upload is requested explicitly.

Each series receives a collision-free, upgrade-safe Debian version:

```text
qa-dashboard 0.5.9-0ubuntu1~jammy1
qa-dashboard 0.5.9-0ubuntu1~noble1
qa-dashboard 0.5.9-0ubuntu1~resolute1
qa-dashboard 0.5.9-0ubuntu1~stonking1
```

The package version without the series suffix remains in `package.json`,
`package-lock.json`, and `README.md`.

Release both packages from the umbrella:

```bash
scripts/release.sh --package qa-dashboard --check
scripts/release.sh --package qa-sentinels --check

scripts/release.sh --package qa-dashboard
scripts/release.sh --package qa-sentinels
```

For a partial upload, limit the series explicitly:

```bash
SERIES="jammy" scripts/release.sh --package qa-dashboard
```

To build the untested 26.10 preview explicitly:

```bash
SERIES="stonking" scripts/release.sh --package qa-dashboard
```

The script derives the package name from `debian/changelog`, verifies it against
`--package`, checks every requested series' `Packages.gz`, and uploads with
`dput` only after all requested series are enabled. The two PPAs remain
separate:

```text
ppa:toomanypatterns/qa-dashboard
ppa:toomanypatterns/qa-sentinels
```

## Published revisions

Each series can carry a higher Ubuntu revision if a build must be replaced:

```bash
SERIES="noble" REVISION=2 scripts/release.sh --package qa-dashboard
```

`--check` accepts any already-published revision with the same base version and
series suffix. Use `REVISION=N` only when uploading a replacement.

Current published state:

| Package | jammy | noble | resolute | stonking (untested) |
|---|---|---|---|---|
| qa-dashboard | `0.5.9-0ubuntu16~jammy1` | `0.5.9-0ubuntu16~noble1` | `0.5.9-0ubuntu16~resolute1` | `0.5.9-0ubuntu16~stonking1` |
| qa-sentinels | `1.4.2-0ubuntu5~jammy1` | `1.4.2-0ubuntu5~noble1` | `1.4.2-0ubuntu5~resolute1` | `1.4.2-0ubuntu5~stonking1` |
