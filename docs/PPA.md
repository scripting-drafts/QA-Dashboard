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
