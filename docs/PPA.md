# Existing Ubuntu Backup PPA

The QA packages are published in the existing `toomanypatterns` archive:

```text
ppa:toomanypatterns/ubuntu-backup
```

This is a shared archive; it can carry `ubuntu-backup`, `qa-sentinels` and
`qa-dashboard` together. The Dashboard Recommends the engine; the QA packages
remain separately installable.

## One-time Launchpad setup

The Launchpad account is `toomanypatterns`. It currently has no registered
OpenPGP key, and PPA uploads require one.

1. Register the signing key:

   ```bash
   gpg --list-secret-keys --keyid-format long
   gpg --fingerprint creative.gsp@gmail.com
   ```

   Open `https://launchpad.net/~toomanypatterns/+editpgpkeys`, add the chosen
   fingerprint, and confirm the email challenge. The `F319…` key is already on
   `keyserver.ubuntu.com`; wait until Launchpad shows it as confirmed.

2. Install the upload tools:

   ```bash
   sudo apt install dput devscripts
   ```

3. The existing `~/.dput.cf` profile is enough:

   ```ini
   [ubuntu-backup]
   fqdn = ppa.launchpad.net
   method = ftp
   incoming = ~toomanypatterns/ubuntu/ubuntu-backup/
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
  ~/qa-sentinels_1.1.0_source.changes
debsign -kF104A3F1CE9A23540AEB8F24F31978E49E85DDCA \
  ~/qa-dashboard_0.3.1_source.changes
```

## Upload

```bash
dput ubuntu-backup ~/qa-sentinels_1.1.0_source.changes
dput ubuntu-backup ~/qa-dashboard_0.3.1_source.changes
```

`dput` refuses a second upload of the same `.changes` file unless forced. Use
`dput -f ubuntu-backup …` when retrying after a Launchpad rejection:

```bash
dput -f ubuntu-backup ~/qa-sentinels_1.1.0_source.changes
dput -f ubuntu-backup ~/qa-dashboard_0.3.1_source.changes
```

Watch the build queue:

```text
https://launchpad.net/~toomanypatterns/+archive/ubuntu/ubuntu-backup/+packages
```

When both packages show `Published`, install:

```bash
sudo add-apt-repository ppa:toomanypatterns/ubuntu-backup
sudo apt update
sudo apt install qa-sentinels
sudo apt install qa-sentinels qa-dashboard
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
