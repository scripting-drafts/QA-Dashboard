# APT distribution

QA Sentinels and QA Dashboard are published as **two separate binary
packages**:

```text
qa-sentinels   engine, CLI, evidence store
qa-dashboard   Electron GUI (Recommends qa-sentinels)
```

The canonical origin is the dedicated Launchpad PPAs:

```text
ppa:toomanypatterns/qa-sentinels
ppa:toomanypatterns/qa-dashboard
```

## Install from the PPAs

```bash
sudo add-apt-repository ppa:toomanypatterns/qa-sentinels
sudo add-apt-repository ppa:toomanypatterns/qa-dashboard
sudo apt update
```

Install the engine only, the GUI plus engine, or the GUI alone:

```bash
sudo apt install qa-sentinels
sudo apt install qa-sentinels qa-dashboard
sudo apt install --no-install-recommends qa-dashboard
```

`qa-dashboard` Recommends `qa-sentinels`; `qa-sentinels` is standalone and
does not depend on the Dashboard. The packages can be installed, upgraded and
removed separately. Removing `qa-sentinels` leaves the GUI installed but
without an engine, so remove both if the whole stack is no longer wanted.

Building and uploading the source packages is documented in
[`PPA.md`](PPA.md).

## Optional self-hosted signed repository

Only for mirrors, air-gapped sites or pinned deployments. The PPA stays
canonical; do not publish a self-hosted copy as a second advertised origin.

### Build the packages

From the two source repositories:

```bash
(cd ~/QA-Sentinels && dpkg-buildpackage -b -us -uc)
(cd ~/QA-Dashboard && dpkg-buildpackage -b -us -uc)
```

The resulting files are written to the parent directories:

```text
qa-sentinels_1.1.0_amd64.deb
qa-dashboard_0.3.1_amd64.deb
```

### Repository layout

Any static host or local path works:

```text
qa-dashboard-archive-key.asc
pool/main/q/qa-sentinels/qa-sentinels_1.1.0_amd64.deb
pool/main/q/qa-dashboard/qa-dashboard_0.3.1_amd64.deb
dists/stable/main/binary-amd64/Packages
dists/stable/main/binary-amd64/Packages.gz
dists/stable/Release
dists/stable/InRelease
```

Copy the `.deb` files into their pool directories, then regenerate metadata
from the repository root:

```bash
dpkg-scanpackages pool /dev/null > dists/stable/main/binary-amd64/Packages
gzip -9nc dists/stable/main/binary-amd64/Packages \
  > dists/stable/main/binary-amd64/Packages.gz
apt-ftparchive \
  -o APT::FTPArchive::Release::Origin="QA Dashboard" \
  -o APT::FTPArchive::Release::Label="QA Dashboard" \
  -o APT::FTPArchive::Release::Suite=stable \
  -o APT::FTPArchive::Release::Codename=stable \
  -o APT::FTPArchive::Release::Architectures=amd64 \
  -o APT::FTPArchive::Release::Components=main \
  release dists/stable > /tmp/Release
mv /tmp/Release dists/stable/Release
```

### Signing key

Use a dedicated archive key; do not reuse the maintainer's personal key. One
possible setup:

```bash
export GNUPGHOME="$HOME/.gnupg-qa-dashboard-archive"
install -d -m 0700 "$GNUPGHOME"
gpg --quick-generate-key "QA Dashboard Archive <creative.gsp@gmail.com>" rsa4096 sign 5y
export KEY=$(gpg --list-secret-keys --with-colons | awk -F: '/^sec:/ {print $5; exit}')
gpg --armor --export "$KEY" > qa-dashboard-archive-key.asc
```

Sign the repository metadata:

```bash
GNUPGHOME="$HOME/.gnupg-qa-dashboard-archive" \
  gpg --batch --yes --clearsign -u "$KEY" \
  -o dists/stable/InRelease dists/stable/Release
```

Keep the private key off the published tree and backed up securely.

### Install from the self-hosted repository

```bash
curl -fsSL https://<host>/qa-dashboard-archive-key.asc \
  | sudo gpg --dearmor -o /usr/share/keyrings/qa-dashboard-archive-keyring.gpg

echo 'deb [signed-by=/usr/share/keyrings/qa-dashboard-archive-keyring.gpg] https://<host>/ stable main' \
  | sudo tee /etc/apt/sources.list.d/qa-dashboard.list

sudo apt update
```

## Local testing without signing

For a temporary local repository, `[trusted=yes]` avoids signing:

```text
deb [trusted=yes] file:/tmp/qa-apt-repo stable main
```

Do not use `trusted=yes` for a public repository.
