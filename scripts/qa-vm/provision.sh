#!/usr/bin/env bash
# Rebuild the QA Windows VM from scratch: unattended ISO + QATOOLS media.
# Usage: provision.sh [--media-only|--recreate]
#   --media-only  rebuild the QATOOLS ISO and leave the domain alone
#   --recreate    destroy the domain and its qcow2, then recreate + install
# Idempotent: only defines the domain if it does not exist.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")" && pwd)
ISO=${WIN_ISO:-$HOME/ISOs/Win11_26H2_Consumer_x64_en-us.iso}
DOMAIN=${VM_DOMAIN:-win11}
URI=${LIBVIRT_URI:-qemu:///system}
CRED=${VM_CRED:-$HOME/qa-vm/creds/vm.env}
MEDIA=${VM_MEDIA:-$HOME/qa-vm/media}
CACHE=${VM_CACHE:-$HOME/qa-vm/cache}
TOOLS=$MEDIA/tools
TOOLS_ISO=${TOOLS_ISO:-$HOME/ISOs/qa-tools.iso}
VIRTIO_ISO=${VIRTIO_ISO:-$CACHE/virtio-win.iso}
MODE=${1:-}

case "$MODE" in
  ""|--media-only|--recreate) ;;
  *) echo "usage: $(basename "$0") [--media-only|--recreate]" >&2; exit 2 ;;
esac

v() { virsh -c "$URI" "$@"; }
get() { [ -f "$2" ] || curl -fL --retry 5 -o "$2" "$1"; }
[ -f "$ISO" ] || { echo "missing Windows ISO: $ISO" >&2; exit 1; }

build_media() {
  mkdir -p "$TOOLS" "$CACHE" "$(dirname "$CRED")"
  if [ ! -f "$CRED" ]; then
    printf 'VM_USER=qa\nVM_PASS=Qa!%s\n' "$(openssl rand -hex 6)" > "$CRED"
    chmod 600 "$CRED"
  fi
  pw=$(grep '^VM_PASS=' "$CRED" | cut -d= -f2-)

  get https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win-guest-tools.exe "$TOOLS/virtio-win-guest-tools.exe"
  get https://www.spice-space.org/download/windows/spice-guest-tools/spice-guest-tools-latest.exe "$TOOLS/spice-guest-tools.exe"
  get https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso "$VIRTIO_ISO"

  # Real fallback tree: Win11 x64 virtio drivers + qemu-guest-agent MSI.
  rm -rf "$TOOLS/virtio"
  mkdir -p "$TOOLS/virtio"
  for d in Balloon NetKVM fwcfg pvpanic qemufwcfg qemupciserial smbus sriov \
           viofs viogpudo vioinput viomem viorng vioscsi vioserial viosock viostor; do
    xorriso -osirrox on -indev "$VIRTIO_ISO" -extract "/$d/w11" "$TOOLS/virtio/$d" >/dev/null 2>&1 || true
  done
  xorriso -osirrox on -indev "$VIRTIO_ISO" \
    -extract /guest-agent/qemu-ga-x86_64.msi "$TOOLS/virtio/qemu-ga-x86_64.msi" >/dev/null
  chmod -R u+w "$TOOLS/virtio"
  find "$TOOLS/virtio" -mindepth 2 -maxdepth 2 -type d ! -name amd64 -exec rm -rf {} + 2>/dev/null || true
  find "$TOOLS/virtio" -type f \( -name '*.pdb' -o -name '*.md' \) -delete
  [ -f "$TOOLS/virtio/viostor/amd64/viostor.inf" ] || {
    echo "virtio driver staging failed" >&2; exit 1; }
  [ -f "$TOOLS/virtio/qemu-ga-x86_64.msi" ] || {
    echo "qemu-guest-agent staging failed" >&2; exit 1; }

  sed "s/__PASSWORD__/$pw/g" "$ROOT/unattend/autounattend.xml" > "$MEDIA/autounattend.xml"
  cp "$ROOT/unattend/install-tools.ps1" "$MEDIA/install-tools.ps1"
  genisoimage -quiet -J -R -V QATOOLS -o "$TOOLS_ISO" "$MEDIA"
  echo "media: $TOOLS_ISO"
}

build_media
[ "$MODE" = --media-only ] && exit 0

if v dominfo "$DOMAIN" >/dev/null 2>&1; then
  if [ "$MODE" = --recreate ]; then
    src=$(v domblklist "$DOMAIN" | awk '$1 == "sda" { print $2 }')
    case "$src" in
      /var/lib/libvirt/images/*.qcow2) ;;
      *) echo "refusing to delete unexpected disk: ${src:-<none>}" >&2; exit 1 ;;
    esac
    v destroy "$DOMAIN" >/dev/null 2>&1 || true
    v undefine "$DOMAIN" --nvram --snapshots-metadata --managed-save >/dev/null
    v vol-delete --pool default "$(basename "$src")" >/dev/null
    echo "removed old domain and $(basename "$src")"
  fi
fi

if ! v dominfo "$DOMAIN" >/dev/null 2>&1; then
  virt-install --connect "$URI" \
    --name "$DOMAIN" --memory 8192 --vcpus 4 --cpu host-passthrough \
    --machine q35 --features smm.state=on \
    --boot loader=/usr/share/OVMF/OVMF_CODE_4M.ms.fd,loader.readonly=yes,loader.type=pflash,loader.secure=yes,nvram.template=/usr/share/OVMF/OVMF_VARS_4M.ms.fd \
    --tpm backend.type=emulator,backend.version=2.0,model=tpm-crb \
    --disk size=64,format=qcow2,bus=sata,pool=default \
    --disk path="$TOOLS_ISO",device=cdrom \
    --cdrom "$ISO" \
    --network network=default,model=e1000e \
    --graphics spice,listen=127.0.0.1 --video qxl \
    --channel spicevmc \
    --channel unix,target.type=virtio,target.name=org.qemu.guest_agent.0 \
    --input tablet,bus=usb --sound none \
    --osinfo win11 --noautoconsole
fi

v start "$DOMAIN" >/dev/null 2>&1 || true
sleep 3
v send-key "$DOMAIN" KEY_ENTER >/dev/null 2>&1 || true
sleep 2
v send-key "$DOMAIN" KEY_ENTER >/dev/null 2>&1 || true
echo "provisioned $DOMAIN (unattended install running)"
