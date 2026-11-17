#!/usr/bin/env bash
# Rebuild the QA Windows VM from scratch: unattended ISO + QATOOLS media.
# Idempotent: only defines the domain if it does not exist.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")" && pwd)
ISO=${WIN_ISO:-$HOME/ISOs/Win11_26H2_Consumer_x64_en-us.iso}
DOMAIN=${VM_DOMAIN:-win11}
URI=${LIBVIRT_URI:-qemu:///system}
CRED=${VM_CRED:-$HOME/qa-vm/creds/vm.env}
MEDIA=${VM_MEDIA:-$HOME/qa-vm/media}
TOOLS=$MEDIA/tools
TOOLS_ISO=${TOOLS_ISO:-$HOME/ISOs/qa-tools.iso}

v() { virsh -c "$URI" "$@"; }
[ -f "$ISO" ] || { echo "missing Windows ISO: $ISO" >&2; exit 1; }

mkdir -p "$TOOLS" "$(dirname "$CRED")"
if [ ! -f "$CRED" ]; then
  printf 'VM_USER=qa\nVM_PASS=Qa!%s\n' "$(openssl rand -hex 6)" > "$CRED"
  chmod 600 "$CRED"
fi
pw=$(grep '^VM_PASS=' "$CRED" | cut -d= -f2-)

get() { [ -f "$TOOLS/$2" ] || curl -fL --retry 5 -o "$TOOLS/$2" "$1"; }
get https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win-guest-tools.exe virtio-win-guest-tools.exe
get https://www.spice-space.org/download/windows/spice-guest-tools/spice-guest-tools-latest.exe spice-guest-tools.exe

sed "s/__PASSWORD__/$pw/g" "$ROOT/unattend/autounattend.xml" > "$MEDIA/autounattend.xml"
cp "$ROOT/unattend/install-tools.ps1" "$MEDIA/install-tools.ps1"
genisoimage -quiet -J -R -V QATOOLS -o "$TOOLS_ISO" "$MEDIA"

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
    --channel spicevmc --channel qemu-guest-agent --input tablet,bus=usb --sound none \
    --osinfo win11 --noautoconsole
fi

v start "$DOMAIN" >/dev/null 2>&1 || true
sleep 3
v send-key "$DOMAIN" KEY_ENTER >/dev/null 2>&1 || true
sleep 2
v send-key "$DOMAIN" KEY_ENTER >/dev/null 2>&1 || true
echo "provisioned $DOMAIN (unattended install running)"
