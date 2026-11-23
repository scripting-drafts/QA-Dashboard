#!/usr/bin/env bash
# QA VM deploy: pushes a per-machine MSI into the Windows guest over the
# qemu-guest-agent channel (no SMB, no SSH, no network share).
# Usage: deploy.sh <path/to/app.msi> [--clean]
#   --clean   revert to the "qa-baseline" snapshot before installing
set -euo pipefail

MSI=${1:?usage: deploy.sh <app.msi> [--clean]}
CLEAN=${2:-}
DOMAIN=${VM_DOMAIN:-win11}
URI=${LIBVIRT_URI:-qemu:///system}
TIMEOUT=${DEPLOY_TIMEOUT:-900}
LABEL=QADEPLOY

v() { virsh -c "$URI" "$@"; }

iso=$(mktemp --suffix=.iso)
work=$(mktemp -d)
cleanup() {
  change_media_eject || true
  rm -rf "$work" "$iso"
}
trap cleanup EXIT

change_media_eject() {
  v change-media "$DOMAIN" sdc --eject --force >/dev/null 2>&1 || true
}

echo "==> domain: $DOMAIN"
state=$(v domstate "$DOMAIN" | tr -d '[:space:]')
if [ "$state" != "running" ]; then
  echo "==> starting domain"
  v start "$DOMAIN" >/dev/null
fi

if [ "$CLEAN" = "--clean" ]; then
  if ! v snapshot-info "$DOMAIN" qa-baseline >/dev/null 2>&1; then
    echo "missing snapshot qa-baseline (create it after a clean provision)" >&2
    exit 2
  fi
  echo "==> reverting to snapshot qa-baseline"
  v snapshot-revert "$DOMAIN" qa-baseline --running >/dev/null
fi

echo "==> waiting for guest agent"
ok=0
for _ in $(seq 1 90); do
  if v qemu-agent-command "$DOMAIN" '{"execute":"guest-ping"}' >/dev/null 2>&1; then ok=1; break; fi
  sleep 2
done
[ "$ok" = 1 ] || { echo "guest agent unreachable" >&2; exit 2; }

echo "==> packing deploy media"
cp "$MSI" "$work/app.msi"
cp "$(dirname "$0")/guest/deploy.ps1" "$work/deploy.ps1"
genisoimage -quiet -J -R -V "$LABEL" -o "$iso" "$work"

echo "==> mounting deploy media on sdc"
change_media_eject
v change-media "$DOMAIN" sdc "$iso" --insert --force >/dev/null

ps_cmd="\$d=(Get-Volume -FileSystemLabel '$LABEL').DriveLetter; if(-not \$d){exit 3}; & (\$d+':\\deploy.ps1')"
payload=$(jq -cn --arg c "$ps_cmd" \
  '{execute:"guest-exec",arguments:{path:"powershell.exe",arg:["-NoProfile","-ExecutionPolicy","Bypass","-Command",$c],"capture-output":true}}')

echo "==> running installer in guest"
pid=$(v qemu-agent-command "$DOMAIN" "$payload" | jq -r '.return.pid // empty')
[ -n "$pid" ] || { echo "guest-exec failed" >&2; exit 3; }

rc=99
for _ in $(seq 1 "$TIMEOUT"); do
  st=$(v qemu-agent-command "$DOMAIN" "{\"execute\":\"guest-exec-status\",\"arguments\":{\"pid\":$pid}}")
  if [ "$(echo "$st" | jq -r '.return.exited')" = "true" ]; then
    rc=$(echo "$st" | jq -r '.return.exitcode')
    echo "$st" | jq -r '.return["out-data"] // empty' | base64 -d 2>/dev/null || true
    echo "$st" | jq -r '.return["err-data"] // empty' | base64 -d 2>/dev/null || true
    break
  fi
  sleep 2
done
[ "$rc" != 99 ] || { echo "installer timed out" >&2; exit 4; }

read_guest_file() {
  local path=$1 limit=${2:-65536} h
  h=$(v qemu-agent-command "$DOMAIN" \
      "$(jq -cn --arg p "$path" '{execute:"guest-file-open",arguments:{path:$p,mode:"r"}}')" \
      | jq -r '.return // empty')
  [ -n "$h" ] || return 1
  v qemu-agent-command "$DOMAIN" \
    "$(jq -cn --argjson h "$h" --argjson n "$limit" '{execute:"guest-file-read",arguments:{handle:$h,count:$n}}')" \
    | jq -r '.return["buf-b64"] // empty' | base64 -d
  v qemu-agent-command "$DOMAIN" \
    "$(jq -cn --argjson h "$h" '{execute:"guest-file-close",arguments:{handle:$h}}')" >/dev/null 2>&1 || true
}

echo "==> result"
result=$(read_guest_file 'C:\qa\deploy.json' 8192 || true)
echo "${result:-<no deploy.json>}" | tail -20

msi_rc=$(echo "$result" | jq -r '.exit // empty' 2>/dev/null || true)
case "${msi_rc:-$rc}" in
  0|3010) ;;
  *) echo "==> msi.log tail" >&2; read_guest_file 'C:\qa\msi.log' 4000 >&2 || true; exit 5 ;;
esac

echo "==> screenshot"
shot="${DEPLOY_SCREENSHOT:-$PWD/qa-vm-$(date +%Y%m%d-%H%M%S).ppm}"
v screenshot "$DOMAIN" "$shot" >/dev/null
echo "$shot"

echo "==> ok"
