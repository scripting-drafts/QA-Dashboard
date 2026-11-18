#!/usr/bin/env bash
# Install the eBPF build dependencies.
#
# Root: apt installs the normal packages.
# Non-root: downloads the same Ubuntu packages and extracts them under
#           $ROOT/toolchain, so no system change and no sudo are required.
#
# The toolchain is self-contained: clang, libbpf, libelf, zlib, bpftool and a
# vmlinux.h cached for the running kernel.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TC="${QA_EBPF_TOOLCHAIN:-$ROOT/toolchain}"
KVER="$(uname -r)"
LOCK="$ROOT/root/ebpf/toolchain.lock"
TC_LIB="$TC/usr/lib/x86_64-linux-gnu"

PKGS=(
  clang-14 libclang-cpp14 libllvm14 libclang-common-14-dev libclang1-14
  libbpf-dev libbpf0 libelf-dev libelf1 zlib1g-dev zlib1g linux-tools-common
)

# bpftool lives in the kernel tools package. linux-tools-<kver> is a
# metapackage, so its direct dependencies are fetched too; virtual packages
# (<...>) are skipped.
if apt-cache show "linux-tools-$KVER" >/dev/null 2>&1; then
  PKGS+=("linux-tools-$KVER")
  while read -r dep; do
    [[ -n $dep ]] || continue
    apt-cache show "$dep" >/dev/null 2>&1 && PKGS+=("$dep")
  done < <(apt-cache depends --no-recommends --no-suggests --no-conflicts \
             --no-breaks --no-replaces --no-enhances "linux-tools-$KVER" \
           | awk '/Depends:/{print $2}' | grep -v '^<')
elif apt-cache show linux-tools-generic >/dev/null 2>&1; then
  PKGS+=(linux-tools-generic)
fi

if [[ ${EUID} -eq 0 ]]; then
  echo "installing system packages: ${PKGS[*]}"
  apt-get update -qq
  apt-get install -y "${PKGS[@]}"
  echo "now run: $ROOT/root/ebpf/build.sh"
  exit 0
fi

if ! command -v apt-get >/dev/null 2>&1 || ! command -v dpkg-deb >/dev/null 2>&1; then
  echo "need apt-get and dpkg-deb for the user-local toolchain" >&2
  exit 1
fi

verify_layout() {
  local missing=0 f
  for f in \
    usr/lib/llvm-14/bin/clang \
    usr/lib/x86_64-linux-gnu/libbpf.so \
    usr/lib/x86_64-linux-gnu/libbpf.so.0 \
    usr/lib/x86_64-linux-gnu/libelf.so \
    usr/lib/x86_64-linux-gnu/libelf.so.1 \
    usr/lib/x86_64-linux-gnu/libz.so \
    usr/lib/x86_64-linux-gnu/libz.so.1 \
    usr/include/bpf/libbpf.h \
    usr/include/libelf.h \
    usr/include/zlib.h; do
    [[ -e "$TC/$f" ]] || { echo "missing: $TC/$f" >&2; missing=1; }
  done
  [[ -n $(find "$TC/usr/lib/linux-tools" -name bpftool 2>/dev/null | head -1) ]] \
    || { echo "missing: bpftool under $TC/usr/lib/linux-tools" >&2; missing=1; }
  return "$missing"
}

if verify_layout 2>/dev/null; then
  echo "toolchain already complete: $TC"
else
  mkdir -p "$TC/debs"
  cd "$TC/debs"

  # Pinned versions from the lock file when the archive still carries them.
  declare -A PIN=() OLD_SHA=()
  if [[ -f $LOCK ]]; then
    while read -r name ver sha; do
      [[ -n ${name:-} ]] || continue
      PIN["$name"]="$ver"
      OLD_SHA["$name"]="$sha"
    done < "$LOCK"
  fi

  dl=()
  for p in "${PKGS[@]}"; do
    if [[ -n ${PIN[$p]:-} ]] && apt-cache show "$p=${PIN[$p]}" >/dev/null 2>&1; then
      dl+=("$p=${PIN[$p]}")
    else
      dl+=("$p")
    fi
  done
  echo "downloading build packages (no root): ${dl[*]}"
  apt-get download "${dl[@]}" 1>&2

  # Verify pinned downloads before extracting them.
  : >"$LOCK.tmp"
  for deb in *.deb; do
    name="$(dpkg-deb -f "$deb" Package)"
    ver="$(dpkg-deb -f "$deb" Version)"
    sha="$(sha256sum "$deb" | awk '{print $1}')"
    if [[ -n ${PIN[$name]:-} && ${PIN[$name]} == "$ver" && -n ${OLD_SHA[$name]:-} \
          && ${OLD_SHA[$name]} != "$sha" ]]; then
      echo "checksum mismatch for $name $ver" >&2
      echo "expected ${OLD_SHA[$name]}, got $sha" >&2
      exit 1
    fi
    printf '%s %s %s\n' "$name" "$ver" "$sha" >>"$LOCK.tmp"
  done

  for deb in *.deb; do
    dpkg-deb -x "$deb" "$TC"
  done
  # Merged-usr packages ship /lib/... paths; normalise them under usr/lib so a
  # single -L covers every library.
  if [[ -d "$TC/lib" ]]; then
    mkdir -p "$TC/usr/lib"
    cp -a "$TC/lib/." "$TC/usr/lib/"
    rm -rf "${TC:?}/lib"
  fi
  [[ ${QA_EBPF_KEEP_DEBS:-0} == 1 ]] || rm -f ./*.deb
  sort -o "$LOCK.tmp" "$LOCK.tmp"
  mv "$LOCK.tmp" "$LOCK"
  cd "$ROOT"
  rm -rf "${TC:?}/debs"
fi

verify_layout || { echo "toolchain incomplete: $TC" >&2; exit 1; }

# Cache vmlinux.h for the running kernel so build.sh never compiles against a
# stale header.
export LD_LIBRARY_PATH="$TC_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
BPFTOOL="$(find "$TC/usr/lib/linux-tools" -name bpftool 2>/dev/null | head -1)"
[[ -n $BPFTOOL ]] && BPFTOOL="$(readlink -f "$BPFTOOL")"
CACHE_KVER=
if [[ -f "$TC/vmlinux.meta" ]]; then
  read -r CACHE_KVER _ <"$TC/vmlinux.meta" || CACHE_KVER=
fi
if [[ ${CACHE_KVER:-} == "$KVER" && -f "$TC/vmlinux.h" ]]; then
  echo "vmlinux.h cache is current for $KVER"
elif [[ -n $BPFTOOL && -x $BPFTOOL && -r /sys/kernel/btf/vmlinux ]]; then
  echo "generating $TC/vmlinux.h for $KVER"
  "$BPFTOOL" btf dump file /sys/kernel/btf/vmlinux format c >"$TC/vmlinux.h.tmp"
  mv "$TC/vmlinux.h.tmp" "$TC/vmlinux.h"
  printf '%s %s\n' "$KVER" "$(sha256sum "$TC/vmlinux.h" | awk '{print $1}')" \
    >"$TC/vmlinux.meta"
else
  echo "warning: no bpftool or BTF; vmlinux.h cache not refreshed" >&2
fi

echo "toolchain ready: $TC"
echo "lock file: $LOCK"
echo "now run: $ROOT/root/ebpf/build.sh"
