#!/usr/bin/env bash
# Build the layer-2 eBPF tracer.
#
# Toolchain-first: uses $ROOT/toolchain when it is complete, so the build does
# not depend on host clang/libbpf. Without a complete toolchain the host is
# used (QA_EBPF_ALLOW_HOST=1, the default); set it to 0 to fail instead.
# QA_EBPF_TOOLCHAIN points at an alternate toolchain.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="$ROOT/root/ebpf"
TC="${QA_EBPF_TOOLCHAIN:-$ROOT/toolchain}"
TC_LIB="$TC/usr/lib/x86_64-linux-gnu"
TC_BIN="$TC/usr/lib/llvm-14/bin"
KVER="$(uname -r)"

MODE=build
case "${1:-}" in
  --check) MODE=check ;;
  --print-env) MODE=print ;;
  "") ;;
  *) echo "usage: $0 [--check|--print-env]" >&2; exit 2 ;;
esac

toolchain_complete() {
  [[ -x $TC_BIN/clang ]] || return 1
  [[ -f $TC_LIB/libbpf.so && -e $TC_LIB/libbpf.so.0 ]] || return 1
  [[ -f $TC_LIB/libelf.so && -e $TC_LIB/libelf.so.1 ]] || return 1
  [[ -f $TC_LIB/libz.so && -e $TC_LIB/libz.so.1 ]] || return 1
  [[ -f $TC/usr/include/bpf/libbpf.h ]] || return 1
  return 0
}

resolve_bpftool() {
  local c real
  for c in "$TC/usr/lib/linux-tools/$KVER/bpftool" \
           $(find "$TC/usr/lib/linux-tools" -name bpftool 2>/dev/null | head -1); do
    real="$(readlink -f "$c" 2>/dev/null || true)"
    [[ -n $real && -x $real ]] && { printf '%s\n' "$real"; return 0; }
  done
  command -v bpftool >/dev/null 2>&1 && { command -v bpftool; return 0; }
  return 1
}

SOURCE=
CLANG=
BPF_INC=
LDLIBS=

if toolchain_complete && [[ ${QA_EBPF_USE_SYSTEM:-0} != 1 ]]; then
  SOURCE=toolchain
  CLANG="$TC_BIN/clang"
  export LD_LIBRARY_PATH="$TC_LIB:$TC/usr/lib/llvm-14/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
  BPF_INC="-I$TC/usr/include"
  if [[ $TC == "$ROOT/toolchain" ]]; then
    RPATH='$ORIGIN/../toolchain/usr/lib/x86_64-linux-gnu'
  else
    RPATH="$TC_LIB"
  fi
  LDLIBS="-L$TC_LIB -Wl,-rpath,$RPATH -lbpf -lelf -lz -lpthread"
elif [[ ${QA_EBPF_ALLOW_HOST:-1} == 1 ]] \
     && command -v clang >/dev/null 2>&1 && [[ -f /usr/include/bpf/libbpf.h ]]; then
  SOURCE=system
  CLANG="$(command -v clang)"
  BPF_INC="-I/usr/include"
  LDLIBS="-lbpf -lelf -lz -lpthread"
  echo "warning: no complete toolchain; building against host libbpf" >&2
else
  echo "no usable toolchain or host clang/libbpf" >&2
  echo "run: $HERE/bootstrap-ebpf.sh" >&2
  exit 1
fi
LINKER="${QA_EBPF_LINKER:-$CLANG}"

# vmlinux.h: prefer the cache built for this kernel, regenerate it otherwise.
BPFTOOL="$(resolve_bpftool || true)"
VMLINUX_SRC=
if [[ -f $TC/vmlinux.h && -f $TC/vmlinux.meta ]]; then
  meta_kver=
  read -r meta_kver _ <"$TC/vmlinux.meta" || true
  [[ ${meta_kver:-} == "$KVER" ]] && VMLINUX_SRC="$TC/vmlinux.h"
fi
if [[ -z $VMLINUX_SRC ]]; then
  if [[ -z $BPFTOOL ]]; then
    echo "vmlinux.h for $KVER is not cached and bpftool is unavailable" >&2
    echo "run: $HERE/bootstrap-ebpf.sh" >&2
    exit 1
  fi
  if [[ ! -r /sys/kernel/btf/vmlinux ]]; then
    echo "cannot read /sys/kernel/btf/vmlinux; CONFIG_DEBUG_INFO_BTF is required" >&2
    exit 1
  fi
fi

if [[ $MODE != build ]]; then
  echo "source:    $SOURCE"
  echo "toolchain: $TC"
  echo "clang:     $CLANG"
  echo "linker:    $LINKER"
  echo "bpftool:   ${BPFTOOL:-unavailable}"
  echo "vmlinux:   ${VMLINUX_SRC:-$TC/vmlinux.h (will be generated for $KVER)}"
  echo "includes:  $BPF_INC"
  echo "libs:      $LDLIBS"
  [[ $MODE == check ]] && [[ ! -x $CLANG ]] && exit 1
  exit 0
fi

if [[ -z $VMLINUX_SRC ]]; then
  echo "generating $TC/vmlinux.h for $KVER"
  "$BPFTOOL" btf dump file /sys/kernel/btf/vmlinux format c >"$TC/vmlinux.h.tmp"
  mv "$TC/vmlinux.h.tmp" "$TC/vmlinux.h"
  printf '%s %s\n' "$KVER" "$(sha256sum "$TC/vmlinux.h" | awk '{print $1}')" \
    >"$TC/vmlinux.meta"
  VMLINUX_SRC="$TC/vmlinux.h"
fi
install -m 0644 "$VMLINUX_SRC" "$HERE/vmlinux.h"

echo "building qa_trace.bpf.o with $CLANG ($SOURCE)"
# shellcheck disable=SC2086
"$CLANG" -target bpf -D__TARGET_ARCH_x86 -O2 -g $BPF_INC -I"$HERE" \
  -c "$HERE/qa_trace.bpf.c" -o "$HERE/qa_trace.bpf.o"

echo "building loader with $LINKER ($SOURCE)"
# shellcheck disable=SC2086
"$LINKER" -O2 -Wall -Wextra $BPF_INC -I"$HERE" \
  -o "$HERE/qa_ebpf" "$HERE/qa_trace.c" $LDLIBS

mkdir -p "$ROOT/bin"
install -m 0755 "$HERE/qa_ebpf" "$ROOT/bin/qa_ebpf"
install -m 0644 "$HERE/qa_trace.bpf.o" "$ROOT/bin/qa_trace.bpf.o"
STAMP="$ROOT/bin/qa_ebpf.build.json"
LIBBPF_SRC="$TC_LIB/libbpf.so.0"
[[ $SOURCE == system ]] && LIBBPF_SRC="$(ldconfig -p | awk '/libbpf\.so\.0 /{print $NF; exit}')"
printf '{\n  "kernel_release": "%s",\n  "built_at": "%s",\n  "binary_sha256": "%s",\n  "object_sha256": "%s",\n  "toolchain": "%s",\n  "clang": "%s",\n  "libbpf": "%s",\n  "vmlinux_sha256": "%s"\n}\n' \
  "$KVER" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  "$(sha256sum "$ROOT/bin/qa_ebpf" | awk '{print $1}')" \
  "$(sha256sum "$ROOT/bin/qa_trace.bpf.o" | awk '{print $1}')" \
  "$SOURCE" "$("$CLANG" --version | head -1)" "$LIBBPF_SRC" \
  "$(sha256sum "$HERE/vmlinux.h" | awk '{print $1}')" >"$STAMP"
echo "installed: $ROOT/bin/qa_ebpf and $ROOT/bin/qa_trace.bpf.o"
echo "stamp: $STAMP"
echo "test without privileges (should fail cleanly): $ROOT/bin/qa_ebpf --duration 1"
