# eBPF tracer

`qa_trace.bpf.c` counts, per CPU and per comm:

- scheduler switches (`sched_switch`)
- wakeups (`sched_wakeup`)
- user and kernel page faults (`page_fault_user`, `page_fault_kernel`)

The loader prints JSON with `totals`, `per_cpu` and `top_comms`. Layer 2 adds
that JSON to its report and hash manifest.

## Build

    root/ebpf/bootstrap-ebpf.sh   # root: apt; non-root: ./toolchain, no system change
    root/ebpf/build.sh            # bin/qa_ebpf + bin/qa_trace.bpf.o

`build.sh` is toolchain-first and self-contained: `toolchain/` carries clang,
libbpf, libelf, zlib, `bpftool` and a cached `vmlinux.h`, so no host `clang` or
`libbpf-dev` is required. The host is used only without a complete toolchain
(`QA_EBPF_ALLOW_HOST=0` forbids it); `QA_EBPF_TOOLCHAIN` selects another tree
and `QA_EBPF_USE_SYSTEM=1` forces the host.

`bootstrap-ebpf.sh` pins every download in `toolchain.lock` and verifies the
SHA256 of reused `.deb` files. `build.sh` records the toolchain, clang, libbpf
and `vmlinux.h` hashes in `bin/qa_ebpf.build.json`. `build.sh --check` prints
the resolved compiler, libraries and `vmlinux.h` without building;
`--print-env` prints the same plus the link line.

`vmlinux.h` is regenerated from the running kernel's BTF whenever the kernel
release changes, so rebuild after a kernel upgrade. The loader links its libs
with an `$ORIGIN/../toolchain` rpath; deleting `toolchain/` breaks it until the
next bootstrap.

## Run

Layer 2 calls it automatically. Manually:

    sudo bin/qa_ebpf --duration 30

Requires `CAP_BPF` + `CAP_PERFMON`; the systemd deep service grants both.
Without them the loader fails before attaching and layer 2 records
`eBPF: Operation not permitted`, then continues with ftrace/perf.

## Limits

- Counters, not stacks. Use perf and coredump stacks for call paths.
- Per-comm aggregation is global, not per-core; `ftrace` supplies the per-core
  comm breakdown.
- `vmlinux.h` generation ties the object to the running kernel; rebuild on
  kernel change.
