# Third-party notices — QA Sentinels

QA Sentinels is licensed under the MIT License. See `LICENSE`.

## Runtime

| Component | Scope | License | Notes |
| --- | --- | --- | --- |
| Python 3 standard library | runtime | PSF-2.0 | Host interpreter; not bundled. |
| SQLite | runtime | Public domain | Host library; not bundled. |
| Linux kernel tools (`journalctl`, `perf`, `ftrace`) | runtime | Host distribution licenses | Not bundled. |
| libbpf (optional) | runtime | LGPL-2.1-only OR BSD-2-Clause | Used only by the optional eBPF tracer; built per host. |

## Bundled code

| Component | Scope | License |
| --- | --- | --- |
| QA Sentinels Python package | project | MIT |
| C sampler (`qa_sample`) | shipped | MIT |
| eBPF tracer sources (`root/ebpf`) | shipped | MIT |

## Local build toolchain

`toolchain/` is a host-local build aid. It is not tracked, not installed by the
Debian package, and excluded from the Debian source tarball. Do not redistribute
it with QA Sentinels. If you publish a custom build that includes system
headers or binaries, keep their copyright and license notices.

## License texts

- Python: https://docs.python.org/3/license.html
- SQLite: https://www.sqlite.org/copyright.html
- libbpf: https://github.com/libbpf/libbpf/blob/master/LICENSE.BSD-2-Clause
- MIT: `LICENSE`
