# Windows packaging

Targets: Windows 11 x64 and ARM64.

- Electron Dashboard from the repository root.
- QA Sentinels engine from `sentinels/`, bundled only — Windows has no
  standalone Sentinels installer or supported standalone CLI.
- Bundled Python runtime for the engine.
- Per-user NSIS/MSI installer and portable ZIP.
- TPM 2.0 required for the commercial edition; unsigned test builds do not
  enforce licensing.

Build from the repository root:

```bash
make build-windows
```

The CI workflow `win-msi.yml` builds the MSI on `windows-latest`; the QA VM
workflow deploys it to the Windows 11 test VM.
