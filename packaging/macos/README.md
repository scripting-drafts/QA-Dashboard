# macOS packaging

Targets: macOS 13+ Intel and Apple Silicon.

- Electron Dashboard from the repository root.
- QA Sentinels engine from `sentinels/`, bundled only — macOS has no
  standalone Sentinels installer or supported standalone CLI.
- Bundled universal2 Python runtime for the engine.
- DMG/PKG with Developer ID signing and notarization when credentials exist.
- Secure Enclave required for the commercial edition; unsigned test builds do
  not enforce licensing.

Build from the repository root:

```bash
make build-macos
```

The prerelease workflow builds DMG/ZIP artifacts on `macos-15`. Native
execution and Gatekeeper checks must run on real macOS hardware or a macOS CI
runner.
