# Contributing

Contributions are accepted under the MIT License (inbound = outbound). Sign off
commits with the Developer Certificate of Origin 1.1 (`git commit -s`).

- Keep the renderer sandboxed: `nodeIntegration: false`, `contextIsolation: true`,
  `sandbox: true`.
- Use fixed argument vectors. Do not add a general shell or arbitrary command
  execution.
- Do not add telemetry, network calls, or credentials to the renderer.
- Add tests for backend, IPC, and packaging changes.
- Run `npm test` before opening a pull request.
- Do not include personal data, host-specific paths, or secrets in commits.
