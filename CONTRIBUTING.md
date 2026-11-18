# Contributing

Contributions are accepted under the MIT License (inbound = outbound). Sign off
commits with the Developer Certificate of Origin 1.1 (`git commit -s`).

- Keep collection read-only unless a documented privileged helper is required.
- Do not add telemetry, network uploads, or vendor credentials.
- Add tests for collection, query, ticket, and legal-register changes.
- Run `python3 -m unittest discover -s tests` and `./bin/qa legal --check`.
- Do not include personal data, host-specific paths, or secrets in commits.
