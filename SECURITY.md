# Security policy

Report vulnerabilities privately to the maintainer through the repository's
security advisory feature. Do not open a public issue with exploit details.

QA Sentinels collects host evidence and can run privileged layer-2 helpers.
Security-relevant changes include privilege boundaries, journal parsing, path
handling, evidence integrity, ticket generation, and the optional eBPF build.
Keep the default posture unprivileged and document any elevation.
