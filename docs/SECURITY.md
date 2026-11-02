# Security and privacy review

## Implemented controls

- Single-operator authentication on every private screen and download.
- CSRF token checks for all state-changing requests.
- HTTP-only, SameSite=Strict session cookie; optional Secure flag.
- CSP, frame denial, MIME sniffing prevention, no-referrer, and no-store headers.
- Localhost-only Compose port bindings and no public API.
- Server-generated storage keys, traversal rejection, streamed uploads, extension allowlist, request/per-file limits, private modes, and forced attachment downloads.
- SHA-256 integrity metadata and duplicate-content detection.
- Parameterized SQL, foreign keys, constrained statuses, bounded text inputs, and audit history.
- No credentials in source, URLs, logs, or result data; private paths are Git-ignored.
- Synthetic mock adapter only; no scraping, evasion, or speculative identity inference.
- Cloud AI authorization guard and citation/review-oriented result contracts; no provider enabled.

## Known limitations

- One shared admin password; no per-user attribution, MFA, password hashing, lockout, or durable rate limiting. Keep localhost-only.
- Application data is not encrypted at rest. Depend on full-disk encryption and encrypted backups.
- File extensions are allowlisted, but content is not malware-scanned or deeply signature-validated. Downloads are forced; scan untrusted files outside the app.
- SQLite queue leases are recorded but stale-running-job recovery is not yet automated.
- Relationship data has a foundation schema but no graph editor/visualization yet.
- S3, authorized TikTok API, scheduling, AI providers, and external agent API are interfaces only.

## Before any network exposure

Do not expose this release publicly. A future review must add TLS, reverse-proxy hardening, per-user access controls, MFA, rate limiting, secure secret management, audit-log integrity, backup/restore drills, dependency scanning, and a documented retention/deletion policy.
