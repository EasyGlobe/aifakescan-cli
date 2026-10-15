# Security policy

Do not put credentials, signed upload URLs, original media, raw batch manifests or private reports in public issues.

Use GitHub's **Report a vulnerability** private reporting feature for this repository when enabled. If it is unavailable, use the official service contact form at https://aifakescan.com/contact and ask for a private security channel before sending sensitive details. Include the CLI version, operating system and a sanitized error code. Never send a token or user media as proof.

This repository contains only a public protocol client. Service authorization, quota accounting, scan ownership and detector internals belong to the separate service. There are no production credentials in workflows and no privileged pull-request jobs.

## Security boundaries

- Production API origin is fixed. HTTP redirects are never followed.
- Uploads use a separate unauthenticated HTTP client and an R2 host allowlist.
- Loopback development endpoints use a separate credential namespace.
- A durable owner token is required before guest bytes are uploaded.
- Refresh operations are serialized; rejected account credentials never become guest access.
- Manifests are private; share JSONL/CSV exports instead.
- Cloud deletion is only confirmed after HTTP 204. Local exports remain.

OS process locks prevent concurrent CLI refreshes across state directories and release automatically when a process exits. Keep the empty lock files in place. Loss of a refresh response can require signing in again; the CLI fails closed and does not repeatedly exchange the same refresh token.

Credential-file storage is explicit on Unix and prohibited on Windows. If the OS store is unavailable, the CLI stops instead of creating unrecoverable cloud ownership in an ephemeral session. Local privilege escalation or a compromised user account is outside the client's credential-store boundary.
