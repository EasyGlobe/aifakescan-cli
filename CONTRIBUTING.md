# Contributing

Keep this client independently buildable. Do not copy service code, private schemas, models, logs, configuration, production media, credentials or repository history into this repository.

Use generated test data and mock HTTP services. Run `go test -race ./...` and `go vet ./...`. New APIs must be documented as reviewed public fields in `api/openapi.yaml`; do not export internal service types automatically. Tests must never require production credentials.

Keep actions pinned to full commit SHAs and PR permissions read-only. Never add a `pull_request_target` job that executes untrusted PR code. Do not add remote shell installer or silent update logic. Report security issues privately as described in SECURITY.md.
