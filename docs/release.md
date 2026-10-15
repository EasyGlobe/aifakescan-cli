# Release acceptance

The release workflow is manual and creates a **draft** release only. It does not publish a release, use production secrets or deploy the service. Dispatch it at an existing reviewed `vX.Y.Z[-beta...]` tag and supply the exact reviewed 40-character commit SHA. The workflow rejects a mismatch and builds that immutable commit. Git signing is not assumed; GitHub Actions provenance is generated for the assets. Configure main/tag protection before allowing release dispatch.

Before publishing the first public tag:

1. Review every file and the complete new Git history; this client must have no copied service source/history, private schema, model, credentials, real media or logs.
2. Run secret scans over source, all Git objects, build logs, licenses, SBOM and release archives. Scan for private source paths and production secrets. A secret scanner alone cannot establish source-code isolation.
3. Enable GitHub private vulnerability reporting, secret scanning, push protection, dependency alerts and main/tag protection. Require review and CI checks. Confirm CODEOWNERS resolves to a valid repository owner/team.
4. Verify a fresh clone builds without private repositories or credentials. Review pinned dependencies and licenses.
5. Test native installation and OS credential stores on macOS, Windows and Linux. Cross-compilation is not native acceptance.
6. Test device approval, denial, expiry, refresh, revocation and account deletion with isolated test resources. Verify old web flows continue working.
7. Exercise mixed-media batches, guest fourth-file pause, account continuation, interrupted creation/upload/confirmation/polling, changed source files and deletion pending/completed behavior. Use synthetic media only.
8. Confirm server concurrency/ownership/quota and global cost tests, exact production service version, feature flag and rollback capability. A client mock test or HTTP 200 is not this proof.
9. Review the draft assets, verify SHA-256 and build provenance, and retain the release-to-commit and production-to-commit evidence before publishing.

The workflow includes dependency inventory in SPDX 2.3 form. It describes the resolved module graph, which may include test-only dependencies; it is not a claim that every module is linked into every platform binary.

A current implementation limitation is that refresh-response loss requires a fresh interactive sign-in. Data/recovery credentials are preserved. If a user loses all guest ownership credentials, the CLI cannot bypass ownership checks to retrieve or delete those scans.
