# AIFakeScan CLI

A small open-source client for **batch cloud checks of images and videos**. It uploads unchanged local files to AIFakeScan and saves the evidence returned by the service. It does not include a detector, model weights, local decoding, or FFmpeg.

**Beta implementation.** Availability depends on the service enabling the CLI API. A successful build or mock test is not evidence that production or every operating system has passed acceptance. See [release acceptance](docs/release.md).

Results are `likely_ai`, `inconclusive`, or `no_strong_evidence`. None proves authenticity. Video results describe sampled coverage; categories marked `not_tested` were not checked. Uncalibrated detector scores are not presented as probabilities.

## Install a published beta

Download binaries only from this repository's [GitHub Releases](https://github.com/EasyGlobe/aifakescan-cli/releases). The next planned version is `v0.1.0-beta.2`; these download steps become available when its draft has passed acceptance and is published. A draft release is not a public installation channel.

Choose the archive matching your OS and CPU: macOS/Linux `amd64` or `arm64`, or Windows `amd64` or `arm64`. Also download `SHA256SUMS`. For example, after publication on an Apple Silicon Mac:

```sh
gh release download v0.1.0-beta.2 --repo EasyGlobe/aifakescan-cli \
  --pattern aifakescan-v0.1.0-beta.2-darwin-arm64.tar.gz --pattern SHA256SUMS
shasum -a 256 aifakescan-v0.1.0-beta.2-darwin-arm64.tar.gz
# Compare the digest with the matching filename in SHA256SUMS before extracting.
gh attestation verify aifakescan-v0.1.0-beta.2-darwin-arm64.tar.gz \
  --repo EasyGlobe/aifakescan-cli \
  --signer-workflow EasyGlobe/aifakescan-cli/.github/workflows/release.yml \
  --source-ref refs/tags/v0.1.0-beta.2 --deny-self-hosted-runners
tar -xzf aifakescan-v0.1.0-beta.2-darwin-arm64.tar.gz
./aifakescan-v0.1.0-beta.2-darwin-arm64/aifakescan version
```

For strict commit verification, add `--source-digest` with the release commit recorded in the release notes. On Linux use `sha256sum`; on Windows use PowerShell `Get-FileHash -Algorithm SHA256` and extract the ZIP. Keep the included license texts. No installer downloads and executes an update script.

Alternatively, build independently from this public repository using Go 1.25 or later (CI pins Go 1.27.2):

```sh
go build -trimpath -o aifakescan ./cmd/aifakescan
./aifakescan version
```

## Quick start

```sh
# Entirely local: enumerate eligible files without network requests.
aifakescan scan ./media --recursive --dry-run

# Cloud upload requires explicit privacy acknowledgement in scripts.
aifakescan scan photo.jpg clip.mp4 --accept-upload-policy

aifakescan scan ./media --recursive --limit 20 --concurrency 2 \
  --accept-upload-policy --format jsonl --output results.jsonl

aifakescan quota
aifakescan auth login
aifakescan batch resume batch_example
aifakescan batch export batch_example --format csv --output results.csv

aifakescan report scan_example --format json
aifakescan claim scan_example
aifakescan delete scan_example --wait
```

The IDs above are placeholders; use IDs printed by your own run. Put `--` before any path beginning with a dash. Options work before or after paths. Output files are not replaced unless `--overwrite` is provided.

Guests may complete up to **3 standard scans per UTC day**, also subject to a shared network budget. A shared office or household network may share these guest opportunities. Sign in to continue free standard scans under server safety limits. The initial account beta limits are 20 standard scans per day, including at most 5 videos, with at most 2 in flight and 1 video in flight. Limits are authoritative on the server and may change; `quota` reports the current values. Editing this open-source client cannot bypass them. There is no paid purchase flow in this client.

`auth login` prints an official website URL and a short device code. Open that URL yourself, sign in, check the code and approve your device. The CLI does not open a browser or accept a password. It never silently falls back to guest privileges when stored account credentials expire or are rejected.

```sh
aifakescan auth status
aifakescan auth sessions
aifakescan auth revoke session_example
aifakescan auth logout
```

## What gets uploaded and retained

Files are uploaded unchanged and processed in the cloud. **Original media and analysis records remain until you explicitly delete them.** A report expiring after 45 minutes does not delete the media. A deletion response of 202 means pending; only 204 confirms deletion. Local reports are not removed by cloud deletion.

Read the [service privacy policy](https://aifakescan.com/en/privacy). The CLI does not claim a training opt-out or that media is never used for service improvement. There is no client telemetry.

On first interactive upload, type `upload` to accept the displayed notice. Scripts must pass `--accept-upload-policy`. Acceptance is versioned in each saved batch.

## Files, storage and recovery

Directory scans skip hidden files, hidden directories and symbolic links. They do not recurse unless `--recursive` is supplied. Supported filename candidates are JPEG, PNG, WebP, AVIF, HEIC/HEIF, MP4, MOV, WebM and MKV; the service validates actual bytes and codec support. Images have a local 20 MiB guard, videos 200 MiB. Duration, pixel count and codec validation belong to the server. Dry run does not prove media support or reserve quota.

Each task has a digest and a durable idempotency key before creation. A lost creation response recovers the same task; it does not consume a second scan. Guest ownership credentials are saved **before upload**. A changed local file is not silently submitted using the old key. Interrupted uploads restart the same whole-file upload; byte-range resume is not promised.

Account, guest and scan ownership credentials use macOS Keychain, Windows Credential Manager or Linux Secret Service. If the store is unavailable, uploads stop before ownership would be lost. On Unix, users can explicitly choose a private file:

```sh
# Create a private directory first. The CLI adds an endpoint-specific suffix.
mkdir -m 700 "$HOME/.aifakescan-private"
aifakescan quota --credential-file "$HOME/.aifakescan-private/credentials"
```

Credential-file mode is rejected on Windows because this implementation does not manage Windows ACLs. Keep using the same storage option between runs. Logout revokes the account session and preserves guest scan credentials for deletion. Credentials are never accepted as command arguments or printed in reports.

Batches and paths are private local state under the OS user config directory, isolated by API endpoint. `--state-dir` can choose another private directory. OS process locks serialize each state directory and each credential namespace, including when different `--state-dir` values share credentials. Locks release automatically on process exit; the empty lock files should remain in place. On Windows, the CLI state directory has a protected ACL for the current user and SYSTEM, inherited by manifests. Do not share the state directory, credential file, or raw batch manifest. Share exports instead; they omit absolute paths, idempotency keys, credentials and signed upload URLs.

Production is pinned to `https://api.aifakescan.com`; uploads accept only HTTPS R2 destinations. Redirects are rejected. Development accepts an explicitly chosen **loopback HTTP** mock endpoint with `--test-mode --endpoint http://127.0.0.1:PORT` and an isolated credential namespace. It cannot forward production credentials to a custom host.

## Output and exit codes

Terminal progress goes to stderr. `--format jsonl` writes one result per file and one final `type=summary` line. CSV contains fixed columns and guards spreadsheet formula prefixes. JSONL/JSON preserve evidence, coverage and limitations. Export uses the saved report without another detection request.

| Exit | Meaning |
|---|---|
| 0 | All selected files completed, including inconclusive results |
| 1 | Unclassified internal error |
| 2 | Invalid input or local configuration |
| 3 | Sign-in, verification, or session renewal required |
| 4 | Account, rate, or service protection limit |
| 5 | Some files failed; results remain saved |
| 6 | Network/service interruption; resume the saved batch |
| 130 | Interrupted; submitted cloud work may continue |

An interruption or blocking limit takes priority over partial failures. Verdicts do not themselves change the exit code. See [public protocol](api/openapi.yaml) and [security policy](SECURITY.md).

An upload rejected by object storage keeps the batch resumable and returns exit 6. Only an API authentication failure prompts you to sign in again.

## Development

```sh
go test -race ./...
go vet ./...
go build -trimpath ./cmd/aifakescan
```

Tests use generated local bytes and mock HTTP services only. They never call production or need service credentials. The OS store adapters are not covered by memory-vault integration tests. An opt-in native smoke test uses only a fresh random synthetic namespace: `AIFAKESCAN_TEST_NATIVE_KEYRING=1 go test ./internal/store -run TestNativeCredentialStore -count=1`. Native macOS Keychain set/get/delete has been smoke-tested; native Windows/Linux credential-store and live end-to-end acceptance remain release gates.

## License

[MIT](LICENSE) applies to this new client code. Dependencies retain their own licenses; see [third-party notices](THIRD_PARTY_NOTICES.md). Open-source permissions do not grant extra service quota or access to other people's scans. All authorization and limits are enforced by the service.
