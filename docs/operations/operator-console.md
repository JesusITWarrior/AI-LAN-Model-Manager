# Operator console workflows

The controller exposes operator workflows under `/api/v1/operator/*` and the web console presents them in **Setup & recovery**. These routes are management-plane only: every request requires an active owner session, every mutation additionally requires an allowed Origin and the session CSRF token, and any request carrying an `Authorization` bearer header is rejected. Agent enrollment remains on `/agent/v1/enrollment/*`; inference bearer tokens remain limited to `/v1/*`.

## First run and controller trust

1. Bootstrap the single owner account through the sign-in screen.
2. Open **Setup & recovery** and initialize the controller CA once.
3. Export the CA certificate and compare its SHA-256 fingerprint out-of-band before an agent pins it. The CA private key is never returned by an API.
4. Refresh discovery. mDNS candidates are explicitly untrusted and expire according to their advertisements.

The status panel reports owner, CA, discovery, enrollment, package-management, and backup readiness without returning database paths or credentials.

## Pair and enroll a host

1. Select the candidate by both candidate ID and observed address. The controller rejects stale or unknown bindings.
2. Start pairing. The displayed one-time code and challenge expire after ten minutes.
3. Compare the code at the host and re-enter it in the operator console. Five failed attempts cancel the challenge.
4. The host completes mutual proof on the dedicated enrollment endpoint and receives a certificate bound to its candidate ID, address, protocol version, and controller CA.
5. Watch pairing status until `consumed` with `enrolled: true`.

Raw code digests, nonces, proofs, owner IDs, CSRs, private keys, and session credentials are never included in management DTOs.

## Rename, revoke, and re-enroll

Renaming updates only the public host display name; it does not alter host identity, certificate binding, or inventory keys. Revoking a host certificate is immediate and marks fleet liveness revoked. A revoked certificate cannot authenticate fleet traffic. Re-enrollment does not reactivate the old certificate: it requires a currently discovered matching candidate and starts a fresh one-time pairing challenge.

## Packages, checksums, upgrade, and rollback

The package panel shows only validated controller package metadata: version, package name, SHA-256, unsigned provenance status, source commit, and rollback version. The runtime adapter must verify the exact SHA-256 again before activation. Upgrade and rollback responses state whether activation changed, whether automatic rollback occurred, the prior/current versions, and whether the checksum was verified.

Package mutation is unavailable unless an explicit native installer adapter is injected. The default production runtime therefore fails closed and directs operators to the native procedure in [installation-and-upgrades.md](installation-and-upgrades.md). The web API does not accept arbitrary filesystem paths, shell commands, service names, URLs, or installer arguments.

## Backup and restore

Backup export uses SQLite online backup into the controller audit/export directory, refuses overwrite, and returns a public manifest name plus SHA-256, schema version, and page count. The API never returns an absolute path.

Restore is deliberately split:

1. Place a backup database and its manifest into the configured export directory using the host's controlled administrative procedure.
2. Run **restore preflight**. It checks the bounded filename, manifest shape, SHA-256, current schema version, and `PRAGMA integrity_check` without modifying the live database.
3. Stop the controller and use the offline native restore procedure. A live management request never replaces the database underneath the running process.
4. Restart, sign in, and inspect diagnostics and fleet state.

## Owner evidence

Prepare and attach owner-provided unsigned evidence through a separate management workflow. Selecting a local JSON file does not send anything: the browser checks that the raw body is between 1 and 786,432 bytes and holds the bytes only until you explicitly choose **Prepare**. Preparation is authenticated (owner session plus CSRF) but **not** authorizing.

1. Select a local JSON evidence file. The browser bounds the raw body to 1..786,432 bytes and sends nothing until **Prepare**.
2. **Prepare** (authenticated, non-authorizing) returns a short-lived — 60 seconds —, redacted preview bound to the current owner/session/credential/job history/current X.509 enrollment state. The preview shows the fixed label `Owner-provided unsigned evidence; source not independently proven` together with the exact job/host/request/terminal revision/kind, byte counts, and expiry.
3. A separate explicit **Attach evidence only** click sends only the candidate handle, the expected tuple digest, the fixed action `append-supplemental-native-evidence`, and the `evidence-only` disposition. It does not carry the evidence bytes.
4. The response states one of `stored`, `already_stored`, `conflict`, `stale`, `denied`, `transaction_unknown`, or `committed_unsettled`.

Unknown or unsettled outcomes (`stale`, `transaction_unknown`, `committed_unsettled`) never auto-retry and never re-run the command. They require fresh explicit re-intake before another confirmation. `stored` persists one append-only row to `supplemental_native_evidence` plus a matching audit row, while `supplemental_native_evidence_audit` records the event; it does **not** modify jobs, history, commands, replay, or holds. `already_stored` means an identical tuple already exists; `conflict` means the same tuple was presented with different owner-supplied bytes; `denied` means an authentication or bound check failed.

Data hygiene: the browser does not persist raw bytes, the candidate handle, or the tuple digest to local or session storage; a selection change, reset, or new intake invalidates the previous review. Application caps — prepare raw body max 786,432 bytes, response bytes max 524,288, volatile candidate registry max 16 entries / 8 MiB retained bytes / 60-second candidate TTL, confirm body max 4,096 — are application limits, not evidence authenticity.

Attachment never executes or retries a command, rewrites job/history/result/replay, proves host origin or fresh mTLS, ACKs a command, clears uncertainty, or releases a hold. It attaches only candidate evidence for later manual review.

## Redacted diagnostics

Diagnostics contain only generated time, schema version, runtime state, aggregate host/provider/model/certificate/pairing counts, and coarse database/CA/package checks. They intentionally omit:

- cookies, CSRF values, bearer tokens, pairing codes, nonces, proofs, and digests;
- passwords, private keys, CSRs, certificate bodies, and host snapshots;
- provider endpoints, absolute filesystem paths, database contents, logs, stack traces, and dependency error text.

For deeper investigation, collect service logs locally under the host's access controls and review them before sharing. Treat any exported backup as sensitive even though the diagnostics DTO is redacted.
