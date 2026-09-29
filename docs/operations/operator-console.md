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

## Redacted diagnostics

Diagnostics contain only generated time, schema version, runtime state, aggregate host/provider/model/certificate/pairing counts, and coarse database/CA/package checks. They intentionally omit:

- cookies, CSRF values, bearer tokens, pairing codes, nonces, proofs, and digests;
- passwords, private keys, CSRs, certificate bodies, and host snapshots;
- provider endpoints, absolute filesystem paths, database contents, logs, stack traces, and dependency error text.

For deeper investigation, collect service logs locally under the host's access controls and review them before sharing. Treat any exported backup as sensitive even though the diagnostics DTO is redacted.
