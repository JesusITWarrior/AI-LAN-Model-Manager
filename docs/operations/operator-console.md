# Operator console workflows

The controller exposes operator workflows under `/api/v1/operator/*` and the web console presents them in **Setup & recovery**. These routes are management-plane only: every request requires an active owner session, every mutation additionally requires an allowed Origin and the session CSRF token, and any request carrying an `Authorization` bearer header is rejected. Agent enrollment remains on `/agent/v1/enrollment/*`; inference bearer tokens remain limited to `/v1/*`.

This document is a consumer journey for someone operating an **unsigned internal Alpha** controller. It describes what the console presents today and what remains closed. It does not establish publisher authenticity, does not claim any platform is production-supported, and does not authorize publishing, installing, or relying on any build as a release. Where an action requires an installer it links the existing guide; nothing here invents a supported installer or claims native qualification.

## Topology / current status

Read the console status panel before assuming any route is serving. The status panel reports owner, CA, discovery, enrollment, package-management, and backup readiness without returning database paths or credentials. Today's topology is:

- **Console / management / authentication** — served on the loopback address `127.0.0.1:7340` under the management plane (`/api/v1/operator/*`) and the owner/session plus CSRF-protected status route. The console and its management/authentication traffic share this loopback listener.
- **Inference** — the OpenAI-compatible inference surface uses the same loopback listener on `127.0.0.1:7340` at token-authenticated `/v1/*` routes, with a default inference client base URL of `http://127.0.0.1:7340/v1`. Management and inference credentials remain separate; an inference bearer never authorizes a management mutation and a management session never serves as an inference credential.
- **Optional separate TLS 1.3 agent plane** — an operator may opt a single selected private RFC 1918 host address into a dedicated TLS 1.3 mutual-authentication agent plane (console and inference listeners stay loopback-only). This is opt-in and does not expose management or inference beyond loopback.
- **Provider / model work on enrolled hosts** — hosts observe and report provider state; the controller normalizes inventory and placement. Host-agent state, provider adapters, guarded lifecycle actions, verified artifact staging, and custom manifests run on the enrolled host, not in the console.
- **Pre-release / NO-SHIP** — every platform remains a review-stage Alpha with open current-commit gates (Linux/Windows) or absent native qualification (macOS). Nothing below is production-supported, installation-recommended, or publication-ready.

The configuration's `inferencePort` field **does not** currently bind a second application listener, so **do not** assume port `7341` is serving inference. Discovery and non-loopback public inference are disabled.

## Install and first start

There is **no** supported general installer here. The deterministic, unsigned Linux/Windows packaging and installation/upgrade foundations are documented in [installation-and-upgrades.md](installation-and-upgrades.md). To install and start a controller, follow that guide: it verifies the package against checksums and an inventory manifest, verifies every payload byte before changing the installation, installs versioned files under a bounded data directory, keeps controller state separately, and creates only a local service. Re-running is idempotent; a newer verified package switches releases while preserving state and rolls back if `/auth/v1/status` is not healthy.

After the console is reachable on `127.0.0.1:7340`, the first run proceeds as below. Do not infer that an installer was qualified, that macOS service packaging is present, or that any publishable release exists.

## First run and controller trust

1. Bootstrap the single owner account through the sign-in screen.
2. Open **Setup & recovery** and initialize the controller CA once.
3. Export the CA certificate and compare its SHA-256 fingerprint out-of-band before an agent pins it. The CA private key is never returned by an API.
4. Refresh discovery. mDNS candidates are explicitly untrusted and expire according to their advertisements.

The status panel reports owner, CA, discovery, enrollment, package-management, and backup readiness without returning database paths or credentials.

**Discovery grants no trust.** A discovered candidate is a binding to inspect, not an authority to trust. Every enrolled identity still requires mutual proof, certificate status, binding, expiry, and owner confirmation.

## Pair and enroll a host

1. Select the candidate by both candidate ID and observed address. The controller rejects stale or unknown bindings.
2. Start pairing. The displayed one-time code and challenge expire after ten minutes.
3. Compare the code at the host and re-enter it in the operator console. Five failed attempts cancel the challenge.
4. The host completes mutual proof on the dedicated enrollment endpoint and receives a certificate bound to its candidate ID, address, protocol version, and controller CA.
5. Watch pairing status until `consumed` with `enrolled: true`.

Raw code digests, nonces, proofs, owner IDs, CSRs, private keys, and session credentials are never included in management DTOs.

## Rename, revoke, and re-enroll

Renaming updates only the public host display name; it does not alter host ***, certificate binding, or inventory keys. Revoking a host certificate is immediate and marks fleet liveness revoked. A revoked certificate cannot authenticate fleet traffic. Re-enrollment does not reactivate the old certificate: it requires a currently discovered matching candidate and starts a fresh one-time pairing challenge.

Discovery confirms presence, not eligibility: a renamed, revoked, or unpaired host still requires a fresh, owner-confirmed pairing and a currently valid certificate.

## Provider setup and model operations

Provider and model work happens **on the enrolled host**; the console observes, normalizes, and places — it does not run providers. Guidance grounded in current behavior:

- **Observe, do not trust.** Ollama and LM Studio implement versioned operations for probe, inventory, estimate, load/options, drain/unload, install/remove-managed-artifact, and health. Provider responses are untrusted observations with freshness metadata; adapters cannot receive controller credentials or use arbitrary network destinations.
- **Inventory is success, not qualification.** A successful `inventory` observation confirms the provider was seen on a host; it is **not** enrollment success, liveness proof, or production support. A provider can report inventory while its underlying qualification (exact-current-commit native gates, service health, recovery) remains open.
- **Load / drain / unload are guarded owner actions.** `load`, `drain`, and `unload` move models through `absent -> installing -> installed -> loading -> loaded_idle -> serving` (safe stop: `serving -> draining -> loaded_idle -> unloading -> installed`). These are lifecycle mutations that policy gates before dispatch and that **may require owner approval**; console guidance must not imply every provider or native flow is qualified, authorized, or approved.
- **Placement is authorization-visible.** The controller normalizes capability requirements and revalidates host/provider/model state before destructive work; substitution requires policy authorization and is visible in response metadata and audit history.

State remains the guard: `unknown` or `stale` blocks destructive action, and retries apply only to declared idempotent operations.

## Inference client configuration

Point an OpenAI-compatible inference client at the loopback surface:

- **Base URL:** `http://127.0.0.1:7340/v1`
- **Authentication:** a separately issued **inference bearer token**. Inference credentials authorize only `/v1/*` inference routes and never management operations. Do **not** reuse a management session cookie, CSRF token, or owner credential as an inference bearer. A request carrying an `Authorization` bearer header is rejected at the management plane; the management plane never serves as an inference credential.
- **Listener:** inference shares the loopback `127.0.0.1:7340` listener with console/management at `/v1/*`. The configuration's `inferencePort` field does not bind a second application listener — do not assume `http://127.0.0.1:7341/v1` serves anything.
- **Transport:** TLS is deliberately disabled only for this loopback-only surface. Discovery and non-loopback public inference are disabled.

Sending prompts never grants authority to alter hosts or models. Obtain an inference token through the console's token workflow; never extract, share, or mix management credentials for inference.

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

## Uninstall boundaries

Uninstall is the operator's controlled administrative procedure, not a web-API action. The console does not expose uninstall as a management route:

- **Normal uninstall preserves state and configuration.** Removing the local service / uninstalling the package leaves controller state, enrolled certificates, inventory, audit history, and backups in place for later re-enrollment, restore, or forensics.
- **Explicit purge removes state.** A deliberate, operator-initiated purge (removing state directory, certificate directory, and backups) is the only path that deletes that data, and it is a manual administrative step, not a console mutation and not a management-plane route.
- **No filesystem / shell routes.** The web API does not accept arbitrary filesystem paths, shell commands, service names, installer arguments, or purge flags. Destructive removal stays outside the controller API.

Do not read a present uninstall *command in the guide* as a qualified console action; it is operator-run, and normal uninstall preserves state while only an explicit purge discards it.

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

## Troubleshooting

Bounded, guidance-only actions that **never** request secrets, raw provider responses, model names, private paths, or credentials. For the Windows presentation / missing-key defect and enrollment/repair workflow, consult [enrollment-diagnosis.md](enrollment-diagnosis.md); it explains the local key/CSR preparation, redacted local failure phases, and that the ordinary `started` message is not enrollment success.

- **Host fails to enroll.** Confirm discovery shows the candidate, then follow [enrollment-diagnosis.md](enrollment-diagnosis.md) for the local key/CSR preparation and redacted failure phases. Do not relax proof, authentication, certificate status, expiry, or rate limits.
- **Host missing from inventory.** A missing inventory observation is a diagnostic hint, not a qualification check. Re-run the bounded observation; a provider may be offline or not yet inventoryed. Inventory success is not enrollment or liveness.
- **Pairing challenge expired or cancelled.** Begin a fresh pairing. A stale or cancelled challenge requires a new one-time code.
- **Certificate revoked / fleet degraded.** Check certificate status and binding, then re-enroll with a freshly discovered matching candidate. Re-enrollment starts a fresh challenge; it does not resurrect the old certificate.

Always collect service logs locally under the host's access controls and share redacted diagnostics only. Diagnostics never expose credentials, CSRs, keys, model names, or private paths.

## Known limits / qualification

This operator console documents an **unsigned internal Alpha** at the current source line; it is a status description, not a support announcement and not a release. See [docs/operations/alpha-support-matrix.md](alpha-support-matrix.md) for the source-stage review versus release support / qualification split.

No platform is production-supported, installation-recommended, or publication-ready. Current-commit native gates (Linux/Windows) remain open; macOS native qualification is absent, and its first-Alpha inclusion vs. explicit exclusion is an owner decision, pending. Signing, publication, and an explicit owner go/no-go remain closed. The console operates a loopback console/management/authentication/inference surface (`127.0.0.1:7340`, with inference client base URL `http://127.0.0.1:7340/v1`), an optional separate TLS 1.3 agent plane, and provider/model work on enrolled hosts — none of which closes any release gate or implies any platform is qualified.
