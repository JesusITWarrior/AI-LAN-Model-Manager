# Architecture

## Principle

Observe first, plan second, authorize third, mutate last, and verify actual host
and provider state instead of trusting command intent.

## Components

### Controller and UI

The TypeScript controller owns enrollment, normalized inventory, policies,
resource reservations, placement plans, approvals, durable jobs, audit history,
and routing decisions. The React UI will present Fleet, Models, Operations, and
Settings views. Browser input remains untrusted; management authorization is
always enforced server-side.

### Host agent

A small Go agent runs on Linux, macOS, and Windows. It owns telemetry, provider
adapters, guarded lifecycle actions, verified artifact staging, and constrained
custom manifests. It runs unprivileged by default; narrow privileged helpers are
isolated. Discovery yields only an untrusted candidate. The discovery packet
builder and listener lifecycle are explicit and injectable; operating-system
multicast sender wiring is deferred to the authenticated transport integration.
One-time pairing creates mutual identities with replay protection, rotation, and
revocation.

### Provider contract

Ollama and LM Studio first implement versioned operations for probe, inventory,
estimate, load/options, drain/unload, install/remove-managed-artifact, and health.
Provider responses are untrusted observations with freshness metadata. Adapters
cannot receive controller credentials or use arbitrary network destinations.

### Separate planes

The OpenAI-compatible inference gateway and management API use separate routes,
credentials, scopes, rate limits, and audit categories. Sending prompts never
grants authority to alter hosts or models.

### Owner evidence lane

Owner-provided unsigned evidence travels a separate management lane that
attaches candidate evidence only, never authorizing the mutation:

1. Untrusted owner-provided JSON bytes (raw body bounded 1..786,432 bytes).
2. Bounded decode (strict UTF-8/JSON/duplicate-key/shape/cap) against a server-built current snapshot.
3. A volatile owner/session/credential-bound candidate registry (max 16 entries, 8 MiB retained bytes, 60-second candidate TTL) with a redacted preview; the browser keeps no raw bytes, candidate handle, or tuple digest in local/session storage.
4. Explicit owner POST confirmation sending only the candidate handle, expected tuple digest, fixed action `append-supplemental-native-evidence`, and `evidence-only` disposition (confirm body max 4,096 bytes).
5. Fresh same-transaction job/history/queue/current X.509 enrollment checks; `committed_unsettled`/`transaction_unknown` outcomes require fresh explicit re-intake and never auto-retry.
6. The transaction appends supplemental evidence (one append-only row to `supplemental_native_evidence`) plus its audit event to `supplemental_native_evidence_audit`, while the queue remains authoritative input and is left unchanged (response bytes max 524,288).
7. Post-commit lease settlement and truthful uncertain outcomes (`stale`, `denied`, etc.).

Authority boundaries in this lane: the redacted preview is **not** permission; current enrolled certificate validation is **not** remote possession/fresh mTLS; stored evidence is **not** a native ACK, receipt, or hold release. Management and inference planes remain separate.

## State machines

- Host: `discovered -> pairing_pending -> paired -> active -> degraded/offline -> revoked`
- Pairing: `created -> presented -> owner_confirmed -> mutually_proven -> consumed`
- Model: `absent -> installing -> installed -> loading -> loaded_idle -> serving`
- Safe stop: `serving -> draining -> loaded_idle -> unloading -> installed`
- Artifact: `requested -> authorized -> reserved -> transferring -> verifying -> committing -> available`
- Job: `submitted -> validated -> authorized -> dispatched -> running -> succeeded|failed|timed_out|cancelled`

Unknown or stale state blocks destructive action. Retries apply only to declared
idempotent operations.

## Placement and fallback

The controller normalizes exact-model or capability requirements: runtime,
context, tools, modalities, reasoning, privacy, locality, and latency. It rejects
unauthorized, offline, stale, incompatible, or under-resourced hosts before
ranking. Reservations preserve memory, VRAM, and disk headroom. Ranking prefers
a healthy loaded placement, then an installed artifact, then acquisition.

If the preferred model is unavailable, capability policy excludes incompatible
alternatives and ranks the rest by explicit preferences, quality, latency,
privacy, context, load cost, and current pressure. Substitution requires policy
authorization and is visible in response metadata and audit history.

## Artifact transfer and eviction

A verified authorized peer is the preferred source for an exact artifact;
approved original download is the fallback. Peers supply bytes but never trusted
metadata or installation authority. Transfers are authenticated, resumable,
rate-limited, staged, digest-verified, and atomically committed. Agents remain
outbound-only: a controller rendezvous relays exact ticket-bound chunks from the
source agent's existing authenticated command poll/result flow to the destination. SQLite persists the ticket-bound source request, bounded chunk, destination ACK window, final receipt, and transfer checkpoint so controller restart replays only the exact pending step. A transfer reaches `received` only after the destination explicitly commits the expected size and SHA-256 digest. No peer address, URL, cache path, arbitrary relay listener, or temporary agent listener is carried in a transfer ticket. Relay composition is optional and therefore closed by default.

Only manager-owned temporary cache entries may be automatically evicted. Every
candidate is revalidated immediately before deletion against active requests,
leases, pinning, transfers, policy protection, and free-space assumptions.

## Public repository boundary

Tracked files contain schemas and synthetic examples only. Real topology,
addresses, identities, credentials, provider paths, manifests, inventories,
telemetry, logs, requests, and artifacts remain in ignored local state.
