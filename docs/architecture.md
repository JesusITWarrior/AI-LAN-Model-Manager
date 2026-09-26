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
isolated. Discovery yields only an untrusted candidate. One-time pairing creates
mutual identities with replay protection, rotation, and revocation.

### Provider contract

Ollama and LM Studio first implement versioned operations for probe, inventory,
estimate, load/options, drain/unload, install/remove-managed-artifact, and health.
Provider responses are untrusted observations with freshness metadata. Adapters
cannot receive controller credentials or use arbitrary network destinations.

### Separate planes

The OpenAI-compatible inference gateway and management API use separate routes,
credentials, scopes, rate limits, and audit categories. Sending prompts never
grants authority to alter hosts or models.

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
rate-limited, staged, digest-verified, and atomically committed.

Only manager-owned temporary cache entries may be automatically evicted. Every
candidate is revalidated immediately before deletion against active requests,
leases, pinning, transfers, policy protection, and free-space assumptions.

## Public repository boundary

Tracked files contain schemas and synthetic examples only. Real topology,
addresses, identities, credentials, provider paths, manifests, inventories,
telemetry, logs, requests, and artifacts remain in ignored local state.
