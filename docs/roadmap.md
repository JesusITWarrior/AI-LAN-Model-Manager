# Roadmap

## Milestone 0 — safe foundation

- [x] Record component and trust boundaries.
- [x] Exclude secrets, runtime state, inventories, and artifacts from Git.
- [x] Implement pure lifecycle and placement primitives with tests.
- [x] Add a loopback-only controller health surface.
- [ ] Add CI for TypeScript, Go, secret scanning, dependencies, and SBOMs.
- [ ] Define the immutable local agent safety envelope and pairing protocol.

## Milestone 1 — smallest safe vertical slice

1. Authenticate one local owner.
2. Discover one agent as an untrusted candidate.
3. Pair using an expiring one-time code with visible identity confirmation.
4. Establish persistent mutual identities with rotation and revocation.
5. Report read-only health, resources, provider status, and model inventory.
6. Submit one constrained lifecycle job through policy and durable orchestration.
7. Revalidate hard limits on the agent, execute, and report observed state.
8. Display append-oriented audit history and host revocation.
9. Test reconnect, duplicate jobs, expiry, replay, revocation, and partial failure.

Peer copy, custom commands, self-update, eviction, fallback placement, remote
Internet exposure, and global no-prompt mode remain disabled in this milestone.

## Milestone 2 — guarded hot-swapping

- Add load, context/options, admission stop, drain, unload, and read-back checks.
- Add idempotency, timeouts, cancellation, rollback, leases, and audit chaining.
- Add prompts and scoped persistent grants.
- Enable no-prompt mode only after hard-limit adversarial tests pass.

## Milestone 3 — routing and recommendations

- Add a separately authorized OpenAI-compatible inference gateway.
- Add capability profiles and explainable fallback ranking.
- Add queue, fallback, privacy, locality, and fail-closed policy controls.

## Milestone 4 — acquisition and temporary cache

- Add approved-source downloads and authenticated manifests.
- Add digest-verified, resumable peer transfer as the preferred fast path.
- Add manager-owned temporary cache, quotas, reserves, and guarded eviction.

## Milestone 5 — extensibility and hardening

- Add constrained custom manifests and a provider plugin SDK.
- Add future-ready roles and permissions.
- Add signed packaging/updates, backup/recovery, and external security review.
