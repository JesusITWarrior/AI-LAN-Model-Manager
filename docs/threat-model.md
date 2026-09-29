# Threat model

LAN Model Manager is pre-release, local-first software. This document describes implemented boundaries and known limits; it does not claim deployment hardening or release signing that does not yet exist.

## Assets and actors

Protected assets include the controller database, owner and inference credentials, pairing material, certificate private keys, model artifacts, provider state, audit history, and private LAN topology. Untrusted actors include discovery peers, unauthenticated network clients, malformed provider responses, imported artifacts, and custom-provider command output. An authenticated host or controller can also be compromised, so authorization and state checks are repeated at the component that performs a mutation.

## Trust boundaries and ingress

1. **Discovery is untrusted.** An advertisement creates only a bounded candidate. It grants no management authority or credentials.
2. **Pairing requires owner confirmation.** The state machine binds candidate identity, address, port, protocol version, expiring one-time code digests, nonces, and proof digests. The proof is derived from the pairing transcript and code; it is not a digital-signature mechanism.
3. **Controller/agent transport is authenticated.** Enrolled hosts use TLS 1.3 mutual authentication and signed envelopes. Certificate status, endpoint binding, request/body binding, timestamps, and persistent monotonic replay state are checked before fleet mutation.
4. **Management and inference are separate.** Management uses owner sessions and CSRF checks. The OpenAI-compatible inference surface uses separately issued bearer tokens; inference credentials cannot authorize management operations.
5. **Provider data is untrusted.** Native and custom adapters apply strict schemas, size/cardinality limits, freshness checks, stable errors, and normalized outputs.

## Mutation and command controls

Policy evaluates each lifecycle intent before dispatch. Approval convenience can skip a prompt but cannot bypass hard denials. Host observations, capability bindings, active-request accounting, artifact leases, and lifecycle state are revalidated before destructive work.

Custom-provider commands support only `probe`, `inventory`, `load`, `drain`, and `unload`. A validated plan contains an exact absolute executable, argv array, allowlisted child environment, timeout, and output bound. Execution does not use a shell, PATH lookup, or ambient environment. Local authorization is checked immediately before process start, and returned JSON is checked for operation/provider/action binding, freshness, shape, and sensitive values. **The current implementation does not provide an OS namespace, cgroup, container, or command-signature sandbox; operating-system account isolation remains a deployment responsibility.**

## Artifact and cache boundaries

Peer transfer requires an authenticated, expiring ticket and exact source/destination/artifact binding. Chunks and complete content are digest-checked before publication. Approved downloads are staged privately, bounded, verified, and quarantined on mismatch. Provider import proof is checked before atomic publication; partial failures invoke compensation and quarantine paths.

Automatic eviction is limited to manager-owned temporary artifacts. Active leases, pins, recent-use protection, current observations, and plan revalidation prevent unsafe deletion. Startup recovery reconciles interrupted eviction state.

## Persistence and recovery

SQLite migrations use an immutable checksum ledger and transactional application; future or altered schemas fail closed. Jobs, audit chains, replay high-water marks, credentials, revocation state, and fleet health persist across restart. Database backup uses SQLite's online backup API, records schema version and SHA-256, refuses overwrite, verifies digest and `PRAGMA integrity_check`, and restores through a temporary file before atomic publication.

## Release and dependency boundary

The checked-in release tooling performs offline npm lock integrity checks, an allowlisted license inventory, tracked-file secret scanning, deterministic host-agent archives, checksums, CycloneDX SBOM generation, and unsigned provenance bound to the source commit and artifact digest. Hosted workflow execution is manual-only.

**Generated packages and provenance are unsigned.** The signing gate intentionally fails until explicit signer identity, readable key material, and the supported algorithm are supplied. No release is published by the current workflow.

## Representative abuse cases

| Abuse case | Implemented mitigation |
| --- | --- |
| Forged discovery advertisement | Candidate remains untrusted until confirmed pairing and enrollment. |
| Replayed authenticated message | Persistent per-certificate monotonic replay state and timestamp bounds. |
| Stale or divergent lifecycle response | Exact request/job/host/sequence binding and post-operation observation checks. |
| Prompt token used for host control | Separate inference bearer and management session scopes. |
| Shell injection through custom provider | No shell; exact executable/argv, bounded typed placeholders, allowlisted environment. |
| Model changed during transfer/import | Ticket, manifest, chunk and full digest checks; quarantine and rollback. |
| Eviction races with inference | Admission accounting, leases, pins, reservations, and pre-delete revalidation. |
| Database or backup tampering | Migration ledger, audit hash chain, backup digest, integrity check, fail-closed open/restore. |
| Dependency or release drift | Lock/license/secret gates, deterministic artifacts, SBOM and digest-bound provenance. |

## Residual risks

- LAN discovery metadata is observable and spoofable before pairing.
- A compromised OS account can bypass application-level controls and access local files or processes.
- Custom commands are constrained but are not OS-sandboxed by this project.
- Provider APIs and model runtimes remain separate attack surfaces.
- The controller is intentionally loopback-only in the current supported configuration; public exposure is denied.
- Cross-platform packages are cross-compiled and fixture-tested, but final release qualification still requires native-host validation.
- Advisory vulnerability data is not fetched by the offline gate; a future release process should add an explicitly networked review step.
- Release signing and publication are not operational.

## Public repository boundary

Tracked examples use synthetic identifiers and loopback documentation values. Real addresses, machine names, credentials, certificates, private keys, provider paths, inventories, logs, prompts, request content, databases, and model artifacts belong only in ignored local state.
