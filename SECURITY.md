# Security policy

## Current status

This repository is pre-release software. The controller scaffold is a local
development surface only and must not be exposed to an untrusted network.

## Non-negotiable invariants

1. Discovery does not grant trust. A host is unusable until the owner verifies
   an expiring pairing code and endpoint identity fingerprint.
2. Controller-agent traffic is mutually authenticated after pairing and resists
   replay. Identities support rotation and revocation.
3. Agents run unprivileged by default and expose typed capabilities, not a
   general-purpose remote shell.
4. Custom commands use exact executables and validated argument templates.
   Shell interpretation and arbitrary environment inheritance are off.
5. Inference and management use separate permissions; inference credentials do
   not confer installation, deletion, migration, or host-control authority.
6. A model with active requests cannot be unloaded, deleted, or replaced.
   Intervention first stops admission and drains or explicitly aborts requests.
7. Placement preserves configured memory, VRAM, and storage headroom. No-prompt
   mode waives approval prompts only; it never bypasses hard safety limits.
8. Automatic eviction is limited to manager-owned temporary cache entries.
   Pinned, active, transferring, loading, user-installed, or protected models
   are never silently deleted.
9. Downloads and peer transfers stage privately and verify an authenticated
   manifest, expected size, provenance, and cryptographic digest before commit.
10. Every mutation is authenticated, authorized, schema-validated, idempotent,
    timeout-bounded, locally revalidated, and append-audited under a job ID.
11. Central policy governs intent; the host agent independently enforces an
    immutable local safety envelope even if the controller is compromised.

## Sensitive local data

Never commit LAN addresses, machine names, hardware inventories, usernames,
pairing material, private keys, certificates, tokens, real custom manifests,
provider paths, logs, prompts, request content, or model artifacts. The
repository `.gitignore` excludes standard local locations. CI will add secret
and dependency scanning before release.

## Vulnerability reporting

Do not open public issues containing exploit details or deployment information.
Until a private reporting channel is published, contact the repository owner
through GitHub without including secrets in the first message.
