# Certificate verification and host clock discrepancy

## Trust and time policy

New host enrollment and rotation certificates start 60 seconds before the controller's issuance clock, rounded down to X.509's whole-second precision. This is a fixed issuance policy, not a configurable verification allowance; the maximum backdate is less than 61 seconds. Expiry remains issuance plus 30 days, rounded down to seconds and capped at the issuing CA's expiry. Backdating neither renews nor changes an existing certificate and does not change owner confirmation, single-use challenges, candidate binding, key matching, CA pinning, signature, chain, or client-auth checks.

The host still verifies using its actual local time. It does not shift its clock, trust an HTTP Date header, skip validity checks, extend expiry, or retry a consumed challenge. A host more than the bounded issuance interval behind still fails closed. A newly-created CA may itself be not-yet-valid on a lagging host; backdating a leaf cannot bypass that CA boundary. Existing zero-backdated certificates are unchanged.

## Distinguishing the failure

The host's redacted enrollment diagnostics retain stage `verify` and expose fixed subreasons:

- `result-invalid`: the response envelope, challenge, controller, CA pin, or candidate binding failed validation before certificate verification.
- `verify-input`, `certificate-parse`, `ca-parse`, `ca-source`, `ca-pin`: malformed verification input or missing/mismatched trust material.
- `key-mismatch`, `binding-mismatch`, `certificate-purpose`: the leaf does not match the persistent key, candidate/IP binding, or client-auth purpose.
- `certificate-not-yet-valid`, `certificate-expired`: the leaf is outside its validity interval at the host's local time.
- `chain-not-yet-valid`, `chain-expired`: full X.509 verification rejected a CA/chain validity interval.
- `chain-untrusted`: another signature, trust, constraints, or chain verification failure.

These are categories, not proof that the host clock is wrong: a controller clock error or a genuinely invalid certificate can produce time failures too. No raw X.509 error, certificate, key, code, URL, proof, or path is added to the diagnostic. Unknown diagnostic values remain the generic `failed` category.

A successful controller issuance/consumed challenge followed by local stage `verify` and no durable `enrollment.json` is compatible with a local certificate rejection. It does not establish a save/permissions failure. The persistent key can already exist because key/CSR preparation precedes requesting owner confirmation.

## Read-only diagnosis before another owner code

1. Record public certificate validity timestamps, issuance time, and the redacted host stage/reason. Do not inspect or export private keys.
2. Bracket a host UTC reading with controller UTC readings and record the request interval. The bracket bounds discrepancy without treating network round-trip latency as an exact clock offset. Independently inspect the controller's time-synchronization status. A stale service `observedAt` timestamp alone is not a simultaneous clock measurement.
3. Check all verification predicates, not just time: result binding, persistent-key match, CA pin/source, client-auth purpose, signature, and full-chain validity. Do not disable validity checks or bypass CA trust to test a theory.
4. If time is discrepant, have the authorized operator correct time synchronization through the host's normal administration process before another owner-confirmed enrollment. This code does not change system clocks. A consumed challenge cannot be replayed, and a failed local verification does not automatically revoke an already-issued controller certificate. Resolve that state only through the existing explicit owner-controlled recovery procedure; do not generate, revoke, or re-enroll merely to collect timing evidence.

## Synthetic regressions

The Go fixture fixes controller issuance at `2026-11-03T17:43:39.468Z` and host verification 15 seconds earlier. The original zero-backdate policy deterministically rejects it as `certificate-not-yet-valid`, without saving enrollment state, deleting the prepared key, or making the challenge reusable. A 60-second issuance backdate accepts 15-second and 60-second lag fixtures; a 61-second lag still rejects. Separate fixtures retain rejection of expired/future CA chains, wrong trust pools, damaged signatures, wrong keys/bindings, malformed certificates, and wrong EKUs.

The controller test exercises actual OpenSSL issuance and independently verifies its synthetic leaf chain at an injected timestamp with `openssl verify -attime`. It checks exact validity timestamps, unchanged 30-day expiry, CA-expiry capping, failure outside the backdate window, and the fresh-CA boundary. All generated fixture material is temporary and unrelated to any installed host. These tests are not installed-service enrollment or fleet reconnect acceptance.
