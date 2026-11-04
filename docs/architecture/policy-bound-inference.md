# Policy-bound remote inference composition

The default application chat route composes `RemoteInferenceService` through
`createRemoteInferenceChat`. The production agent plane gives the **same runtime
owner's generation-fenced relay view** to signed command polling and TLS stream
HTTP ingestion. No ordinary `AgentChatTransport` or persistent `AgentCommandStore`
is used for prompt/result bytes. Existing listener exposure configuration is
unchanged.

## Authority and admission

Bearer `inference:invoke` is required. Only exact durable running Ollama models
with agreeing installed, non-temporary serving/loaded-idle snapshots qualify.
The runtime never registers admission from inventory, loads models, substitutes,
or acquires unmanaged cache entries. Unknown restart accounting remains closed.
Policy defaults to deny; approval-required inference is denied, not queued.

Selection conveys no authority. Dispatch reselects and binds exact model,
provider, host, active certificate, fresh resources, authenticated token owner,
policy version/hash and actual operation counts before issuing the command-bound
capability. `RemoteInferenceService.open` acquires the only authoritative lease;
the generic public adapter has no second admissions controller or queue/cache.
Active acceptance rechecks token/trust, inventory, resource freshness, policy and
admission uncertainty. Stopping admission blocks new work while existing valid
leases may finish; it is not cancellation. A 250ms owner watchdog also interrupts work when no consumer is reading.

## Ephemeral bounded delivery

The owner supports at most 16 live executions, one per host, with 120-second
execution deadlines. Commands allow 64 messages, 262144 input content bytes,
524288 request bytes, 4096 events, 131072 bytes/event and 1048576 total event
bytes. Agent ingestion caps bodies at 180224 bytes, 16 concurrent waits globally,
two per certificate, and a 10-second upload deadline. There is one retained relay
slot per execution. Errors are redacted.

Streaming bridges call relay `next` only on downstream demand. There is no detached
pump. A never-consumed iterator `return` and request abort close the execution
owner. Strict validated success with usage is required before public terminal
chunk/`[DONE]`; failure or ordinary EOF cannot produce success. Nonstream requests
aggregate only validated chunks in memory up to 262144 content bytes and return
JSON only after strict success. HTTP/socket buffers add their normal bounded
transport buffering; relay acceptance is **not** a public-delivery attestation.

The metadata-only execution ledger records remote execution ownership outcomes,
never successful public delivery. It contains no prompts, encoded messages,
completions, bearers or command JSON. A successful relay terminal settles execution
even if later downstream delivery fails. No delivery-success ledger is claimed.

## Cancellation, recovery and shutdown

Local cancellation, timeout, failure, stale/revoked trust or owner interruption
mark shared admission uncertain and draining before releasing local accounting.
Only independently trusted remote drain observation can clear uncertainty. Valid
success proof is immutable across same-stack cancellation/close.

Startup marks unfinished ledger entries interrupted and scrubs legacy ordinary
chat commands without replay. Logical scrub is not secure erasure of old pages,
WAL files or backups. Stop/start replaces the relay; old adapter views cannot lease
new-generation work and unresolved target drains remain closed.

Application stop rejects new owner work, closes and joins registered public HTTP
and agent stream and signed command long-poll waits plus lifecycle work before SQLite close. Synchronous
runtime close aborts waits and terminalizes execution before DB teardown; later
execution settlement is DB-free. Startup failure closes owners before listeners.

## Known conservative boundary

Fleet inventory maps loaded-idle, serving and draining snapshots to durable
running state. Inventory does **not** create admission accounting: a separately
trusted lifecycle/accounting owner must establish admission before execution. Therefore enabling routes is not a promise that an arbitrary
paired/inventoried model is eligible to serve.
