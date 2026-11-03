# Authenticated bounded stream relay component (not public inference)

This slice composes the accepted `StreamCommand` / `StreamEvent` wire contract and
Go `Executor.ExecuteStream` with an **opt-in controller component**. It does not
open a listener, enable a public inference route, issue capabilities, change owner
policy, or install a stream submission management endpoint. The default
controller runtime still rejects streaming. No live prompts/models are used.

## Explicit ownership and admission

`AgentStreamRelay.open(rawCommand)` is an internal dependency-injection seam,
not an authorization API. Its caller must already own routing, owner-policy,
capability and admission/lease authority. It strictly validates the supplied
complete capability/digest, exact host/model/request/job bindings, limits and
expiry; it never creates, repairs or expands that authority. Expired commands and
commands with more than five minutes remaining are rejected. The earlier command
or capability deadline wins. The current component permits **one retained stream
per host and 16 globally**, including completed handles awaiting owner cleanup.
These are hard ceilings; constructor options may only reduce them.

A successful open returns a sole-consumer handle with `next(signal)`, `outcome`,
`cancel()` and `close()`. The owner must close in `finally`, including disconnects.
`AgentCommandService` accepts an optional relay and adds `streamCommand` to its
signed polling response only when explicitly injected. Stream commands are mutually exclusive with ordinary commands or peer
transfers in a response. While a stream is
active, the service does not lease ordinary work; while ordinary work is queued
or leased, it does not lease a stream. The ordinary `CommandRequest` parser,
`AgentCommandStore`, dispatcher and ordinary command-result paths still reject
`inference.chat.stream`. No stream can enter the ordinary running-result requeue.

Stream polling destructively leases once. A lost polling response can lose work,
not regenerate it: the owner gets deadline/interruption rather than a new stream.
No output retry, replay log, lease requeue or buffered-completion fallback exists.
The relay retains at most 4,096 one-shot identifier tombstones per instance and
fails new opens at exhaustion instead of evicting safety history. Each command
consumes up to three distinct identifier tombstones. Closing frees request/event
storage but not these bounded identifier tombstones. Separately, leased requests
ending without success retain host/job cancellation tombstones after close.
Every authenticated control poll repeats them until command deadline plus 30
seconds; a lost poll response cannot consume the cancellation. These tombstones
contain no command/output and the union of live requests and pending cancellation
IDs shares the global stream cap. Capacity exhaustion rejects new opens rather
than dropping cancellation. Lazy expiry runs on open/poll; a stopped instance
retains at most that fixed cap. This cancels provider reads even when no event
POST is pending. Graceful process teardown still requires cancelling the agent
control session; no delivery across a dead controller is claimed.

## Authenticated outbound delivery

`createAgentStreamHttpHandler` is mounted only through an explicitly supplied
`createFleetAgentHttpHandler({streams: ...})` component dependency. Routes:

- `POST /agent/v1/streams/event`, signed message `agent.stream.event`, payload
  exactly `{eventBase64}`. Base64 is canonical and contains the **original raw
  serialized public event**, not a decoded/re-encoded JSON object.
- `POST /agent/v1/streams/result`, signed message `agent.stream.result`, payload
  exactly `{commandDigest, result}`. `result` is a terminal `CommandResponse`
  with null observation, exact host/job/request/sequence and authorization digest.
  Accepted/running results and conflicting terminal outcomes are rejected. A
  result cannot substitute for missing success events or become public chunks.

The adapter requires TLS 1.3, a verified mTLS peer, exact certificate fingerprint
and serial binding, active repository certificate, and matching authenticated
host. The actual TLS socket source address must equal the certificate address
binding; valid IPv4-mapped IPv6 addresses are canonicalized to IPv4 (including
hex notation), and invalid/zone-qualified addresses fail closed. No forwarded
header or caller-supplied source address is trusted. `ControllerTransport.accept` applies the existing signed-envelope crypto,
size/freshness checks and persistent replay verifier. Certificate active status
is rechecked at **consumer acceptance** after any publication wait. Invalid and
revoked identities never reach a consumer.

Control and stream traffic use separate durable replay/sequence lanes. Stream
requests retain the existing replay algorithm, using a domain-separated SHA-256
key in the existing replay table (no schema migration); control keys/semantics
are unchanged. The Go client persists stream reservations in `stream-sequence-<certificate fingerprint>`
using the same atomic sequence-store implementation (fresh lane on certificate rotation). Events and stream results
share this lane. Control polls/hello/heartbeats retain `fleet-sequence`. A blocked
POST therefore cannot force a later control poll to invalidate its sequence, or
require disabling replay checks. Replay state is never a chunk replay log.

The raw envelope is bounded and strictly scanned for duplicate keys, invalid
UTF-8, document BOMs, invalid escaped surrogates, numeric-token and nesting errors
**before JSON.parse loses evidence**. The decoded event bytes independently pass
the accepted raw stream parser/validator, preserving exact serialized byte/count
accounting. Signed controller polling envelopes likewise pass the Go strict raw
scanner before typed decoding; stream commands use `ParseStreamCommand` on the
preserved `json.RawMessage`. Missing, foreign, reordered, duplicate or excess
terminals fail closed. EOF alone is never success.

## Bounded synchronous acceptance and cancellation

Each stream has **one slot**, bounded by its command's `maxEventBytes`
(1,024–131,072), `maxTotalEventBytes` (at most 1,048,576) and `maxEvents` (at most
4,096, including terminal). The validator consumes exact raw event bytes. There
is no completion accumulator or detached per-token publisher. The slot retains
one parsed event and its raw-byte accounting, not an output replay copy.

A publisher's HTTP response and synchronous emitter return are withheld until
`handle.next` transfers the event to the sole consumer. Merely filling the slot
is **not** acknowledgement. This acceptance does not claim delivery to a remote
SSE client or completion of an arbitrary downstream callback; a later routing
adapter must stop calling `next` while its downstream is blocked. One accepted
in-transit event plus one pending slot is the bounded pipeline, not an unbounded
queue. A validated terminal's consumer acceptance owns the outcome; cancellation
or buffered result delivery afterward cannot contradict accepted success.

The HTTP layer separately caps bodies at 180,224 bytes, 16 in-flight bodies/waits
globally and two per certificate. Bodies must finish within ten seconds. Timeout/overflow clears every retained
partial-body buffer and detaches upload data/end listeners before releasing
admission. Unfinished uploads receive a connection-close error response and are
destroyed on response finish, with a 100 ms forced-destroy fallback; counters
remain reserved until destruction. Error/abort/disconnect cleanup is idempotent
and clears storage/listeners before decrementing counters. The component stats
report admitted HTTP operations and retained partial-upload bytes, not total
process memory. Real TLS regressions repeat 170,000-byte unfinished uploads
(two concurrent, twice), overflow uploads, and verify destroyed requests, removed
listeners, zero retained-upload bytes/counters, then healthy signed streaming.
Event
acceptance waits are bounded by the command deadline or cancellation. The
separate per-certificate stream budget is 8,256 requests/minute, enough for two
maximum-count sequences plus bounded result overhead; **no event consumes the
fleet control allowance of 120/minute**. Rate-key storage is capped at 2,048;
capacity exhaustion rejects rather than evicting safety state. The stream and
control budgets remain enabled. The synthetic TLS fixture sends over 120 events
and verifies continued control polling.

The Go client uses a distinct fixed-origin, enrolled-CA, no-proxy/no-redirect
TLS transport for event POSTs, bounded to two connections, without the control
client's eight-second response-header timeout. Its request context is the actual
executor/capability deadline. Control polling runs in the command loop while
`ExecuteStream` blocks on publication. Cancellation routes through that poll to
the active execution context; HTTP disconnect, deadline, cancellation, revocation
at acceptance, invalid sequence and consumer close all reject/clear pending work.
No fresh context is created to force terminal output to a missing sink. Stream
result delivery has a five-second context bound and is attempted once by the
runner, never retried as provider work or allowed to block control indefinitely.

A controller deadline and agent-side deadline/disconnect can race: a stream may
settle cancelled rather than deadline when disconnect wins, but cannot succeed
without accepted success terminal. The local executor's durable outcome and the
relay's delivery outcome are distinct evidence; loss of terminal acknowledgement
may leave them different without regenerating output.

## Teardown and restart

The component owner calls `stop()` before teardown: it rejects blocked publishers,
wakes consumers, settles unfinished handles as **interrupted**, clears retained
mailboxes/requests and permanently closes the instance. New instances restore
**no streams or output**. An agent posting to a replacement instance receives a
rejection for the unknown job; no implicit reconstruction occurs. The production
agent already uses `command.NewPersistent`; its existing running-marker recovery
produces `INDETERMINATE` without executing a provider, and completed replays return
only cached outcomes. The synthetic composition verifies no second execution.

An abrupt process crash cannot resolve in-memory promises. Persisting and
reconciling interrupted request/admission outcomes belongs to the future routing
owner's durable ledger; this component deliberately creates no production job or
DB recovery authority. A caller must not re-open old requests into a new instance
as a reconnect mechanism. Actual crash recovery/admission release is an explicit
remaining production enablement gate, not a claim made by graceful `stop()`.

## Proof and remaining production gates

Synthetic Go↔TypeScript TLS1.3 tests exercise ordinary and slow streaming, the real
Go command runner, more than 120 event requests, independent control polls,
cancellation, deadline/restart interruption, missing/foreign/out-of-order/raw
invalid events, unauthorized/revoked hosts, terminal-result conflicts, no output
regeneration and mailbox cleanup. Local tests cover single-consumer/publisher
bounds, revocation while pending, accepted-success cancellation races, one-shot
IDs and per-host/global capacity. No model or external provider is contacted.

Before enabling production streaming, separately implement and review:

1. Owner-policy and route admission authority: supported stream operation,
   authenticated inference identity, allowed model/provider/host, policy/approval
   digest, placement/fallback behavior and denial-by-default routing. Never expose
   this component's `open` as an unauthenticated management submission endpoint.
2. Controller admission/lease ownership through final downstream delivery and
   coordination with the agent's active registry handle; bounded fair queuing,
   drain/unload exclusion and cleanup on every failure, cancel and disconnect.
3. Durable owner ledger/restart reconciliation for interrupted ephemeral requests,
   including abrupt crash and lost poll/terminal acknowledgement. Old request IDs
   must never be resubmitted to regenerate output. There is no chunk replay log.
4. Public SSE routing/framing, downstream write/drain backpressure, consumer abort
   wiring, bounded in-transit ownership and error redaction. Emit `[DONE]` **only**
   after validated `succeeded` acceptance, never EOF/failure/cancel/interruption.
   Decide/document the precise network-write versus relay-acceptance guarantee.
5. End-to-end public HTTP/SSE authorization, policy, cancellation, downstream
   delivery-loss, admission-release and crash tests. Component TLS proofs do not
   establish these production authority or delivery guarantees.

Parent review is required before this component slice is accepted. No production
SSE/streaming readiness is asserted.
