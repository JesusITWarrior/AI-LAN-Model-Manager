# Agent-local Ollama streaming primitive

`agents/host-agent/internal/provider/ollama.Client.ChatStream` is a bounded,
synthetic-fixture-tested **provider primitive only**. It is not production
controller-to-agent streaming. Existing nonstreaming `Chat`, command dispatch,
controller transport, and public SSE handling are unchanged.

## Local contract

- Input is the existing typed `ChatRequest`; the endpoint, HTTP client, timeout,
  provider identity, model normalization, message/options schema, and request
  size are validated before sending `POST /api/chat` with `stream: true`.
  Only the configured normalized loopback origin is eligible; production client
  construction retains the no-redirect transport. No caller-supplied URL,
  authorization header, transport option, or raw provider payload is accepted.
- Responses must be HTTP 200 `application/x-ndjson` (optional media parameters).
  Each record is at most 65,536 bytes excluding LF; the request's
  `MaxResponseBytes` bounds the complete decoded NDJSON body including delimiters, with a
  hard 262,144-byte ceiling. A fixed 4 KiB reader buffer is the only read-ahead;
  at most one bounded record and a pending terminal chunk are retained. The final
  record may end at EOF without LF; blank records are invalid. CRLF is accepted,
  with CR counted against the frame bound.
- Each delta has exactly `model`, `created_at`, `message`, `done: false`.
  A terminal record has those fields plus exactly `done_reason`,
  `total_duration`, `load_duration`, `prompt_eval_count`,
  `prompt_eval_duration`, `eval_count`, `eval_duration`. Identity must match,
  timestamps must match strict RFC3339 lexical bounds (uppercase T/Z, two-digit
  hours, dot fractions, zone hours 00–23/minutes 00–59) and pass calendar
  validation; messages must be assistant role/content only,
  and finish reason must be `stop` or `length`. Counts/durations are uint64;
  summed usage must not overflow. Unknown fields (including thinking/tools),
  provider error records, duplicate keys at either accepted object level,
  malformed JSON/UTF-8, and null fields fail closed. Repeated ordinary delta
  content is not deduplicated because repetition can be legitimate text.
- The synchronous callback receives only `ChatChunk` public fields: ID,
  `chat.completion.chunk`, canonical model, index-zero assistant delta, nullable
  finish reason, and terminal-only usage. No timestamps, diagnostics, endpoint,
  duration, or unknown metadata is forwarded. Terminal content, if present, is
  preserved as its final delta, not dropped.
- Exactly one valid done record **and clean EOF** are required for success.
  The terminal chunk is withheld until EOF; duplicate done, trailing deltas,
  junk, body errors, total-limit violations, and cancellation before EOF cannot
  emit a successful terminal chunk. A provider that keeps its response open
  after done must close it before the request deadline or the call fails.
  Previously emitted deltas may precede any failure; they are not completion.
- Callback execution directly gates further parsing/read calls. Callbacks must
  honor the supplied context for blocking work; arbitrary uncooperative Go
  callbacks cannot be forcibly interrupted without leaking work. Callback errors
  propagate unchanged; provider transport/body/parser errors are fixed redacted
  errors. Cancellation/deadline is returned as the context error and closes the
  response body. Context cancellation takes precedence immediately after the
  HTTP doer returns, even for nil-error responses with bad status or media type.
  There are no per-chunk goroutines or detached reader queues.

## Required next dependency: Go command/protocol integration

Before a transport slice or production-streaming claim, define and independently
review a matching strict, versioned stream command/event contract in Go and TS:

1. Add an explicit streaming operation/adapter surface without changing the
   existing `inference.chat` result semantics. Bind provider/model/request IDs,
   exact request and frame/total limits, deadline, capability authorization and
   approval digest. Unknown fields/operations must stay closed by default.
2. Define request-bound ordered event sequence numbers, an allowlisted chunk
   shape, terminal success/failure/cancel semantics, and a single terminal owner.
   Enforce cross-language safe integer usage bounds (the local Go primitive uses
   uint64), duplicate/out-of-order rejection, and serialized-public-event bounds
   in addition to the upstream NDJSON byte bounds. Include explicit EOF proof
   semantics rather than treating exhausted iteration as success.
3. Keep registry admission/active-request tracking, drain-before-unload,
   cancellation, capability/deadline validation, and leases alive through the
   actual terminal outcome, including callback/transport failure. Propagate
   cancellation into both blocked provider reads and bounded event publication.
4. Add synthetic Go command/protocol tests for authenticated identity binding,
   approval digest coverage, cancellation races, one terminal, bounded publication
   and slow consumers; then checkpoint before adding transport integration.
5. The later transport slice must add authenticated outbound event delivery,
   bounded buffering/backpressure, replay/restart semantics, disconnect cleanup,
   and end-to-end Go↔TS fixtures. The existing controller agent-chat transport
   explicitly rejects streaming and must not silently fall back to buffered chat.
   Public SSE must emit `[DONE]` only after a validated success terminal, not mere
   EOF, while preserving lease/admission cleanup on every exit path.

No live models, prompts, credentials, configuration, deployment, or hosted CI
are involved in this slice. All new fixtures use synthetic model identities and
content.

## Local command dependency (implemented; no relay)

The `command` package now exposes **separate local-only**
`Executor.ExecuteStream` / `Registry.ExecuteStream` entry points for the explicit
`inference.chat.stream` operation. The ordinary executor, registry dispatch,
TS `parseCommandRequest`, agent polling transport and controller chat transport
remain closed to this operation. Existing `inference.chat` stays buffered and
unchanged. No endpoint, relay, routing, public SSE or live configuration is added.
`packages/core/src/stream-command.ts` is the matching strict wire boundary, not a
production dispatcher. Both implementations consume the synthetic shared
`agents/host-agent/internal/command/testdata/stream-v1.json` fixture.

### Version 1 command

The existing request/capability envelope is retained, with a model-inference
capability whose model target exactly matches nested `params.chat.modelId` and
whose host matches the outer host. `params` has **exactly**:

- `schemaVersion: 1`;
- `chat`: the complete existing typed chat command parameters, including explicit
  nullable temperature/max-tokens fields, exact request ID, provider ID, model ID,
  canonical lower-case model name, base64 UTF-8 messages, request-byte limit and
  upstream response-byte limit;
- `upstreamFrameBytes: 65536`, the fixed accepted provider primitive's frame bound;
- `maxEventBytes`: 1,024–131,072 serialized UTF-8 bytes;
- `maxTotalEventBytes`: at least maxEventBytes, at most 1,048,576 bytes;
- `maxEvents`: 1–4,096, including the terminal event.

The model-name grammar intentionally uses the intersection of the existing TS
and Go command grammars (ASCII alphanumeric first, then `._:/-`, length ≤256,
nonempty path segments that do not start/end with a dot), with exact lower-case
binding. It does not silently normalize a differently signed identity.
The canonical authorization digest covers **all** command fields and limits,
excluding only the digest itself. No additional approval bypass exists.
Deadline and capability expiry bound execution; the earlier one wins. These
interfaces do not authenticate a peer by themselves: only an authenticated
transport may eventually call the local executor. Direct registry calls are
internal adapter calls, not an authorization boundary.

### Ordered public event protocol

Each serialized event has exactly `schemaVersion`, `hostId`, `jobId`, `requestId`,
`commandDigest`, `index`, `kind`, `chunk`, `errorCode`. Indices start at zero and
increase by one. Every binding is exact. Kinds are:

- `chunk`: public provider-neutral assistant delta, nullable finish reason null,
  no usage, and null errorCode;
- `succeeded`: the provider's final public chunk, finish reason stop/length and
  exact summed usage; null errorCode;
- `failed`: null chunk and fixed `STREAM_FAILED` errorCode;
- `cancelled`: null chunk and fixed `CANCELLED` errorCode.

Chunks allow only `id`, `object: "chat.completion.chunk"`, canonical `model`, one
index-zero assistant `choices` entry, and terminal-only usage. No private provider
metadata passes. Both individual usage counts **and their sum** must be
nonnegative integers ≤9,007,199,254,740,991. Command sequence numbers have the same
safe-integer ceiling; event indices are additionally bounded by maxEvents.
Unknown/missing/duplicate keys, nonintegral numeric tokens, invalid UTF-8 or
unpaired escaped surrogates, reordered/duplicate events, wrong bindings, extra
terminals, overflow and serialized byte/count limit violations fail closed.
A poisoned validator cannot later recover. The single-consumer validators'
`Finish`/`finish` requires an actual terminal, not mere input exhaustion; callers
must inspect terminal kind and must never equate a failed/cancelled terminal with
success. Raw serialized byte lengths—not decoded text length—consume the limits.
A transport frame delimiter is not part of this JSON-event byte count and must
be separately bounded by the future framing layer.

The registry verifies exact installed provider/model identity and loaded state,
then retains its admission handle through provider execution **and synchronous
publication of the terminal outcome**. It calls the accepted `ChatStream`; a
provider terminal callback is withheld until that call returns successfully,
which proves that primitive's valid terminal + clean EOF rule. Errors after a
provisional terminal cannot publish success. No provider/output goroutines,
unbounded queues, detached publication, or full completion accumulator are added.
A concurrent inventory disappearance cannot erase an outstanding admission
handle. Drain/unload remain blocked while publication is blocked.

`StreamEmitter(ctx, bytes)` is a synchronous bounded-publication interface.
Implementers must honor cancellation when blocked and may not retain an
unbounded backlog. An arbitrary uncooperative callback cannot be forcibly
interrupted safely. Publication errors are final; they never trigger another
publication attempt or a command requeue. On cancellation, no fresh background
context is created to force a terminal onto an unavailable sink: a blocked
publisher exits with context error, the executor records cancelled/timeout, and
an event consumer with no delivered terminal must fail incomplete. Likewise,
pre-admission/size/publication failures can end without a deliverable terminal;
the local buffered outcome is authoritative for cleanup, not substitute chunks.
A terminal publication returning nil is its acceptance/linearization point;
cancellation immediately afterward cannot contradict an accepted success.

The executor reserves an in-flight replay entry before invoking a stream,
persisting it first when a durable store is configured. Completed replays return
only their buffered final outcome, **never** stream output. Interrupted durable
`running` markers become `INDETERMINATE` without contacting the provider. A
stream's active-admission rejection is a failed final outcome, not the legacy
lifecycle `running` response that would requeue work. Chunks are never stored as
`CommandResponse` observations. Event byte/count exhaustion, sink failure and
provider failure never regenerate already emitted output.

### Exact remaining transport dependency

Before enabling any production operation, independently review this local slice
and add all of the following in a separate transport change:

1. An authenticated outbound agent event channel with exact authenticated host /
   command binding and strict Go↔TS raw parsers; explicitly authorize the new
   operation in only the intended controller and agent transport paths.
2. A bounded framing and publication adapter implementing synchronous
   backpressure and cancellation/deadline propagation, disconnect cleanup,
   sink acceptance semantics and no detached readers or publishers.
3. Controller admission/lease ownership through the final delivery outcome,
   coordination with the agent's admission handle, and cancellation routing.
4. Durable reconnect/replay behavior that distinguishes cached command outcome
   from unreplayable/interrupted output, never regenerates the request and never
   treats a buffered result as streaming chunks. No chunk replay log exists here.
5. Public SSE mapping that emits `[DONE]` **only** after a strictly validated
   `succeeded` event, never EOF, disconnect, timeout, failure or cancelled outcome;
   end-to-end synthetic tests for delivery loss, restart and slow consumers.

No production-streaming claim is made by this dependency.

### Review hardening: raw UTF-8 and ownership

Both raw stream command and event parsers explicitly reject a leading UTF-8 BOM;
TS must not rely on TextDecoder's default BOM stripping. Shared raw rejection
fixtures exercise both boundaries in Go and TS. UTF-8 BOM inside allowed string
content is ordinary content, not a document prefix.

Go stream executor, registry and validator entry points snapshot `Request.Params`
and the nullable capability `ModelID` pointer before validation/ownership. Callers
must not mutate input concurrently with the entry snapshot itself. Subsequent
caller mutations do not alter the owned authorization or validation state; tests
mutate only after the snapshot, synchronously, without data races. This mirrors
the TS validator's private request clone.

Emitter byte slices are borrowed, read-only for the synchronous call. A publisher
that needs retention must make its own bounded copy, must not mutate supplied
bytes, and must not create concurrent/unbounded retention. No buffer reuse or
ownership transfer is implied by returning nil.
