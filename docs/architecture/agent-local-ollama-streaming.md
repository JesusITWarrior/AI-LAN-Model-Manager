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
