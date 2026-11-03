# Policy-bound remote inference foundation

This component is **not production route enablement**. The default public chat
route remains closed. Neither the production agent plane nor its command poll
and stream HTTP adapters receive the inference owner's relay in this slice.
The existing non-streaming `createAgentChatTransport` remains uncomposed: it
manufactures capabilities without policy and its ordinary `AgentCommandStore`
would persist encoded prompts and responses.

## Ownership and authority

`ControllerCoreServices.inference` owns `RemoteInferenceService`, constructed
with the runtime's exact `services.admissions`, token manager, policy service,
repositories and job stores. It never registers a model or creates idle
accounting. Unknown admission after a process restart is closed.

The chat dependency seam supplies `ChatAuthenticatedContext` containing token
metadata to resolution, lease acquisition and transport, not the bearer header.
The foundation's separate component API requires this context explicitly:

1. `select(context, canonicalModel)` selects only an exact, durable model and
   returns an immutable, instance-owned binding. It is not a capability.
2. `open(context, selection, chatInput, signal)` revalidates the token, policy,
   host/provider/model identity, fresh resources, current active certificate
   binding, liveness and admission before issuing work. It checks again after
   constructing the command. No asynchronous queue is composed; capacity is
   fail-fast. A future queue must call this method **after** its wait.
3. Policy uses the authenticated token owner's actor identity and real durable
   operation counts plus parsed resources. Default deny and approval-required
   both deny. A full command digest and strict `parseStreamCommand` validation
   bind the execution capability; no capability is issued at selection time.

Only ready Ollama providers and a running model whose installed snapshot is
`serving` or `loaded-idle` qualify. The snapshot's model/provider/name/timestamp
must agree with the durable record. Managed-temporary models are excluded until
there is a shared runtime cache owner. There is no model substitution, auto-load,
client-selected provider endpoint, or new network listener.

## Content and recovery boundaries

Migration 16 retains migrations 1–15 unchanged, extends the three constrained
policy history tables to accept `model-inference`, preserves approval and decision
history, and adds `inference_executions`. The ledger contains only execution IDs,
token/owner/host/provider/model IDs, command digest, policy version/hash, deadline,
timestamps and a terminal outcome. Prompts, encoded messages, completions,
bearers, cookies and command JSON do not enter this ledger or the ordinary queue.
The accepted relay owns command and event bytes ephemerally with bounded limits.

Startup marks unfinished ledger entries `interrupted`, without command replay or
synthetic success. Legacy ordinary inference commands are scrubbed and expired,
and nonterminal jobs are cancelled with `INTERRUPTED` before listeners can poll.
This logical scrub is not a secure-erasure claim for historical SQLite pages,
WAL files or backups that predate this boundary.

## Cancellation is not remote settlement

A validated relay success terminal can finish a successful execution. Local
cancel, deadline, relay failure, consumer closure or shutdown is **not** proof
that the provider stopped. Those paths first mark admission as remote-work-uncertain and drain the
model, then release local accounting exactly once. Uncertainty independently
blocks acquire, resume, forget, load and unload, even when local leases are zero.
Only a fresh, verified remote drain observation can confirm idle and clear that
gate; this service never confirms idle or resumes admission. Ledger non-success outcomes describe the local
execution owner, not a remote provider-stop attestation. The relay exposes synchronous first-terminal proof so same-stack consumer
cancellation or owner close after accepted success cannot rewrite that successful
ledger outcome before promise continuations run.

Application stop synchronously rejects submissions to both lifecycle and
inference owners, then awaits their shutdown together before SQLite close.
Runtime synchronous close and startup-failure cleanup terminalize inference
ownership before database teardown; later outcome continuations are no-ops.
Stop/start creates a fresh relay without replay and retains unresolved target
drains. All live execution controllers have bounded relay deadlines and a global
limit of 16, with one active execution per host enforced by the relay.

## Gates before route composition

A separate reviewed composition must connect the **same** owned relay to
command polling, authenticated stream ingestion, fleet interruption and the
public consumer adapter. It must preserve lazy backpressure and accepted strict
terminal semantics, revalidate after all queue/cache waits, handle downstream
delivery separately from remote execution settlement, and prove shutdown races.
It must also reconcile actual inventory state: current fleet ingestion records
`loaded-idle` as `installed`, while this conservative foundation requires a
`running` durable record. No serving-model accounting may be inferred from that
mapping. Nonstream inference must stay closed unless replaced by a coherent
policy-bound ephemeral transport that cannot persist content or replay work.
