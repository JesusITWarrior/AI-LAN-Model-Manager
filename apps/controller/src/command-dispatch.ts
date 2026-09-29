import { createHash } from "node:crypto";
import type { CommandRequest, CommandResponse } from "@lan-model-manager/core";
import { capabilityMatches, parseCommandRequest, parseCommandResponse, responseMatches } from "@lan-model-manager/core";
import type { JobStores } from "./jobs-store.js";

export interface CommandWire { send(request: CommandRequest): unknown; cancel?(jobId:string):boolean }
export type DispatchResult = { readonly ok: true; readonly state: string; readonly observation: unknown } | { readonly ok: false; readonly error: string };
export type SuccessVerifier = (response: CommandResponse) => boolean;
const action = (operation: string) => operation === "probe" || operation === "inventory" || operation === "estimate" || operation === "inference.chat" ? "load" : operation;
const terminal = new Set(["succeeded", "failed", "timed-out", "cancelled"]);

export class CommandDispatcher {
  constructor(private readonly stores: JobStores, private readonly wire: CommandWire, private readonly clock: () => string = () => new Date().toISOString()) {}

  dispatch(input: unknown, verifySuccess?: SuccessVerifier): DispatchResult {
    const parsed = parseCommandRequest(input);
    if (!parsed.ok) return { ok: false, error: "ERR_DISPATCH_INPUT" };
    const request = parsed.value, now = this.clock();
    if (Date.parse(now) >= Date.parse(request.deadline) || !capabilityMatches(request, now)) return { ok: false, error: "ERR_DISPATCH_DENIED" };
    const digest = createHash("sha256").update(JSON.stringify(request)).digest("hex");
    try {
      const existing = this.stores.jobs.get(request.jobId);
      if (existing) {
        const audit = this.stores.audit.list().findLast(event => event.jobId === request.jobId && event.action === "command-dispatch");
        const priorDigest = audit && typeof audit.details === "object" && audit.details !== null && !Array.isArray(audit.details) ? (audit.details as Record<string, unknown>).digest : null;
        if (existing.payload.operation.idempotencyKey !== request.idempotencyKey || existing.payload.operation.requestId !== request.requestId || priorDigest !== digest) return { ok: false, error: "ERR_DISPATCH_CONFLICT" };
        if (terminal.has(existing.payload.state)) return { ok: true, state: existing.payload.state, observation: null };
      } else {
        this.stores.withAuditTransaction(tx => {
          tx.jobs.create({ operation: { jobId: request.jobId as never, requestId: request.requestId as never, action: action(request.operation) as never, hostId: request.hostId as never, submittedAt: now as never, manifestRevision: null, idempotencyKey: request.idempotencyKey, idempotent: true }, state: "submitted", updatedAt: now as never, progressPercent: null, attempt: 1, terminalCode: null, terminalMessage: null });
          for (const [index, state] of (["validated", "authorized", "dispatched"] as const).entries()) tx.jobs.transition(request.jobId, state, new Date(Date.parse(now) + index + 1).toISOString(), { progressPercent: null, terminalCode: null, terminalMessage: null });
          tx.audit.append({ actorKind: "controller", actorId: "controller", action: "command-dispatch", outcome: "observed", requestId: request.requestId, jobId: request.jobId, hostId: request.hostId, details: { digest, operation: request.operation }, occurredAt: now });
        });
      }
      let raw: unknown;
      try { raw = this.wire.send(request); } catch { const failed = this.fail(request, "WIRE_FAILED"); return failed.ok ? { ok: false, error: "ERR_DISPATCH_WIRE" } : failed; }
      const response = parseCommandResponse(raw);
      if (!response.ok || !responseMatches(request, response.value)) { const failed = this.fail(request, "INVALID_RESPONSE"); return failed.ok ? { ok: false, error: "ERR_DISPATCH_RESPONSE" } : failed; }
      if (response.value.status === "succeeded" && verifySuccess && !verifySuccess(response.value)) {
        const failed = this.fail(request, "OBSERVATION_STALE", response.value.observedAt);
        return failed.ok ? { ok: false, error: "ERR_DISPATCH_OBSERVATION" } : failed;
      }
      return this.settle(request, response.value);
    } catch { return { ok: false, error: "ERR_DISPATCH_DATABASE" }; }
  }

  settle(request: CommandRequest, response: CommandResponse): DispatchResult {
    if (!responseMatches(request, response)) return { ok: false, error: "ERR_DISPATCH_RESPONSE" };
    const state = ({ accepted: "accepted", running: "running", succeeded: "succeeded", failed: "failed", cancelled: "cancelled" } as const)[response.status];
    try {
      const current = this.stores.jobs.get(request.jobId);
      if (!current) return { ok: false, error: "ERR_DISPATCH_NOT_FOUND" };
      if(terminal.has(current.payload.state))return{ok:true,state:current.payload.state,observation:null};
      const patch = { progressPercent: response.progress, terminalCode: response.errorCode, terminalMessage: response.errorCode };
      this.stores.withAuditTransaction(tx => {
        let currentState = current.payload.state;
        for (const step of ["accepted", "running"] as const) {
          if (terminal.has(currentState) || (state === "accepted" && step === "running")) break;
          if (currentState === step || (currentState === "running" && step === "accepted")) continue;
          tx.jobs.transition(request.jobId, step, new Date(Date.parse(response.observedAt) + (step === "running" ? 1 : 0)).toISOString(), { progressPercent: step === "running" ? Math.min(response.progress ?? 1, 99) : 0, terminalCode: null, terminalMessage: null });
          currentState = step;
        }
        if (currentState !== state) tx.jobs.transition(request.jobId, state, new Date(Date.parse(response.observedAt) + 2).toISOString(), patch);
        tx.audit.append({ actorKind: "agent", actorId: request.hostId, action: "command-result", outcome: response.status === "succeeded" ? "succeeded" : response.status === "failed" ? "failed" : "observed", requestId: request.requestId, jobId: request.jobId, hostId: request.hostId, details: { status: response.status }, occurredAt: response.observedAt });
      });
      return { ok: true, state, observation: response.observation };
    } catch { return { ok: false, error: "ERR_DISPATCH_DATABASE" }; }
  }

  cancel(jobId: string): DispatchResult { try { const job = this.stores.jobs.get(jobId); if (!job) return { ok: false, error: "ERR_DISPATCH_NOT_FOUND" }; if (terminal.has(job.payload.state)) return { ok: true, state: job.payload.state, observation: null }; const now=new Date(Math.max(Date.parse(this.clock()),Date.parse(job.updatedAt)+1)).toISOString(); if (this.wire.cancel && !this.wire.cancel(jobId)) return { ok: false, error: "ERR_DISPATCH_DATABASE" };const refreshed=this.stores.jobs.get(jobId);if(refreshed&&terminal.has(refreshed.payload.state))return{ok:true,state:refreshed.payload.state,observation:null}; this.stores.withAuditTransaction(tx=>{tx.jobs.transition(jobId, "cancelled", now, { progressPercent: null, terminalCode: "CANCELLED", terminalMessage: "cancelled" });tx.audit.append({actorKind:"controller",actorId:"controller",action:"command-cancel",outcome:"cancelled",requestId:job.payload.operation.requestId,jobId,hostId:job.hostId,details:null,occurredAt:now});}); return { ok: true, state: "cancelled", observation: null }; } catch { return { ok: false, error: "ERR_DISPATCH_DATABASE" }; } }

  private fail(request: CommandRequest, code: string, observedAt?: string): DispatchResult {
    const base = Math.max(Date.parse(observedAt ?? this.clock()), Date.parse(this.clock()) + 4);
    return this.settle(request, { requestId: request.requestId, jobId: request.jobId, hostId: request.hostId, sequence: request.sequence, status: "failed", progress: null, observedAt: new Date(base).toISOString(), observation: null, errorCode: code });
  }
}
