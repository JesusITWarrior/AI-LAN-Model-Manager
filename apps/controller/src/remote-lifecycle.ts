import type { CommandRequest, CommandResponse } from "@lan-model-manager/core";
import { parseCommandRequest } from "@lan-model-manager/core";
import type { AdmissionController } from "./admission-accounting.js";
import type { AgentCommandStore } from "./agent-command-channel.js";
import type { CoupledContext, JobStores } from "./jobs-store.js";
import { LifecycleService, verifyLifecycleObservation, type LifecycleExecution, type LifecycleResult } from "./lifecycle-service.js";
import type { ControllerRepositories, ModelRecord } from "./repositories.js";

const OPERATIONS = new Set(["load", "drain", "unload"]);
const fail = (): LifecycleResult => Object.freeze({ ok: false, error: "ERR_LIFECYCLE_OBSERVATION" });
const object = (value: unknown): Record<string, unknown> | null => typeof value === "object" && value !== null && !Array.isArray(value) ? value as Record<string, unknown> : null;

/**
 * Drives the policy-checked lifecycle service over the durable authenticated
 * agent queue and applies only a fresh, target-bound terminal observation.
 * It accepts no endpoint, command, shell, path, or provider configuration.
 */
export class RemoteLifecycleController {
  constructor(
    private readonly lifecycle: LifecycleService,
    private readonly commands: AgentCommandStore,
    private readonly repositories: ControllerRepositories,
    private readonly jobs: JobStores,
    private readonly admissions?: AdmissionController,
    private readonly clock: () => string = () => new Date().toISOString(),
  ) { if (!commands.defersLifecycle()) throw new Error("ERR_REMOTE_LIFECYCLE_CONFIG"); }

  async execute(input: LifecycleExecution, signal: AbortSignal): Promise<LifecycleResult> {
    const parsed = parseCommandRequest(input?.request);
    if (!parsed.ok || !OPERATIONS.has(parsed.value.operation) || parsed.value.capability.targetKind !== "model" || parsed.value.capability.modelId === null) return Object.freeze({ ok: false, error: "ERR_LIFECYCLE_INPUT" });
    const request = parsed.value;
    const existing = this.commands.request(request.jobId);
    if (existing) {
      if (JSON.stringify(existing) !== JSON.stringify(request)) return Object.freeze({ ok: false, error: "ERR_LIFECYCLE_DISPATCH" });
      const replay = this.commands.result(request.jobId);
      if (replay) return this.finish(request, replay);
    }

    const started = this.lifecycle.execute(input);
    if (!started.ok || started.state === "failed" || started.state === "cancelled" || started.state === "timed-out") return started;
    if (started.state === "succeeded") return started;

    const abort = () => { this.lifecycle.cancel(request.jobId); };
    signal.addEventListener("abort", abort, { once: true });
    try {
      const response = await this.commands.waitResult(request.jobId, request.deadline, signal);
      return this.finish(request, response);
    } catch {
      if (signal.aborted) abort();
      else this.commands.poll(request.hostId);
      return Object.freeze({ ok: false, error: "ERR_LIFECYCLE_DISPATCH" });
    } finally {
      signal.removeEventListener("abort", abort);
    }
  }

  cancel(jobId: string): LifecycleResult { return this.lifecycle.cancel(jobId); }

  private finish(request: CommandRequest, response: CommandResponse): LifecycleResult {
    if (response.status !== "succeeded") return Object.freeze({ ok: true, state: response.status, observation: response.observation });
    const modelId = request.capability.modelId;
    const before = modelId === null ? null : this.repositories.models.get(modelId);
    if (!before) return this.reject(request, response);
    const observation = object(response.observation);
    if (!observation) return this.reject(request, response);

    // A replay after the post-observation was already applied is a no-op.
    if (this.jobs.jobs.get(request.jobId)?.state === "succeeded" && typeof observation.observedAt === "string" && before.observedAt >= observation.observedAt && this.matchesApplied(before, request.operation)) {
      return Object.freeze({ ok: true, state: "succeeded", observation: response.observation });
    }
    const now = Date.parse(this.clock());
    if (!Number.isFinite(now) || Date.parse(response.observedAt) > now + 30_000 || Date.parse(String(observation.observedAt)) > now + 30_000 || !verifyLifecycleObservation(response, before.observedAt, request)) return this.reject(request, response);

    let resumeAdmission = false;
    if (request.operation === "load" && this.admissions) {
      try {
        let accounting;
        try { accounting = this.admissions.snapshot(before.modelId); }
        catch { this.admissions.register(before.modelId); accounting = this.admissions.snapshot(before.modelId); }
        if (accounting.active !== 0) return Object.freeze({ ok: false, error: "ERR_LIFECYCLE_STATE" });
        resumeAdmission = accounting.draining;
        this.admissions.resumeAdmission(before.modelId);
      } catch { return Object.freeze({ ok: false, error: "ERR_LIFECYCLE_STATE" }); }
    }

    const prior = object(before.snapshot) ?? Object.create(null) as Record<string, unknown>;
    const runtimeState = request.operation === "unload" ? "unloaded" : "loaded-idle";
    const post = Object.freeze({ ...prior, runtimeState, activeRequests: 0 });
    const observedAt = String(observation.observedAt);
    try {
      const occurredAt = new Date(Math.max(Date.parse(this.clock()), Date.parse(response.observedAt) + 3)).toISOString();
      this.jobs.withAuditTransaction(tx => {
        this.repositories.models.upsert({
          modelId: before.modelId,
          providerId: before.providerId,
          hostId: before.hostId,
          canonicalName: before.canonicalName,
          state: request.operation === "unload" ? "installed" : "running",
          type: before.type,
          digest: before.digest,
          digestKnown: before.digestKnown,
          observedAt,
          snapshot: post,
        });
        this.settle(tx, request, response, "succeeded", null);
        tx.audit.append({ actorKind: "controller", actorId: "controller", action: "lifecycle-observation-applied", outcome: "succeeded", requestId: request.requestId, jobId: request.jobId, hostId: request.hostId, details: { operation: request.operation, modelId: before.modelId, pre: { observedAt: before.observedAt, state: before.state, snapshot: before.snapshot }, post: { observedAt, state: request.operation === "unload" ? "installed" : "running", snapshot: post } }, occurredAt });
      });
    } catch {
      if (resumeAdmission && this.admissions) void this.admissions.stopAdmission(before.modelId).catch(() => {});
      return Object.freeze({ ok: false, error: "ERR_LIFECYCLE_STATE" });
    }
    return Object.freeze({ ok: true, state: "succeeded", observation: response.observation });
  }

  private reject(request: CommandRequest, response: CommandResponse): LifecycleResult {
    try { this.jobs.withAuditTransaction(tx => this.settle(tx, request, response, "failed", "OBSERVATION_STALE")); } catch { return Object.freeze({ ok: false, error: "ERR_LIFECYCLE_STATE" }); }
    return fail();
  }

  private settle(tx: CoupledContext, request: CommandRequest, response: CommandResponse, target: "succeeded" | "failed", code: string | null): void {
    const job = tx.jobs.get(request.jobId);
    if (!job || ["succeeded", "failed", "timed-out", "cancelled"].includes(job.payload.state)) return;
    let state = job.payload.state;
    let at = Math.max(Date.parse(response.observedAt), Date.parse(job.updatedAt) + 1);
    for (const step of ["accepted", "running"] as const) {
      if (state === step || state === "running") continue;
      tx.jobs.transition(request.jobId, step, new Date(at++).toISOString(), { progressPercent: step === "accepted" ? 0 : Math.min(response.progress ?? 1, 99), terminalCode: null, terminalMessage: null });
      state = step;
    }
    tx.jobs.transition(request.jobId, target, new Date(at++).toISOString(), { progressPercent: target === "succeeded" ? 100 : null, terminalCode: code, terminalMessage: code });
    tx.audit.append({ actorKind: "agent", actorId: request.hostId, action: "command-result", outcome: target, requestId: request.requestId, jobId: request.jobId, hostId: request.hostId, details: { status: target }, occurredAt: new Date(at).toISOString() });
  }

  private matchesApplied(model: ModelRecord, operation: CommandRequest["operation"]): boolean {
    const state = object(model.snapshot)?.runtimeState;
    return operation === "unload" ? model.state === "installed" && state === "unloaded" : model.state === "running" && state === "loaded-idle";
  }
}
