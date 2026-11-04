import { commandPolicyOperation, parseCommandRequest, parseHostResourceObservation, type AuthorizationIntent } from "@lan-model-manager/core";
import type { ControllerRuntimeHandle } from "./controller-runtime.js";
import type { GuardResult } from "./guard.js";
import type { LifecycleResult } from "./lifecycle-service.js";

const terminal = new Set(["succeeded", "failed", "timed-out", "cancelled"]);
const fail = (error: "ERR_LIFECYCLE_INPUT" | "ERR_LIFECYCLE_STATE" | "ERR_LIFECYCLE_DENIED"): LifecycleResult => ({ ok: false, error });
function record(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

/** Owner-only bounded remote lifecycle adapter. Policy facts come from durable
 * inventory/trust/jobs, never from browser-supplied authorization assertions.
 * No endpoints, shell commands, artifacts, options or inference are accepted.
 */
export class ManagementLifecycleService {
  constructor(private readonly runtime: ControllerRuntimeHandle, private readonly clock: () => string = () => new Date().toISOString()) {}

  async submit(input: unknown, guard: GuardResult): Promise<LifecycleResult> {
    if (!guard.ok) return fail("ERR_LIFECYCLE_DENIED");
    if (!this.runtime.services.lifecycle.acceptsSubmissions) return fail("ERR_LIFECYCLE_STATE");
    const body = record(input);
    if (!body || Object.keys(body).some(key => !["request", "approvalId"].includes(key))) return fail("ERR_LIFECYCLE_INPUT");
    const parsed = parseCommandRequest(body.request);
    if (!parsed.ok || !["load", "drain", "unload"].includes(parsed.value.operation)) return fail("ERR_LIFECYCLE_INPUT");
    if (body.approvalId !== undefined && (typeof body.approvalId !== "string" || !/^[a-f0-9]{64}$/.test(body.approvalId))) return fail("ERR_LIFECYCLE_INPUT");
    const request = parsed.value, now = this.clock(), nowMs = Date.parse(now);
    // Bound the HTTP wait; typed command/capability validation remains enforced
    // by the lifecycle service and dispatcher as well.
    if (Date.parse(request.deadline) <= nowMs || Date.parse(request.deadline) > nowMs + 300_000) return fail("ERR_LIFECYCLE_INPUT");
    const { repositories, services } = this.runtime;
    const model = request.capability.modelId === null ? null : repositories.models.get(request.capability.modelId);
    const host = repositories.hosts.get(request.hostId);
    const provider = model ? repositories.providers.get(model.providerId) : null;
    if (!model || !host || !provider || model.hostId !== host.hostId || provider.hostId !== host.hostId || request.capability.targetKind !== "model" || request.capability.targetId !== model.modelId) return fail("ERR_LIFECYCLE_STATE");
    const resource = parseHostResourceObservation(record(host.snapshot)?.resource);
    if (!resource.ok || resource.value.hostId !== host.hostId || resource.value.platform !== host.platform) return fail("ERR_LIFECYCLE_STATE");
    const live = repositories.db.prepare("SELECT c.status,c.not_before,c.not_after,c.revoked_at,l.last_observed_at,l.health,l.revoked_at AS live_revoked_at FROM fleet_liveness l JOIN host_certificates c ON c.fingerprint=l.certificate_fingerprint AND c.candidate_id=l.host_id WHERE l.host_id=?").get(host.hostId) as {status:string;not_before:string;not_after:string;revoked_at:string|null;last_observed_at:string;health:string;live_revoked_at:string|null}|undefined;
    const fresh = (at: string) => { const age = nowMs - Date.parse(at); return Number.isFinite(age) && age >= 0 && age < 60_000; };
    const counts = repositories.db.prepare("SELECT SUM(CASE WHEN state NOT IN ('succeeded','failed','timed-out','cancelled') THEN 1 ELSE 0 END) active, SUM(CASE WHEN submitted_at>? THEN 1 ELSE 0 END) recent FROM jobs WHERE job_id<>?").get(new Date(nowMs - 60_000).toISOString(), request.jobId) as {active:number|null;recent:number|null};
    const intent: AuthorizationIntent = {
      requestId: request.requestId, actorKind: "owner", actorId: guard.session.ownerId,
      operation: commandPolicyOperation(request.operation), targetKind: "model", targetId: model.modelId, hostId: host.hostId, modelId: model.modelId,
      observationFresh: host.online && host.freshness === "fresh" && [host.observedAt, provider.observedAt, model.observedAt, resource.value.observedAt].every(fresh) && !!live && live.health === "active" && live.live_revoked_at === null && fresh(live.last_observed_at),
      hostRevoked: !live || live.status !== "active" || live.revoked_at !== null || Date.parse(live.not_before) > nowMs || Date.parse(live.not_after) <= nowMs,
      modelCompatible: provider.health === "ready" && model.state !== "available",
      // These operations do not change listener exposure.
      publicExposure: false,
      availableMemoryBytes: resource.value.memory.availableBytes,
      availableVramBytes: resource.value.accelerators.reduce((max, gpu) => Math.max(max, gpu.memory.availableBytes), 0),
      availableStorageBytes: resource.value.storage.availableBytes,
      activeOperations: counts.active ?? 0, operationsLastMinute: counts.recent ?? 0,
    };
    const decision = services.policy.authorize(intent);
    if (!decision.ok || decision.value.reasons.some(reason => reason !== "approval-required" && reason !== "allowed-read")) return fail("ERR_LIFECYCLE_DENIED");
    if (decision.value.requiresApproval && body.approvalId !== undefined && !services.policy.consume(body.approvalId, intent, request).ok) return fail("ERR_LIFECYCLE_DENIED");
    if (!services.policy.validateCapability(request.capability, intent, decision.value, request)) return fail("ERR_LIFECYCLE_DENIED");
    // Register only an unloaded, idle target through load. Never synthesize idle
    // accounting for a serving model or discard an existing active lease.
    if (request.operation === "load") {
      const snapshot = record(model.snapshot);
      if (snapshot?.activeRequests !== 0 || !["installed", "unloaded", "failed"].includes(String(snapshot?.runtimeState ?? model.state))) return fail("ERR_LIFECYCLE_STATE");
      services.admissions.register(model.modelId);
    }
    return services.lifecycle.execute({ request, intent }, new AbortController().signal);
  }

  cancel(input: unknown, guard: GuardResult): LifecycleResult {
    if (!guard.ok) return fail("ERR_LIFECYCLE_DENIED");
    const body = record(input);
    if (!body || Object.keys(body).length !== 1 || typeof body.jobId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(body.jobId)) return fail("ERR_LIFECYCLE_INPUT");
    const request = this.runtime.services.commands.request(body.jobId);
    if (!request || !["load", "drain", "unload"].includes(request.operation)) return fail("ERR_LIFECYCLE_STATE");
    const job = this.runtime.jobStores.jobs.get(body.jobId);
    if (!job) return fail("ERR_LIFECYCLE_STATE");
    // Cancellation reduces authority; it remains available to the authenticated
    // owner even after policy changes or host revocation. No new capability.
    if (terminal.has(job.state)) return { ok: true, state: job.state, observation: null };
    return this.runtime.services.lifecycle.cancel(body.jobId);
  }
}
