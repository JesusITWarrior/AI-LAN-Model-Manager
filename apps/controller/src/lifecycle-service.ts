import type { CommandRequest, CommandResponse, AuthorizationIntent } from "@lan-model-manager/core";
import { commandPolicyOperation, parseCommandRequest } from "@lan-model-manager/core";
import type { PolicyService } from "./policy-service.js";
import type { CommandDispatcher, DispatchResult } from "./command-dispatch.js";
import type { ControllerRepositories, ModelRecord } from "./repositories.js";

export type LifecycleError =
  | "ERR_LIFECYCLE_INPUT" | "ERR_LIFECYCLE_DENIED" | "ERR_LIFECYCLE_CAPABILITY"
  | "ERR_LIFECYCLE_STATE" | "ERR_LIFECYCLE_OBSERVATION" | "ERR_LIFECYCLE_DISPATCH";
export type LifecycleResult = { readonly ok: true; readonly state: string; readonly observation: unknown } | { readonly ok: false; readonly error: LifecycleError };
export interface LifecycleExecution {
  readonly intent: AuthorizationIntent;
  readonly request: CommandRequest;
  readonly drainIntent?: AuthorizationIntent;
  readonly drainRequest?: CommandRequest;
}

type Observation = { readonly observedAt: string; readonly runtimeState?: string; readonly artifactState?: string; readonly activeRequests?: number };
const fail = (error: LifecycleError): LifecycleResult => Object.freeze({ ok: false, error });
const record = (value: unknown): Record<string, unknown> | null => typeof value === "object" && value !== null && !Array.isArray(value) ? value as Record<string, unknown> : null;
const snapshot = (model: ModelRecord | null): Record<string, unknown> | null => model ? record(model.snapshot) : null;
const active = (model: ModelRecord | null): number | null => { const value = snapshot(model)?.activeRequests; return Number.isSafeInteger(value) && Number(value) >= 0 ? Number(value) : null; };
const runtime = (model: ModelRecord | null): string => String(snapshot(model)?.runtimeState ?? (model?.state === "running" ? "loaded-idle" : model?.state ?? "absent"));

function freshObservation(response: CommandResponse, before: string, request: CommandRequest): boolean {
  if (response.status !== "succeeded") return true;
  const value = record(response.observation);
  if (!value || typeof value.observedAt !== "string" || Number.isNaN(Date.parse(value.observedAt)) || Date.parse(value.observedAt) <= Date.parse(before)) return false;
  const observation = value as Observation, params = record(request.params);
  if (params && typeof params.providerId === "string" && value.providerId !== params.providerId) return false;
  if (params && typeof params.model === "string" && value.canonicalModelName !== params.model) return false;
  switch (request.operation) {
    case "load": case "set-options": return observation.runtimeState === "loaded" || observation.runtimeState === "loaded-idle";
    case "drain": return (observation.runtimeState === "loaded" || observation.runtimeState === "loaded-idle") && observation.activeRequests === 0;
    case "unload": return observation.runtimeState === "unloaded";
    case "install": return observation.artifactState === "installed";
    case "remove-managed-artifact": return observation.artifactState === "absent";
    default: return true;
  }
}

export class LifecycleService {
  constructor(private readonly policy: PolicyService, private readonly dispatcher: CommandDispatcher, private readonly repositories: ControllerRepositories) {}

  execute(input: LifecycleExecution): LifecycleResult {
    const parsed = parseCommandRequest(input?.request);
    if (!parsed.ok || input.intent.operation !== commandPolicyOperation(parsed.value.operation) || parsed.value.requestId !== input.intent.requestId) return fail("ERR_LIFECYCLE_INPUT");
    const request = parsed.value;
    const model = input.intent.modelId === null ? null : this.repositories.models.get(input.intent.modelId);
    const activeRequests = active(model);
    if (!this.targetMatches(request, model) || !this.precondition(request.operation, model) || (model !== null && activeRequests === null)) return fail("ERR_LIFECYCLE_STATE");
    if (request.operation === "unload" && activeRequests !== null && activeRequests > 0 && (!input.drainIntent || !input.drainRequest)) return fail("ERR_LIFECYCLE_STATE");
    const authorization = this.policy.authorize(input.intent);
    if (!authorization.ok) return fail("ERR_LIFECYCLE_DENIED");
    const approvalOnly = authorization.value.requiresApproval && authorization.value.reasons.every(reason => reason === "approval-required");
    if ((!authorization.value.allowed && !approvalOnly) || !this.policy.validateCapability(request.capability, input.intent, authorization.value)) return fail("ERR_LIFECYCLE_CAPABILITY");
    const before = model?.observedAt ?? "1970-01-01T00:00:00.000Z";

    if (request.operation === "unload" && activeRequests !== null && activeRequests > 0) {
      if (!input.drainIntent || !input.drainRequest) return fail("ERR_LIFECYCLE_STATE");
      const drained = this.execute({ intent: input.drainIntent, request: input.drainRequest });
      if (!drained.ok || drained.state !== "succeeded") return drained;
    }
    const result = this.dispatcher.dispatch(request, response => freshObservation(response, before, request));
    if (!result.ok) return fail(result.error === "ERR_DISPATCH_OBSERVATION" ? "ERR_LIFECYCLE_OBSERVATION" : "ERR_LIFECYCLE_DISPATCH");
    return result as LifecycleResult;
  }

  private targetMatches(request: CommandRequest, model: ModelRecord | null): boolean {
    const params = record(request.params);
    if (!params || typeof params.providerId !== "string") return false;
    if (model === null) return request.operation === "install";
    return params.providerId === model.providerId && typeof params.model === "string" && params.model === model.canonicalName;
  }

  private precondition(operation: CommandRequest["operation"], model: ModelRecord | null): boolean {
    const state = runtime(model), requests = active(model), snap = snapshot(model);
    if (model !== null && requests === null) return false;
    switch (operation) {
      case "load": return model !== null && requests === 0 && ["installed", "unloaded", "failed"].includes(state);
      case "set-options": return model !== null && requests === 0 && ["loaded", "loaded-idle"].includes(state);
      case "drain": return model !== null && requests !== null && requests > 0 && ["serving", "running", "loaded", "loaded-idle"].includes(state);
      case "unload": return model !== null && ["serving", "running", "loaded", "loaded-idle"].includes(state);
      case "install": return model === null;
      case "remove-managed-artifact": return model !== null && requests === 0 && snap?.managedTemporary === true && snap?.pinned !== true && ["installed", "unloaded"].includes(state);
      default: return true;
    }
  }
}
