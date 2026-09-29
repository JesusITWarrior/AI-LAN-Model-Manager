/**
 * Production read-only adapter for the management API.
 *
 * The controller runtime (see {@link createControllerRuntime}) exposes exactly:
 *
 *   { owner, sessions, inferenceTokens, pairing, fleet, policy, replay }
 *
 * It does **not** compose a `LifecycleService` or a `CommandDispatcher` (those
 * are lifecycle-mutation machinery that is deliberately not wired into the
 * runtime handle). Because of that, this module intentionally consumes only the
 * read-facing services the runtime actually provides and never fakes a
 * lifecycle/dispatcher: read-only management routes wire directly against
 * {@link ControllerRuntimeHandle.services}, while lifecycle-mutation routes are
 * left out of the wiring so they cannot reach a live lifecycle implementation.
 *
 * The adapter is constructed directly from a {@link ControllerRuntimeHandle}
 * without any unsafe casts and without any no-op mutation dependency.
 */

import type { ControllerRuntimeHandle } from "./controller-runtime.js";
import type { OriginPolicyOptions } from "./origin.js";
import type { ManagementApiDependencies } from "./management-api.js";
import { ControllerOperatorService, type OperatorServiceOptions } from "./operator-service.js";

/**
 * The read-facing subset of {@link ManagementApiDependencies} that this module
 * is able to construct from the real runtime. It contains only the services
 * the runtime actually composes.
 */
export type ReadManagementApiDependencies = ManagementApiDependencies;

/**
 * Adapt a runtime handle into the read-facing management dependency record.
 *
 * No `lifecycle` or `dispatcher` is supplied: the runtime does not expose them,
 * so they cannot be wired here. Read routes (fleet/jobs/audit/policy/approvals/
 * settings/inference-token metadata) are fully supported; lifecycle mutation
 * routes are intentionally left unwired so they cannot fake success against a
 * live lifecycle engine.
 */
export function createReadManagementDependencies(
  runtime: ControllerRuntimeHandle,
  allowedOrigins: readonly string[],
  originOptions: OriginPolicyOptions = {},
  operatorOptions: OperatorServiceOptions = {},
): ReadManagementApiDependencies {
  const services = runtime.services;
  return {
    sessions: services.sessions,
    allowedOrigins,
    fleet: services.fleet,
    jobs: runtime.jobStores,
    policy: services.policy,
    inference: services.inferenceTokens,
    operator: new ControllerOperatorService(runtime, operatorOptions),
    originOptions,
  };
}
