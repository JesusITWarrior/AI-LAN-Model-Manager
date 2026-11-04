/** Runtime-backed management composition; the read-only adapter remains available explicitly. */
import { OwnerLifecycleProposals } from "./owner-lifecycle-proposals.js";
import { ManagementLifecycleService } from "./management-lifecycle.js";
import type { ControllerRuntimeHandle } from "./controller-runtime.js";
import type { OriginPolicyOptions } from "./origin.js";
import type { ManagementApiDependencies } from "./management-api.js";
import { ControllerOperatorService, type OperatorServiceOptions } from "./operator-service.js";

export type ReadManagementApiDependencies = ManagementApiDependencies;

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

/** Production routes share the runtime-owned command queue with the mTLS agent plane. */
export function createManagementDependencies(
  runtime: ControllerRuntimeHandle,
  allowedOrigins: readonly string[],
  originOptions: OriginPolicyOptions = {},
  operatorOptions: OperatorServiceOptions = {},
  clock: () => string = () => new Date().toISOString(),
): ManagementApiDependencies {
  const lifecycle=new ManagementLifecycleService(runtime,clock);
  return { ...createReadManagementDependencies(runtime, allowedOrigins, originOptions, operatorOptions), lifecycle, proposals:new OwnerLifecycleProposals(runtime,lifecycle,clock) };
}
