import type { CapabilityProfile, ObservedModelCapability } from "./capability-matching.js";

export type ModelLifecycleState =
  | "absent" | "installing" | "installed" | "loading" | "loaded_idle"
  | "serving" | "draining" | "unloading" | "failed";

export interface ResourceAmount {
  readonly memoryBytes: number;
  readonly vramBytes: number;
  readonly diskBytes: number;
}

export interface ModelRequirements extends ResourceAmount {
  readonly runtime: string;
}

export interface HostModelObservation {
  readonly modelId: string;
  /** Lifecycle state of the model on this host. "serving"/"loaded_idle" place freely; "draining" closes admission. */
  readonly state: ModelLifecycleState;
  /** Concurrent in-flight inference requests bound to this model (load signal). */
  readonly activeRequests: number;
  readonly installed: boolean;
  readonly managedTemporary: boolean;
  readonly pinned: boolean;
  /** Optional capability snapshot used for capability-eligibility placement checks. */
  readonly capability?: ObservedModelCapability | null;
}

export interface HostSnapshot {
  readonly hostId: string;
  readonly authorized: boolean;
  readonly online: boolean;
  readonly observationFresh: boolean;
  /** Revocation state (peer/cert revoked). Absent/`false` = not revoked. */
  readonly revoked?: boolean;
  /** Host-level admission control. Absent/"active" = accepting traffic; "drain" = rejecting. */
  readonly admission?: "active" | "drain";
  /** Explicit resource-observation validity; false always fails closed. */
  readonly resourcesKnown?: boolean;
  /** Current and maximum concurrent model-load operations, when constrained. */
  readonly activeLoads?: number;
  readonly maxConcurrentLoads?: number;
  readonly runtimes: readonly string[];
  readonly available: ResourceAmount;
  readonly reserve: ResourceAmount;
  readonly models: readonly HostModelObservation[];
}

export interface PlacementRequest {
  readonly modelId: string;
  readonly requirements: ModelRequirements;
  /** Concurrency headroom cap for a loaded/serving model (positive integer). `null` = no cap. */
  readonly maxConcurrentRequests?: number | null;
  /** Optional 13.1 capability profile. When present, a model must be capability-eligible to be placed. */
  readonly profile?: CapabilityProfile | null;
}

export interface PlacementCandidate {
  readonly hostId: string;
  /** Deterministic, higher-is-better preference score. Bounded so it never crosses placement bands. */
  readonly score: number;
  /** Whether the model must be acquired (install) or is already present on the host. */
  readonly acquisition: "none" | "install";
  /** Redacted, canonical preference reasons (never topology: no endpoints/digests/snapshots). */
  readonly reasons: readonly string[];
  /** Active requests bound to the selected model, where known. */
  readonly activeRequests: number;
}

export interface PlacementRejection {
  readonly hostId: string;
  readonly reasons: readonly string[];
}

export interface PlacementPlan {
  readonly selected: PlacementCandidate | null;
  readonly candidates: readonly PlacementCandidate[];
  readonly rejected: readonly PlacementRejection[];
}
