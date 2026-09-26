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
  readonly state: ModelLifecycleState;
  readonly activeRequests: number;
  readonly installed: boolean;
  readonly managedTemporary: boolean;
  readonly pinned: boolean;
}

export interface HostSnapshot {
  readonly hostId: string;
  readonly authorized: boolean;
  readonly online: boolean;
  readonly observationFresh: boolean;
  readonly runtimes: readonly string[];
  readonly available: ResourceAmount;
  readonly reserve: ResourceAmount;
  readonly models: readonly HostModelObservation[];
}

export interface PlacementRequest {
  readonly modelId: string;
  readonly requirements: ModelRequirements;
}

export interface PlacementCandidate {
  readonly hostId: string;
  readonly score: number;
  readonly acquisition: "none" | "install";
  readonly reasons: readonly string[];
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
