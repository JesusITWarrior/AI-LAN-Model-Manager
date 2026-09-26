import type { HostModelObservation, ModelLifecycleState } from "./types.js";

const transitions: Readonly<Record<ModelLifecycleState, readonly ModelLifecycleState[]>> = {
  absent: ["installing"],
  installing: ["installed", "failed"],
  installed: ["loading", "absent", "failed"],
  loading: ["loaded_idle", "failed"],
  loaded_idle: ["serving", "unloading", "failed"],
  serving: ["draining", "failed"],
  draining: ["loaded_idle", "failed"],
  unloading: ["installed", "failed"],
  failed: ["absent", "installed", "loading"]
};

export function canTransition(from: ModelLifecycleState, to: ModelLifecycleState): boolean {
  return transitions[from].includes(to);
}

export function canUnload(model: HostModelObservation): boolean {
  return model.state === "loaded_idle" && model.activeRequests === 0;
}

export function canEvict(model: HostModelObservation): boolean {
  return model.installed && model.managedTemporary && !model.pinned &&
    model.activeRequests === 0 && model.state === "installed";
}
