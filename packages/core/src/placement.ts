import type {
  HostSnapshot, PlacementCandidate, PlacementPlan, PlacementRequest
} from "./types.js";

const usable = (available: number, reserve: number): number => Math.max(0, available - reserve);

function evaluateHost(host: HostSnapshot, request: PlacementRequest): {
  candidate?: PlacementCandidate;
  rejection?: readonly string[];
} {
  const rejected: string[] = [];
  if (!host.authorized) rejected.push("host is not authorized");
  if (!host.online) rejected.push("host is offline");
  if (!host.observationFresh) rejected.push("host observation is stale");
  if (!host.runtimes.includes(request.requirements.runtime)) {
    rejected.push(`runtime ${request.requirements.runtime} is unavailable`);
  }

  const observed = host.models.find((model) => model.modelId === request.modelId);
  const installed = observed?.installed === true;
  const memory = usable(host.available.memoryBytes, host.reserve.memoryBytes);
  const vram = usable(host.available.vramBytes, host.reserve.vramBytes);
  const disk = usable(host.available.diskBytes, host.reserve.diskBytes);

  if (memory < request.requirements.memoryBytes) rejected.push("insufficient memory after reserve");
  if (vram < request.requirements.vramBytes) rejected.push("insufficient VRAM after reserve");
  if (!installed && disk < request.requirements.diskBytes) rejected.push("insufficient storage after reserve");
  if (rejected.length > 0) return { rejection: rejected };

  const ready = observed?.state === "loaded_idle" || observed?.state === "serving";
  return {
    candidate: {
      hostId: host.hostId,
      score: (ready ? 1_000_000 : installed ? 500_000 : 0) +
        Math.floor(memory / 1_000_000_000) + Math.floor(vram / 1_000_000_000) * 2,
      acquisition: installed ? "none" : "install",
      reasons: [ready ? "model is already loaded" : installed
        ? "model is already installed" : "host can safely acquire the model"]
    }
  };
}

export function planPlacement(request: PlacementRequest, hosts: readonly HostSnapshot[]): PlacementPlan {
  const candidates: PlacementCandidate[] = [];
  const rejected: { hostId: string; reasons: readonly string[] }[] = [];
  for (const host of hosts) {
    const result = evaluateHost(host, request);
    if (result.candidate) candidates.push(result.candidate);
    if (result.rejection) rejected.push({ hostId: host.hostId, reasons: result.rejection });
  }
  candidates.sort((left, right) => right.score - left.score || left.hostId.localeCompare(right.hostId));
  return { selected: candidates[0] ?? null, candidates, rejected };
}
