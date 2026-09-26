import {
  parseProtocolId,
  parseUtcTimestamp,
  type HostId,
  type ParseResult,
  type UtcTimestamp,
} from "./protocol.js";

declare const byteAmountBrand: unique symbol;
export type ByteAmount = number & { readonly __brand: typeof byteAmountBrand };
export type AcceleratorKind = "nvidia" | "amd" | "intel" | "apple" | "other";
export type HostPlatform = "linux" | "darwin" | "windows";

export interface ResourceQuantity {
  readonly totalBytes: ByteAmount;
  readonly usedBytes: ByteAmount;
  readonly availableBytes: ByteAmount;
}
export interface AcceleratorObservation {
  readonly id: string;
  readonly name: string;
  readonly kind: AcceleratorKind;
  readonly memory: ResourceQuantity;
  readonly utilizationPercent: number | null;
}
export interface HostResourceObservation {
  readonly hostId: HostId;
  readonly observedAt: UtcTimestamp;
  readonly platform: HostPlatform;
  readonly cpuLogicalCores: number;
  readonly cpuUtilizationPercent: number | null;
  readonly memory: ResourceQuantity;
  readonly storage: ResourceQuantity;
  readonly accelerators: readonly AcceleratorObservation[];
}

const fail = <T>(error: string): ParseResult<T> => ({ ok: false, error });
const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;
const SAFE_NAME_PATTERN = /^[^\u0000-\u001f\u007f]+$/;

function descriptors(
  input: unknown,
  keys: readonly string[],
  error: string,
): ParseResult<Record<string, PropertyDescriptor>> {
  if (typeof input !== "object" || input === null) return fail(error);
  try {
    if (Array.isArray(input)) return fail(error);
    const prototype = Object.getPrototypeOf(input);
    if (prototype !== Object.prototype && prototype !== null) return fail(error);
    const ownKeys = Reflect.ownKeys(input);
    if (
      ownKeys.length !== keys.length ||
      ownKeys.some((key) => typeof key !== "string" || !keys.includes(key)) ||
      keys.some((key) => !ownKeys.includes(key))
    ) return fail(error);
    const result = Object.getOwnPropertyDescriptors(input);
    if (keys.some((key) => !result[key] || !("value" in result[key]))) return fail(error);
    return { ok: true, value: result };
  } catch {
    return fail(error);
  }
}

export function parseByteAmount(input: unknown): ParseResult<ByteAmount> {
  return typeof input === "number" && Number.isSafeInteger(input) && input >= 0
    ? { ok: true, value: input as ByteAmount }
    : fail("ERR_BYTE_AMOUNT");
}

export function parseResourceQuantity(input: unknown): ParseResult<ResourceQuantity> {
  const fields = descriptors(input, ["totalBytes", "usedBytes", "availableBytes"], "ERR_RESOURCE_QUANTITY");
  if (!fields.ok) return fields;
  const total = parseByteAmount(fields.value.totalBytes?.value as unknown);
  const used = parseByteAmount(fields.value.usedBytes?.value as unknown);
  const available = parseByteAmount(fields.value.availableBytes?.value as unknown);
  if (!total.ok || !used.ok || !available.ok) return fail("ERR_RESOURCE_QUANTITY");
  if (used.value > total.value || available.value > total.value || used.value + available.value > total.value) {
    return fail("ERR_RESOURCE_INVARIANT");
  }
  const output = Object.create(null) as Record<string, unknown>;
  output.totalBytes = total.value;
  output.usedBytes = used.value;
  output.availableBytes = available.value;
  return { ok: true, value: Object.freeze(output) as unknown as ResourceQuantity };
}

function parsePercent(input: unknown): ParseResult<number | null> {
  return input === null || (typeof input === "number" && Number.isInteger(input) && input >= 0 && input <= 100)
    ? { ok: true, value: input }
    : fail("ERR_UTILIZATION");
}

export function parseAcceleratorObservation(input: unknown): ParseResult<AcceleratorObservation> {
  const fields = descriptors(input, ["id", "name", "kind", "memory", "utilizationPercent"], "ERR_ACCELERATOR");
  if (!fields.ok) return fields;
  const id = fields.value.id?.value as unknown;
  const name = fields.value.name?.value as unknown;
  const kind = fields.value.kind?.value as unknown;
  if (typeof id !== "string" || id.length < 1 || id.length > 128 || !ID_PATTERN.test(id)) return fail("ERR_ACCELERATOR_ID");
  if (typeof name !== "string" || name.length < 1 || name.length > 256 || !SAFE_NAME_PATTERN.test(name)) return fail("ERR_ACCELERATOR_NAME");
  if (kind !== "nvidia" && kind !== "amd" && kind !== "intel" && kind !== "apple" && kind !== "other") return fail("ERR_ACCELERATOR_KIND");
  const memory = parseResourceQuantity(fields.value.memory?.value as unknown);
  if (!memory.ok) return fail("ERR_ACCELERATOR_MEMORY");
  const utilization = parsePercent(fields.value.utilizationPercent?.value as unknown);
  if (!utilization.ok) return utilization;
  const output = Object.create(null) as Record<string, unknown>;
  Object.assign(output, { id, name, kind, memory: memory.value, utilizationPercent: utilization.value });
  return { ok: true, value: Object.freeze(output) as unknown as AcceleratorObservation };
}

function parseAccelerators(input: unknown): ParseResult<readonly AcceleratorObservation[]> {
  try {
    if (!Array.isArray(input)) return fail("ERR_ACCELERATORS");
    const keys = Reflect.ownKeys(input);
    const fieldDescriptors = Object.getOwnPropertyDescriptors(input);
    const lengthDescriptor: PropertyDescriptor | undefined = Object.getOwnPropertyDescriptor(input, "length");
    const length = lengthDescriptor?.value as unknown;
    if (!Number.isSafeInteger(length) || (length as number) < 0 || (length as number) > 32) return fail("ERR_ACCELERATORS");
    if (keys.some((key) => typeof key !== "string" || (key !== "length" && !/^(0|[1-9][0-9]*)$/.test(key)))) return fail("ERR_ACCELERATORS");
    const output: AcceleratorObservation[] = [];
    const ids = new Set<string>();
    for (let index = 0; index < (length as number); index += 1) {
      const field = fieldDescriptors[String(index)];
      if (!field || !("value" in field)) return fail("ERR_ACCELERATORS");
      const accelerator = parseAcceleratorObservation(field.value as unknown);
      if (!accelerator.ok) return accelerator;
      if (ids.has(accelerator.value.id)) return fail("ERR_DUPLICATE_ACCELERATOR");
      ids.add(accelerator.value.id);
      output.push(accelerator.value);
    }
    return { ok: true, value: Object.freeze(output) };
  } catch {
    return fail("ERR_ACCELERATORS");
  }
}

export function parseHostResourceObservation(input: unknown): ParseResult<HostResourceObservation> {
  const fields = descriptors(input, [
    "hostId", "observedAt", "platform", "cpuLogicalCores", "cpuUtilizationPercent",
    "memory", "storage", "accelerators",
  ], "ERR_HOST_OBSERVATION");
  if (!fields.ok) return fields;
  const hostId = parseProtocolId("host", fields.value.hostId?.value as unknown);
  if (!hostId.ok) return fail("ERR_HOST_ID");
  const observedAt = parseUtcTimestamp(fields.value.observedAt?.value as unknown);
  if (!observedAt.ok) return fail("ERR_OBSERVED_AT");
  const platform = fields.value.platform?.value as unknown;
  if (platform !== "linux" && platform !== "darwin" && platform !== "windows") return fail("ERR_PLATFORM");
  const cores = fields.value.cpuLogicalCores?.value as unknown;
  if (typeof cores !== "number" || !Number.isSafeInteger(cores) || cores < 1 || cores > 4096) return fail("ERR_CPU_CORES");
  const cpu = parsePercent(fields.value.cpuUtilizationPercent?.value as unknown);
  if (!cpu.ok) return fail("ERR_CPU_UTILIZATION");
  const memory = parseResourceQuantity(fields.value.memory?.value as unknown);
  if (!memory.ok) return fail("ERR_HOST_MEMORY");
  const storage = parseResourceQuantity(fields.value.storage?.value as unknown);
  if (!storage.ok) return fail("ERR_HOST_STORAGE");
  const accelerators = parseAccelerators(fields.value.accelerators?.value as unknown);
  if (!accelerators.ok) return accelerators;
  const output = Object.create(null) as Record<string, unknown>;
  Object.assign(output, {
    hostId: hostId.value, observedAt: observedAt.value, platform, cpuLogicalCores: cores,
    cpuUtilizationPercent: cpu.value, memory: memory.value, storage: storage.value,
    accelerators: accelerators.value,
  });
  return { ok: true, value: Object.freeze(output) as unknown as HostResourceObservation };
}
