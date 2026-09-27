import { posix, win32 } from "node:path";

export const CONTROLLER_CONFIG_KEYS = Object.freeze([
  "bindHost",
  "port",
  "inferenceHost",
  "inferencePort",
  "dataDir",
  "logLevel",
  "discoveryEnabled",
  "publicInferenceEnabled",
  "tlsRequired",
  "mutualTlsRequired",
] as const);

export const CONTROLLER_ENV_KEYS = Object.freeze([
  "LANMM_BIND_HOST",
  "LANMM_PORT",
  "LANMM_INFERENCE_HOST",
  "LANMM_INFERENCE_PORT",
  "LANMM_DATA_DIR",
  "LANMM_LOG_LEVEL",
  "LANMM_DISCOVERY_ENABLED",
  "LANMM_PUBLIC_INFERENCE_ENABLED",
  "LANMM_TLS_REQUIRED",
  "LANMM_MUTUAL_TLS_REQUIRED",
] as const);

export const CONTROLLER_LOG_LEVELS = Object.freeze([
  "error",
  "warn",
  "info",
  "debug",
] as const);

export type ControllerLogLevel = (typeof CONTROLLER_LOG_LEVELS)[number];

export type ControllerConfigError =
  | "ERR_CONFIG_OBJECT"
  | "ERR_CONFIG_KEYS"
  | "ERR_CONFIG_ACCESSOR"
  | "ERR_CONFIG_HOST"
  | "ERR_CONFIG_PORT"
  | "ERR_CONFIG_PORT_CONFLICT"
  | "ERR_CONFIG_BOOLEAN"
  | "ERR_CONFIG_DATA_DIR"
  | "ERR_CONFIG_LOG_LEVEL"
  | "ERR_CONFIG_TLS"
  | "ERR_CONFIG_PUBLIC_INFERENCE"
  | "ERR_ENV_OBJECT"
  | "ERR_ENV_KEYS"
  | "ERR_ENV_ACCESSOR"
  | "ERR_ENV_VALUE"
  | "ERR_PATH_FLAVOR";

export type ControllerConfigResult<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly error: ControllerConfigError };

export interface ControllerConfig {
  readonly bindHost: string;
  readonly port: number;
  readonly inferenceHost: string;
  readonly inferencePort: number;
  readonly dataDir: string;
  readonly logLevel: ControllerLogLevel;
  readonly discoveryEnabled: boolean;
  readonly publicInferenceEnabled: boolean;
  readonly tlsRequired: boolean;
  readonly mutualTlsRequired: boolean;
}

export interface ControllerPathPlan {
  readonly rootDir: string;
  readonly databasePath: string;
  readonly artifactDir: string;
  readonly cacheDir: string;
  readonly stagingDir: string;
  readonly quarantineDir: string;
  readonly auditDir: string;
}

export type ControllerPathFlavor = "posix" | "win32";

/**
 * Ambient state is deliberately absent from the parser. Callers that want a
 * default data root must derive it at their application boundary and supply it.
 */
export interface ControllerConfigParseOptions {
  readonly defaultDataRoot?: unknown;
  readonly pathFlavor?: ControllerPathFlavor;
}

type DataDescriptors = Record<PropertyKey, PropertyDescriptor>;
type PathApi = typeof posix | typeof win32;

const CONFIG_KEY_SET = new Set<string>(CONTROLLER_CONFIG_KEYS);
const ENV_KEY_SET = new Set<string>(CONTROLLER_ENV_KEYS);
const LOG_LEVEL_SET = new Set<unknown>(CONTROLLER_LOG_LEVELS);
const DEFAULT_PORT = 7340;
const DEFAULT_INFERENCE_PORT = 7341;

function fail<T>(error: ControllerConfigError): ControllerConfigResult<T> {
  return { ok: false, error };
}

function frozenNullObject<T>(values: Record<string, unknown>): T {
  return Object.freeze(Object.assign(Object.create(null), values)) as T;
}

function inspectPlainRecord(
  input: unknown,
  objectError: ControllerConfigError,
  keysError: ControllerConfigError,
  accessorError: ControllerConfigError,
  allowedKeys?: ReadonlySet<string>,
  ignoreUnrelated = false,
): ControllerConfigResult<DataDescriptors> {
  try {
    if (typeof input !== "object" || input === null || Array.isArray(input)) return fail(objectError);
    const prototype = Object.getPrototypeOf(input);
    if (prototype !== Object.prototype && prototype !== null) return fail(objectError);
    const keys = Reflect.ownKeys(input);
    if (keys.some((key) => typeof key !== "string")) return fail(keysError);
    if (allowedKeys && keys.some((key) => {
      if (typeof key !== "string") return true;
      return ignoreUnrelated ? key.startsWith("LANMM_") && !allowedKeys.has(key) : !allowedKeys.has(key);
    })) return fail(keysError);
    const descriptors = Object.getOwnPropertyDescriptors(input);
    for (const key of keys) {
      if (typeof key !== "string") return fail(keysError);
      const descriptor = descriptors[key];
      if (!descriptor || !("value" in descriptor)) return fail(accessorError);
    }
    return { ok: true, value: descriptors };
  } catch {
    return fail(objectError);
  }
}

function ownValue(descriptors: DataDescriptors, key: string): { readonly present: boolean; readonly value: unknown } {
  const descriptor = descriptors[key];
  return descriptor && "value" in descriptor
    ? { present: true, value: descriptor.value as unknown }
    : { present: false, value: undefined };
}

function isLoopbackHost(value: unknown): value is string {
  if (typeof value !== "string" || value.length === 0 || value.length > 45 || value.includes("\0")) return false;
  if (value === "localhost" || value === "::1" || value === "0:0:0:0:0:0:0:1") return true;
  const octets = value.split(".");
  if (octets.length !== 4 || octets[0] !== "127") return false;
  return octets.every((octet) => /^(0|[1-9][0-9]{0,2})$/.test(octet) && Number(octet) <= 255);
}

function isPort(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 1 && value <= 65_535;
}

function isLogLevel(value: unknown): value is ControllerLogLevel {
  return LOG_LEVEL_SET.has(value);
}

function nativeFlavor(): ControllerPathFlavor {
  return process.platform === "win32" ? "win32" : "posix";
}

function pathApi(flavor: ControllerPathFlavor): PathApi {
  return flavor === "win32" ? win32 : posix;
}

function validateAbsoluteDataDir(value: unknown, flavor: ControllerPathFlavor): value is string {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0") || /[\u0001-\u001f\u007f]/.test(value)) return false;
  if (value.trim() !== value) return false;
  const api = pathApi(flavor);
  if (!api.isAbsolute(value) || api.normalize(value) !== value || value === api.parse(value).root || value.endsWith(api.sep)) return false;
  if (flavor === "posix") {
    if (value.includes("\\")) return false;
    return !value.split("/").some((part) => part === "." || part === "..");
  }
  if (value.includes("/") || !/^[A-Za-z]:\\/.test(value) || value.startsWith("\\\\")) return false;
  const components = value.slice(3).split("\\");
  const reserved = /^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$/i;
  return !components.some((part) =>
    part.length === 0 || part === "." || part === ".." || part.endsWith(".") || part.endsWith(" ") ||
    /[<>:"|?*]/.test(part) || reserved.test(part)
  );
}

/** Build an immutable local-state path plan without performing file-system I/O. */
export function createControllerPathPlan(
  rootInput: unknown,
  flavor: ControllerPathFlavor = nativeFlavor(),
): ControllerConfigResult<ControllerPathPlan> {
  try {
    if (flavor !== "posix" && flavor !== "win32") return fail("ERR_PATH_FLAVOR");
    if (!validateAbsoluteDataDir(rootInput, flavor)) return fail("ERR_CONFIG_DATA_DIR");
    const api = pathApi(flavor);
    const rootDir = rootInput;
    const children = {
      databasePath: api.join(rootDir, "controller.sqlite3"),
      artifactDir: api.join(rootDir, "artifacts"),
      cacheDir: api.join(rootDir, "cache"),
      stagingDir: api.join(rootDir, "staging"),
      quarantineDir: api.join(rootDir, "quarantine"),
      auditDir: api.join(rootDir, "audit"),
    } as const;
    for (const child of Object.values(children)) {
      const relative = api.relative(rootDir, child);
      if (relative.length === 0 || relative === ".." || relative.startsWith(`..${api.sep}`) || api.isAbsolute(relative)) {
        return fail("ERR_CONFIG_DATA_DIR");
      }
    }
    return { ok: true, value: frozenNullObject<ControllerPathPlan>({ rootDir, ...children }) };
  } catch {
    return fail("ERR_CONFIG_DATA_DIR");
  }
}

/**
 * Parse a strict plain record without coercion, property access, file-system I/O,
 * or working-directory lookup. Log-level spelling is exact and lowercase.
 */
export function parseControllerConfig(
  input: unknown,
  options: ControllerConfigParseOptions = {},
): ControllerConfigResult<ControllerConfig> {
  try {
    const inspected = inspectPlainRecord(
      input,
      "ERR_CONFIG_OBJECT",
      "ERR_CONFIG_KEYS",
      "ERR_CONFIG_ACCESSOR",
      CONFIG_KEY_SET,
    );
    if (!inspected.ok) return inspected;
    const descriptors = inspected.value;
    const bindHostField = ownValue(descriptors, "bindHost");
    const portField = ownValue(descriptors, "port");
    const inferenceHostField = ownValue(descriptors, "inferenceHost");
    const inferencePortField = ownValue(descriptors, "inferencePort");
    const dataDirField = ownValue(descriptors, "dataDir");
    const logLevelField = ownValue(descriptors, "logLevel");
    const discoveryField = ownValue(descriptors, "discoveryEnabled");
    const publicInferenceField = ownValue(descriptors, "publicInferenceEnabled");
    const tlsField = ownValue(descriptors, "tlsRequired");
    const mutualTlsField = ownValue(descriptors, "mutualTlsRequired");

    const bindHost = bindHostField.present ? bindHostField.value : "127.0.0.1";
    const port = portField.present ? portField.value : DEFAULT_PORT;
    const inferenceHost = inferenceHostField.present ? inferenceHostField.value : "127.0.0.1";
    const inferencePort = inferencePortField.present ? inferencePortField.value : DEFAULT_INFERENCE_PORT;
    const flavor = options.pathFlavor ?? nativeFlavor();
    if (flavor !== "posix" && flavor !== "win32") return fail("ERR_PATH_FLAVOR");
    const dataDir = dataDirField.present ? dataDirField.value : options.defaultDataRoot;
    const logLevel = logLevelField.present ? logLevelField.value : "info";
    const discoveryEnabled = discoveryField.present ? discoveryField.value : false;
    const publicInferenceEnabled = publicInferenceField.present ? publicInferenceField.value : false;
    const tlsRequired = tlsField.present ? tlsField.value : true;
    const mutualTlsRequired = mutualTlsField.present ? mutualTlsField.value : true;

    if (!isLoopbackHost(bindHost) || !isLoopbackHost(inferenceHost)) return fail("ERR_CONFIG_HOST");
    if (!isPort(port) || !isPort(inferencePort)) return fail("ERR_CONFIG_PORT");
    if (port === inferencePort) return fail("ERR_CONFIG_PORT_CONFLICT");
    if (!isLogLevel(logLevel)) return fail("ERR_CONFIG_LOG_LEVEL");
    if ([discoveryEnabled, publicInferenceEnabled, tlsRequired, mutualTlsRequired].some((value) => typeof value !== "boolean")) {
      return fail("ERR_CONFIG_BOOLEAN");
    }
    if (!validateAbsoluteDataDir(dataDir, flavor)) return fail("ERR_CONFIG_DATA_DIR");
    if (mutualTlsRequired && !tlsRequired) return fail("ERR_CONFIG_TLS");
    // TLS may be deliberately disabled only because both listeners are constrained
    // above to canonical loopback hosts. Public inference remains unavailable.
    if (publicInferenceEnabled) return fail("ERR_CONFIG_PUBLIC_INFERENCE");

    return {
      ok: true,
      value: frozenNullObject<ControllerConfig>({
        bindHost,
        port,
        inferenceHost,
        inferencePort,
        dataDir,
        logLevel,
        discoveryEnabled,
        publicInferenceEnabled,
        tlsRequired,
        mutualTlsRequired,
      }),
    };
  } catch {
    return fail("ERR_CONFIG_OBJECT");
  }
}

function parseEnvPort(value: string): number | null {
  if (!/^(?:[1-9][0-9]{0,4})$/.test(value)) return null;
  const parsed = Number(value);
  return isPort(parsed) ? parsed : null;
}

function parseEnvBoolean(value: string): boolean | null {
  if (value === "true") return true;
  if (value === "false") return false;
  return null;
}

/**
 * Adapt an explicitly supplied environment record. Unrelated variables are ignored;
 * unknown LANMM_* variables and non-string values are rejected.
 */
export function parseControllerEnvironment(
  input: unknown,
  options: ControllerConfigParseOptions = {},
): ControllerConfigResult<ControllerConfig> {
  try {
    const inspected = inspectPlainRecord(
      input,
      "ERR_ENV_OBJECT",
      "ERR_ENV_KEYS",
      "ERR_ENV_ACCESSOR",
      ENV_KEY_SET,
      true,
    );
    if (!inspected.ok) return inspected;
    const raw = inspected.value;
    const config = Object.create(null) as Record<string, unknown>;
    const mappings = [
      ["LANMM_BIND_HOST", "bindHost", "string"],
      ["LANMM_PORT", "port", "port"],
      ["LANMM_INFERENCE_HOST", "inferenceHost", "string"],
      ["LANMM_INFERENCE_PORT", "inferencePort", "port"],
      ["LANMM_DATA_DIR", "dataDir", "string"],
      ["LANMM_LOG_LEVEL", "logLevel", "string"],
      ["LANMM_DISCOVERY_ENABLED", "discoveryEnabled", "boolean"],
      ["LANMM_PUBLIC_INFERENCE_ENABLED", "publicInferenceEnabled", "boolean"],
      ["LANMM_TLS_REQUIRED", "tlsRequired", "boolean"],
      ["LANMM_MUTUAL_TLS_REQUIRED", "mutualTlsRequired", "boolean"],
    ] as const;
    for (const [envKey, configKey, kind] of mappings) {
      const field = ownValue(raw, envKey);
      if (!field.present) continue;
      if (typeof field.value !== "string") return fail("ERR_ENV_VALUE");
      if (kind === "string") {
        config[configKey] = field.value;
      } else if (kind === "port") {
        const parsed = parseEnvPort(field.value);
        if (parsed === null) return fail("ERR_CONFIG_PORT");
        config[configKey] = parsed;
      } else {
        const parsed = parseEnvBoolean(field.value);
        if (parsed === null) return fail("ERR_CONFIG_BOOLEAN");
        config[configKey] = parsed;
      }
    }
    return parseControllerConfig(config, options);
  } catch {
    return fail("ERR_ENV_OBJECT");
  }
}
