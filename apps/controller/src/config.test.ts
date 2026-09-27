import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { posix, win32 } from "node:path";
import test from "node:test";
import {
  CONTROLLER_CONFIG_KEYS,
  CONTROLLER_ENV_KEYS,
  CONTROLLER_LOG_LEVELS,
  createControllerPathPlan,
  parseControllerConfig,
  parseControllerEnvironment,
  type ControllerConfigParseOptions,
} from "./config.js";

const nativeFlavor = process.platform === "win32" ? "win32" : "posix";
const nativeRoot = process.platform === "win32" ? "C:\\lanmm-data" : "/tmp/lanmm-data";
const nativeOptions: ControllerConfigParseOptions = {
  defaultDataRoot: nativeRoot,
  pathFlavor: nativeFlavor,
};
const fullConfig = () => ({
  bindHost: "127.0.0.1",
  port: 7340,
  inferenceHost: "::1",
  inferencePort: 7341,
  dataDir: nativeRoot,
  logLevel: "info",
  discoveryEnabled: false,
  publicInferenceEnabled: false,
  tlsRequired: true,
  mutualTlsRequired: true,
});

function errorOf(result: ReturnType<typeof parseControllerConfig>): string | null {
  return result.ok ? null : result.error;
}

test("configuration defaults are conservative, caller-rooted, detached, frozen, and exact", () => {
  const input = Object.create(null) as Record<string, unknown>;
  const result = parseControllerConfig(input, nativeOptions);
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.deepEqual(Object.keys(result.value), [...CONTROLLER_CONFIG_KEYS]);
  assert.equal(result.value.bindHost, "127.0.0.1");
  assert.equal(result.value.port, 7340);
  assert.equal(result.value.inferenceHost, "127.0.0.1");
  assert.equal(result.value.inferencePort, 7341);
  assert.equal(result.value.dataDir, nativeRoot);
  assert.equal(result.value.logLevel, "info");
  assert.equal(result.value.discoveryEnabled, false);
  assert.equal(result.value.publicInferenceEnabled, false);
  assert.equal(result.value.tlsRequired, true);
  assert.equal(result.value.mutualTlsRequired, true);
  assert.equal(Object.getPrototypeOf(result.value), null);
  assert.equal(Object.isFrozen(result.value), true);
  input.port = 9000;
  assert.equal(result.value.port, 7340);
  assert.throws(() => Object.assign(result.value, { port: 9000 }), TypeError);
});

test("state-root default is explicit and parsing performs no filesystem creation", () => {
  assert.deepEqual(parseControllerConfig({}), { ok: false, error: "ERR_CONFIG_DATA_DIR" });
  const root = process.platform === "win32"
    ? `C:\\lanmm-never-create-${process.pid}`
    : `/tmp/lanmm-never-create-${process.pid}`;
  assert.equal(existsSync(root), false);
  const first = parseControllerConfig({}, { defaultDataRoot: root, pathFlavor: nativeFlavor });
  const second = parseControllerConfig({}, { defaultDataRoot: root, pathFlavor: nativeFlavor });
  assert.deepEqual(first, second);
  assert.equal(first.ok, true);
  assert.equal(existsSync(root), false);
  assert.deepEqual(
    parseControllerConfig({}, { defaultDataRoot: root, pathFlavor: "bogus" as "posix" }),
    { ok: false, error: "ERR_PATH_FLAVOR" },
  );
});

test("log levels use an exact lowercase allowlist with info as the default", () => {
  assert.deepEqual(CONTROLLER_LOG_LEVELS, ["error", "warn", "info", "debug"]);
  for (const logLevel of CONTROLLER_LOG_LEVELS) {
    const result = parseControllerConfig({ ...fullConfig(), logLevel });
    assert.equal(result.ok, true, logLevel);
    if (result.ok) assert.equal(result.value.logLevel, logLevel);
  }
  for (const logLevel of ["", "INFO", "Error", "warning", "trace", " info", "info ", null, undefined, 1, true]) {
    assert.equal(errorOf(parseControllerConfig({ ...fullConfig(), logLevel })), "ERR_CONFIG_LOG_LEVEL", String(logLevel));
  }
});

test("configuration accepts only canonical loopback literals", () => {
  for (const host of ["localhost", "127.0.0.1", "127.1.2.3", "::1", "0:0:0:0:0:0:0:1"]) {
    assert.equal(parseControllerConfig({ ...fullConfig(), bindHost: host }).ok, true, host);
    assert.equal(parseControllerConfig({ ...fullConfig(), inferenceHost: host }).ok, true, host);
  }
  for (const host of [
    "0.0.0.0", "::", "192.168.1.2", "8.8.8.8", "example.com", "LOCALHOST", "localhost.",
    "http://127.0.0.1", "user:pass@127.0.0.1", "127.0.0.1:7340", "127.00.0.1", "[::1]", "::1%lo",
    "", " 127.0.0.1", "127.0.0.1 ",
  ]) {
    assert.equal(errorOf(parseControllerConfig({ ...fullConfig(), bindHost: host })), "ERR_CONFIG_HOST", host);
    assert.equal(errorOf(parseControllerConfig({ ...fullConfig(), inferenceHost: host })), "ERR_CONFIG_HOST", host);
  }
});

test("ports enforce integer boundaries and cannot collide", () => {
  for (const port of [1, 65_535]) assert.equal(parseControllerConfig({ ...fullConfig(), port }).ok, true);
  for (const port of [0, -1, 65_536, 1.5, NaN, Infinity, "7340", null]) {
    assert.equal(errorOf(parseControllerConfig({ ...fullConfig(), port })), "ERR_CONFIG_PORT");
  }
  assert.equal(errorOf(parseControllerConfig({ ...fullConfig(), inferencePort: 7340 })), "ERR_CONFIG_PORT_CONFLICT");
});

test("booleans are not coerced and TLS invariants cover every combination", () => {
  for (const value of ["false", 0, 1, null, undefined]) {
    assert.equal(errorOf(parseControllerConfig({ ...fullConfig(), discoveryEnabled: value })), "ERR_CONFIG_BOOLEAN");
  }
  const combinations = [
    [true, true, true],
    [true, false, true],
    [false, false, true],
    [false, true, false],
  ] as const;
  for (const [tlsRequired, mutualTlsRequired, accepted] of combinations) {
    const result = parseControllerConfig({ ...fullConfig(), tlsRequired, mutualTlsRequired });
    assert.equal(result.ok, accepted, `${tlsRequired}/${mutualTlsRequired}`);
    if (!accepted) assert.equal(errorOf(result), "ERR_CONFIG_TLS");
  }
});

test("TLS-off is deliberate loopback development only and public inference always fails closed", () => {
  assert.equal(parseControllerConfig({ ...fullConfig(), tlsRequired: false, mutualTlsRequired: false }).ok, true);
  assert.equal(
    errorOf(parseControllerConfig({ ...fullConfig(), bindHost: "0.0.0.0", tlsRequired: false, mutualTlsRequired: false })),
    "ERR_CONFIG_HOST",
  );
  for (const [tlsRequired, mutualTlsRequired] of [[true, true], [true, false], [false, false]] as const) {
    assert.equal(
      errorOf(parseControllerConfig({ ...fullConfig(), publicInferenceEnabled: true, tlsRequired, mutualTlsRequired })),
      "ERR_CONFIG_PUBLIC_INFERENCE",
    );
  }
});

test("configuration rejects non-records, custom prototypes, symbols, unknown/legacy keys, and accessors", () => {
  for (const input of [null, undefined, true, 1, "x", [], new Date(), Object.create({})]) {
    assert.equal(parseControllerConfig(input, nativeOptions).ok, false);
  }
  for (const legacy of ["tlsEnabled", "mutualTlsEnabled"]) {
    assert.equal(errorOf(parseControllerConfig({ ...fullConfig(), [legacy]: true })), "ERR_CONFIG_KEYS");
  }
  assert.equal(errorOf(parseControllerConfig({ ...fullConfig(), extra: true })), "ERR_CONFIG_KEYS");
  assert.equal(errorOf(parseControllerConfig({ ...fullConfig(), [Symbol("extra")]: true })), "ERR_CONFIG_KEYS");
  let getterCalls = 0;
  const getter = { ...fullConfig() };
  Object.defineProperty(getter, "port", { enumerable: true, get() { getterCalls += 1; return 7340; } });
  assert.equal(errorOf(parseControllerConfig(getter)), "ERR_CONFIG_ACCESSOR");
  assert.equal(getterCalls, 0);
});

test("configuration is non-throwing for revoked and hostile proxies", () => {
  const revocable = Proxy.revocable({}, {});
  revocable.revoke();
  assert.doesNotThrow(() => parseControllerConfig(revocable.proxy, nativeOptions));
  assert.equal(parseControllerConfig(revocable.proxy, nativeOptions).ok, false);
  for (const trap of ["getPrototypeOf", "ownKeys", "getOwnPropertyDescriptor"] as const) {
    const target = trap === "getOwnPropertyDescriptor" ? { port: 7340 } : {};
    const hostile = new Proxy(target, { [trap]() { throw new Error("hostile"); } });
    assert.doesNotThrow(() => parseControllerConfig(hostile, nativeOptions));
    assert.equal(parseControllerConfig(hostile, nativeOptions).ok, false);
  }
});

test("path plans accept contained POSIX and Windows roots without filesystem mutation", () => {
  const cases = [
    ["/var/lib/lanmm", "posix", "/"] as const,
    ["C:\\ProgramData\\LANMM", "win32", "\\"] as const,
  ];
  for (const [root, flavor, separator] of cases) {
    const result = createControllerPathPlan(root, flavor);
    assert.equal(result.ok, true);
    if (!result.ok) continue;
    assert.equal(result.value.rootDir, root);
    assert.equal(result.value.databasePath, `${root}${separator}controller.sqlite3`);
    for (const [key, value] of Object.entries(result.value)) {
      assert.equal(typeof value, "string");
      if (key !== "rootDir") {
        const api = flavor === "posix" ? posix : win32;
        const relative = api.relative(root, value);
        assert.equal(relative.startsWith(".."), false);
        assert.equal(api.isAbsolute(relative), false);
      }
    }
    assert.equal(Object.getPrototypeOf(result.value), null);
    assert.equal(Object.isFrozen(result.value), true);
  }
});

test("path plans reject relative, root, unnormalized, traversal, NUL, and cross-flavor paths", () => {
  for (const root of ["data", "/", "/tmp/../var/lanmm", "/tmp//lanmm", "/tmp/lanmm/", "/tmp/lanmm\\escape", "/tmp/lan\0mm", " C:\\data"]) {
    assert.equal(createControllerPathPlan(root, "posix").ok, false, root);
  }
  for (const root of ["data", "C:\\", "C:\\data\\..\\other", "C:\\data\\", "C:/data", "\\\\server\\share", "C:\\data\0x", "C:\\data\\CON"]) {
    assert.equal(createControllerPathPlan(root, "win32").ok, false, root);
  }
  assert.deepEqual(createControllerPathPlan("/tmp/data", "bogus" as "posix"), { ok: false, error: "ERR_PATH_FLAVOR" });
});

test("environment adapter allowlists variables and accepts every exact log level", () => {
  for (const logLevel of CONTROLLER_LOG_LEVELS) {
    const env = {
      PATH: "/synthetic/bin",
      LANMM_BIND_HOST: "localhost",
      LANMM_PORT: "1",
      LANMM_INFERENCE_HOST: "127.0.0.2",
      LANMM_INFERENCE_PORT: "65535",
      LANMM_DATA_DIR: nativeRoot,
      LANMM_LOG_LEVEL: logLevel,
      LANMM_DISCOVERY_ENABLED: "false",
      LANMM_PUBLIC_INFERENCE_ENABLED: "false",
      LANMM_TLS_REQUIRED: "true",
      LANMM_MUTUAL_TLS_REQUIRED: "true",
    };
    const result = parseControllerEnvironment(env, nativeOptions);
    assert.equal(result.ok, true, logLevel);
    if (!result.ok) continue;
    assert.equal(result.value.port, 1);
    assert.equal(result.value.inferencePort, 65_535);
    assert.equal(result.value.logLevel, logLevel);
    assert.equal(result.value.tlsRequired, true);
    assert.equal(result.value.mutualTlsRequired, true);
  }
});

test("environment adapter rejects unknown, empty, wrong-case, legacy, and non-string values", () => {
  assert.equal(parseControllerEnvironment({ OTHER: "ignored" }, nativeOptions).ok, true);
  assert.deepEqual(parseControllerEnvironment({ LANMM_UNKNOWN: "x" }, nativeOptions), { ok: false, error: "ERR_ENV_KEYS" });
  for (const legacy of ["LANMM_TLS_ENABLED", "LANMM_MTLS_ENABLED"]) {
    assert.deepEqual(parseControllerEnvironment({ [legacy]: "true" }, nativeOptions), { ok: false, error: "ERR_ENV_KEYS" });
  }
  for (const value of ["0", "01", "+1", "1 ", "1.0", "65536", "NaN", 7340]) {
    assert.equal(parseControllerEnvironment({ LANMM_PORT: value }, nativeOptions).ok, false, String(value));
  }
  for (const value of ["TRUE", "False", "1", "0", "yes", "", true]) {
    assert.equal(parseControllerEnvironment({ LANMM_DISCOVERY_ENABLED: value }, nativeOptions).ok, false, String(value));
  }
  for (const value of ["", "INFO", "trace", 1, null, undefined]) {
    const result = parseControllerEnvironment({ LANMM_LOG_LEVEL: value }, nativeOptions);
    assert.equal(result.ok, false, String(value));
    assert.equal(result.ok ? null : result.error, typeof value === "string" ? "ERR_CONFIG_LOG_LEVEL" : "ERR_ENV_VALUE");
  }
  assert.deepEqual(CONTROLLER_ENV_KEYS, [
    "LANMM_BIND_HOST", "LANMM_PORT", "LANMM_INFERENCE_HOST", "LANMM_INFERENCE_PORT", "LANMM_DATA_DIR",
    "LANMM_LOG_LEVEL", "LANMM_DISCOVERY_ENABLED", "LANMM_PUBLIC_INFERENCE_ENABLED", "LANMM_TLS_REQUIRED",
    "LANMM_MUTUAL_TLS_REQUIRED",
  ]);
});

test("environment adapter rejects exotic records without invoking getters and never throws on proxies", () => {
  assert.equal(parseControllerEnvironment(Object.create({}), nativeOptions).ok, false);
  assert.equal(parseControllerEnvironment({ [Symbol("x")]: "x" }, nativeOptions).ok, false);
  let getterCalls = 0;
  const env = Object.defineProperty({}, "LANMM_PORT", { enumerable: true, get() { getterCalls += 1; return "7340"; } });
  assert.deepEqual(parseControllerEnvironment(env, nativeOptions), { ok: false, error: "ERR_ENV_ACCESSOR" });
  assert.equal(getterCalls, 0);
  const revoked = Proxy.revocable({}, {});
  revoked.revoke();
  assert.doesNotThrow(() => parseControllerEnvironment(revoked.proxy, nativeOptions));
  assert.equal(parseControllerEnvironment(revoked.proxy, nativeOptions).ok, false);
});
