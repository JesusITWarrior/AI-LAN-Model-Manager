import test from "node:test";
import assert from "node:assert/strict";
import {
  ERR_CUSTOM_PROVIDER_MANIFEST,
  parseCustomProviderManifest,
  type CustomProviderKind,
  type CustomProviderManifest,
  type CustomActionTemplate,
} from "./custom-provider.js";

/** One well-formed action template, rebuilt per test with overrides. */
function action(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    actionId: "probe",
    executable: "/usr/local/bin/probe",
    argv: ["probe", "--host"],
    env: { LOG_LEVEL: "info" },
    timeoutMs: 5000,
    maxOutputBytes: 8192,
    ...overrides,
  } as Record<string, unknown>;
}

/** A valid manifest, spread-modified for each test. */
function base(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schemaVersion: 1,
    providerId: "provider-1",
    kind: "host",
    actions: [action(), action({ actionId: "drain", executable: "/opt/lanmm/drain.sh" })],
    ...overrides,
  };
}

test("parses a minimal valid manifest into a detached, deeply frozen value", () => {
  const parsed = parseCustomProviderManifest(base());
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;
  const m = parsed.value;
  // Structural shape.
  assert.equal(m.schemaVersion, 1);
  assert.equal(m.providerId, "provider-1");
  assert.equal(m.kind, "host");
  assert.equal(m.actions.length, 2);
  assert.equal(m.actions[0]?.actionId, "probe");
  assert.deepEqual([...m.actions[0]?.argv!], ["probe", "--host"]);
  assert.equal(m.actions[0]?.env?.LOG_LEVEL, "info");
  assert.equal(m.actions[0]?.timeoutMs, 5000);
  // Detachment and deep freezing.
  assert.equal(Object.getPrototypeOf(m), null);
  assert.equal(Object.isFrozen(m), true);
  assert.equal(Object.isFrozen(m.actions), true);
  for (const action of m.actions) {
    assert.equal(Object.getPrototypeOf(action), null);
    assert.equal(Object.isFrozen(action), true);
    assert.equal(Object.isFrozen(action.argv), true);
    assert.equal(Object.isFrozen(action.env), true);
  }
});

test("rejects non-exact objects: extra, missing, symbol, custom proto, arrays", () => {
  assert.equal(parseCustomProviderManifest({}).ok, false);
  assert.equal(parseCustomProviderManifest(null).ok, false);
  assert.equal(parseCustomProviderManifest(42).ok, false);
  assert.equal(parseCustomProviderManifest("string").ok, false);
  assert.equal(parseCustomProviderManifest([]).ok, false);

  // Extra top-level key.
  assert.equal(parseCustomProviderManifest({ ...base(), extra: 1 }).ok, false);
  // Missing providerId / kind / actions.
  const partial = { schemaVersion: 1, kind: "host", actions: [] } as unknown;
  assert.equal(parseCustomProviderManifest(partial).ok, false);

  // Symbol key: add one and drop a real key so count stays 4.
  const symKey = { ...base() } as Record<string, unknown>;
  const symSymbol: symbol = Symbol("x");
  (symKey as unknown as Record<symbol, unknown>)[symSymbol] = "probe";
  delete (symKey as Record<string, unknown>).kind;
  assert.equal(parseCustomProviderManifest(symKey).ok, false);

  // Custom prototype.
  const Custom = class { constructor(actionId: string) { this.actionId = actionId; } actionId: string; };
  const instance = new Custom("probe");
  (instance as unknown as Record<string, unknown>).schemaVersion = 1;
  (instance as unknown as Record<string, unknown>).providerId = "p";
  (instance as unknown as Record<string, unknown>).actions = [];
  assert.equal(Object.getPrototypeOf(instance), Custom.prototype);
  assert.equal(parseCustomProviderManifest(instance).ok, false);

  // actions where an object expected; object where an array expected.
  assert.equal(parseCustomProviderManifest({ ...base(), actions: {} }).ok, false);
  assert.equal(parseCustomProviderManifest({ ...base(), providerId: 123 as unknown }).ok, false);
});

test("getters are never invoked (hostile accessor top-level)", () => {
  let called = 0;
  const hostField: Record<string, unknown> = base() as unknown as Record<string, unknown>;
  Object.defineProperty(hostField, "providerId", {
    get() {
      called += 1;
      return "provider-1";
    },
  });
  const parsed = parseCustomProviderManifest(hostField);
  assert.equal(parsed.ok, false);
  assert.equal(called, 0);
});

test("getters are never invoked on a nested action (hostile action field)", () => {
  let called = 0;
  const hostField: Record<string, unknown> = base() as unknown as Record<string, unknown>;
  const actionObj: Record<string, unknown> = { ...action() };
  Object.defineProperty(actionObj, "executable", {
    get() {
      called += 1;
      return "/usr/local/bin/probe";
    },
  });
  (hostField as Record<string, unknown>).actions = [actionObj];
  const parsed = parseCustomProviderManifest(hostField);
  assert.equal(parsed.ok, false);
  assert.equal(called, 0);
});

test("revoked / hostile Proxy fails closed without invoking the proxies' values", () => {
  const handler: ProxyHandler<Record<string, unknown>> = {
    getPrototypeOf() {
      return Object.prototype;
    },
    get() {
      throw new Error("hostile get");
    },
  };
  const inner: Record<string, unknown> = {
    schemaVersion: 1,
    providerId: "provider-1",
    kind: "host",
    actions: [],
  };
  const proxy = new Proxy(inner, handler);
  const parsed = parseCustomProviderManifest(proxy);
  assert.equal(parsed.ok, false);
  assert.equal(parsed.error, ERR_CUSTOM_PROVIDER_MANIFEST);
});

test("sparse, decorated, accessor, and revoked nested containers fail closed", () => {
  const sparse = new Array(1);
  assert.equal(parseCustomProviderManifest({ ...base(), actions: sparse }).ok, false);
  const decorated = [action()] as unknown[] & { extra?: string };
  decorated.extra = "x";
  assert.equal(parseCustomProviderManifest({ ...base(), actions: decorated }).ok, false);
  const argv = ["probe"];
  Object.defineProperty(argv, "0", { get() { throw new Error("must not run"); } });
  assert.equal(parseCustomProviderManifest({ ...base(), actions: [action({ argv })] }).ok, false);
  const { proxy, revoke } = Proxy.revocable({}, {});
  revoke();
  assert.equal(parseCustomProviderManifest({ ...base(), actions: [action({ env: proxy })] }).ok, false);
});

test("duplicate action identifiers fail closed", () => {
  assert.equal(parseCustomProviderManifest({ ...base(), actions: [action(), action()] }).ok, false);
});

test("invalid ids, kind, action names, executable, argv, env, limits", () => {
  // schema version other than 1.
  assert.equal(parseCustomProviderManifest({ ...base(), schemaVersion: 2 }).ok, false);
  // providerId with slash / metacharacters.
  assert.equal(parseCustomProviderManifest({ ...base(), providerId: "bad/id" }).ok, false);
  // invalid kind.
  assert.equal(parseCustomProviderManifest({ ...base(), kind: "unknown" }).ok, false);

  const manyFailures = [
    { actions: [{ ...action(), actionId: "x/y" }] },
    { actions: [{ ...action(), executable: "bin/probe" }] }, // not absolute
    { actions: [{ ...action(), executable: "/usr/bin/sh -c 'x'" }] }, // shell meta
    { actions: [{ ...action(), executable: "/usr/../etc" }] }, // parent traversal
    { actions: [{ ...action(), executable: "//bad" }] }, // doubled slash
    { actions: [{ ...action(), argv: "x" }] }, // argv non-array
    { actions: [{ ...action(), argv: ["x;rm"] }] }, // argv shell meta
    { actions: [{ ...action(), env: { log_level: "info" } }] }, // env name not uppercase
    { actions: [{ ...action(), env: { LOG_LEVEL: "x\x00y" } }] }, // control char value
    { actions: [{ ...action(), timeoutMs: 0 }] }, // timeout zero
    { actions: [{ ...action(), timeoutMs: 60001 }] }, // timeout over max
    { actions: [{ ...action(), maxOutputBytes: 0 }] }, // output zero
    { actions: [{ ...action(), maxOutputBytes: 1048577 }] }, // output over max
    { actions: [{ ...action(), timeoutMs: 1.5 }] }, // non-integer limit
  ];
  for (const failure of manyFailures) {
    assert.equal(parseCustomProviderManifest({ ...base(), ...failure }).ok, false);
  }
});

test("sensitive public values are rejected", () => {
  // URL / endpoint.
  assert.equal(parseCustomProviderManifest({ ...base(), actions: [{ ...action(), executable: "https://evil/x" }] }).ok, false);
  // Credential leak in env value.
  assert.equal(parseCustomProviderManifest({ ...base(), actions: [{ ...action(), env: { AUTH_TOKEN: "secret=abc" } }] }).ok, false);
  // LEAK a LAN address inside providerId.
  assert.equal(parseCustomProviderManifest({ ...base(), providerId: "provider@192.168.1.10" }).ok, false);
  // LEAK a localhost endpoint.
  assert.equal(parseCustomProviderManifest({ ...base(), actions: [{ ...action(), executable: "http://localhost:5173/run" }] }).ok, false);
  // LEAK a bearer token in argv.
  assert.equal(parseCustomProviderManifest({ ...base(), actions: [{ ...action(), argv: ["--token", "Bearer xyz123"] }] }).ok, false);
});

test("boundary acceptance and rejection for maxima", () => {
  // Accept MAX_ACTIONS (16).
  const manyActions = Array.from({ length: 16 }, (_unused, index) => action({ actionId: `a${String(index).padStart(2, "0")}` }));
  const parsed16 = parseCustomProviderManifest({ ...base(), actions: manyActions });
  assert.equal(parsed16.ok, true);
  if (parsed16.ok) assert.equal(parsed16.value.actions.length, 16);

  // Reject MAX_ACTIONS + 1.
  const tooMany = Array.from({ length: 17 }, (_unused, index) => action({ actionId: `a${String(index).padStart(2, "0")}` }));
  assert.equal(parseCustomProviderManifest({ ...base(), actions: tooMany }).ok, false);

  // Accept MAX_ARGV_ENTRIES (8), reject 9.
  const eightArgv = Array.from({ length: 8 }, (_unused, index) => `v${String(index)}`);
  const nineArgv = Array.from({ length: 9 }, (_unused, index) => `v${String(index)}`);
  assert.equal(parseCustomProviderManifest({ ...base(), actions: [action({ argv: eightArgv })] }).ok, true);
  assert.equal(parseCustomProviderManifest({ ...base(), actions: [action({ argv: nineArgv })] }).ok, false);

  // Accept MAX_ENV_ENTRIES (8), reject 9.
  const eightEnv: Record<string, string> = {};
  for (let index = 0; index < 8; index += 1) eightEnv[`K${String(index)}`] = "v";
  const nineEnv: Record<string, string> = {};
  for (let index = 0; index < 9; index += 1) nineEnv[`K${String(index)}`] = "v";
  assert.equal(parseCustomProviderManifest({ ...base(), actions: [action({ env: eightEnv })] }).ok, true);
  assert.equal(parseCustomProviderManifest({ ...base(), actions: [action({ env: nineEnv })] }).ok, false);

  // Accept boundary MAX_TIMEOUT_MS (60000) and MAX_OUTPUT_BYTES (1048576).
  assert.equal(parseCustomProviderManifest({ ...base(), actions: [action({ timeoutMs: 60_000, maxOutputBytes: 1_048_576 })] }).ok, true);
  assert.equal(parseCustomProviderManifest({ ...base(), actions: [action({ timeoutMs: 60_001, maxOutputBytes: 1_048_576 })] }).ok, false);
});

test("aggregate size budget accepts small manifest but rejects oversized argv", () => {
  // A manifest within budget succeeds.
  assert.equal(parseCustomProviderManifest(base()).ok, true);
  // A single action with a very large argv entry blows the aggregate budget.
  const huge = { actionId: "probe", executable: "/bin/x", argv: ["x".repeat(30_000)], env: {}, timeoutMs: 1, maxOutputBytes: 1 };
  assert.equal(parseCustomProviderManifest({ ...base(), actions: [huge] }).ok, false);
});

test("detachment: mutating the source object does not change the parsed value", () => {
  const source = base() as Record<string, unknown>;
  const parsed = parseCustomProviderManifest(source);
  assert.ok(parsed.ok);
  if (!parsed.ok) return;
  const before = JSON.stringify(parsed.value as unknown);
  // Mutate the source in place: nested array, env map, and top-level fields.
  const sourceActions = source.actions as Record<string, unknown>[];
  sourceActions[0]!.executable = "/EVIL";
  (sourceActions[0]!.env as Record<string, unknown>).HACK = "yes";
  source.providerId = "changed";
  const after = JSON.stringify(parsed.value as unknown);
  assert.equal(before, after);
});

test("output has no caller-owned mutable nested reference", () => {
  const source = base() as Record<string, unknown>;
  const parsed = parseCustomProviderManifest(source);
  assert.ok(parsed.ok);
  if (!parsed.ok) return;
  const m = parsed.value as unknown as Record<string, unknown>;
  // Mutation through the returned reference must throw in strict mode.
  assert.throws(() => { m.providerId = "x"; });
  const actions = m.actions as CustomActionTemplate[];
  assert.throws(() => { (actions as unknown[]).push({} as never); });
  const firstAction = actions[0] as unknown as Record<string, unknown>;
  assert.throws(() => { firstAction.executable = "/x"; });
});

test("stable machine code for every failure", () => {
  const failures = [
    parseCustomProviderManifest({}),
    parseCustomProviderManifest(undefined),
    parseCustomProviderManifest(null),
    parseCustomProviderManifest([]),
    parseCustomProviderManifest({ ...base(), kind: "nope" }),
    parseCustomProviderManifest({ ...base(), providerId: "b/d" }),
  ];
  for (const failure of failures) {
    assert.equal(failure.ok, false);
    if (!failure.ok) assert.equal(failure.error, ERR_CUSTOM_PROVIDER_MANIFEST);
  }
});

// Document the public shape for typecheck use.
export type _ManifestReference = CustomProviderManifest;
export type _KindReference = CustomProviderKind;
