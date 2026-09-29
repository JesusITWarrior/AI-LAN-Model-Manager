import test from "node:test";
import assert from "node:assert/strict";
import {
  ERR_CUSTOM_COMMAND_PLAN,
  planCustomCommand,
  type CustomActionTemplate,
  type CustomCommandBinding,
  type CommandPlanGlobalCaps,
  type CustomCommandPlan,
} from "./custom-command-plan.js";

function template(overrides: Record<string, unknown> = {}): CustomActionTemplate {
  return {
    actionId: "probe",
    executable: "/usr/local/bin/probe",
    argv: ["probe", "--host"],
    env: { LOG_LEVEL: "info" },
    timeoutMs: 5000,
    maxOutputBytes: 8192,
    ...overrides,
  } as unknown as CustomActionTemplate;
}

const caps: CommandPlanGlobalCaps = {
  maxTimeoutMs: 60_000,
  maxOutputBytes: 1_048_576,
  maxExecutableLength: 200,
  maxSlots: 8,
  maxEnvEntries: 8,
};

function binding(overrides: Record<string, unknown> = {}): CustomCommandBinding {
  return {
    providerId: "provider-1",
    callerId: "caller-1",
    allowedRoots: ["/usr/local/bin", "/opt/lanmm"],
    allowedEnvKeys: ["LOG_LEVEL"],
    slots: [],
    valueBinds: {},
    ...overrides,
  };
}

function plan(
  t = template(),
  b = binding(),
): ReturnType<typeof planCustomCommand> {
  return planCustomCommand(t, b, caps, "posix");
}

test("plans a minimal valid manifest for a posix flavor", () => {
  const r = plan();
  assert.equal(r.ok, true);
  if (!r.ok) return;
  const p = r.value;
  assert.equal(p.providerId, "provider-1");
  assert.equal(p.callerId, "caller-1");
  assert.equal(p.actionId, "probe");
  assert.equal(p.flavor, "posix");
  assert.equal(p.executable, "/usr/local/bin/probe");
  assert.deepEqual([...p.argv], ["probe", "--host"]);
  assert.equal(p.env?.LOG_LEVEL, "info");
  assert.equal(p.timeoutMs, 5000);
  assert.equal(p.maxOutputBytes, 8192);
  assert.equal(Object.getPrototypeOf(p), null);
  assert.equal(Object.isFrozen(p), true);
  assert.equal(Object.isFrozen(p.argv), true);
  assert.equal(Object.isFrozen(p.env), true);
});

test("win32 plan canonicalizes an allowlisted executable within a volume root", () => {
  const r = planCustomCommand(
    template({ executable: "C:\\ProgramData\\LANMM\\probe.exe" }),
    binding({
      allowedRoots: ["C:\\ProgramData\\LANMM"],
      allowedEnvKeys: ["LOG_LEVEL"],
    }),
    caps,
    "win32",
  );
  assert.equal(r.ok, true);
  if (!r.ok) return;
  assert.equal(r.value.executable, "C:\\ProgramData\\LANMM\\probe.exe");
});

test("rejects an executable not contained within any allowlisted root", () => {
  const r = planCustomCommand(
    template({ executable: "/usr/bin/evil" }),
    binding({ allowedRoots: ["/usr/local/bin"] }),
    caps,
    "posix",
  );
  assert.equal(r.ok, false);
  assert.equal(r.error, ERR_CUSTOM_COMMAND_PLAN);
});

test("rejects executable paths that are canonical-but-outside roots or traversal/", () => {
  assert.equal(planCustomCommand(template({ executable: "/usr/local/bin/sub/../../etc/x" }), binding(), caps, "posix").ok, false);
  assert.equal(planCustomCommand(template({ executable: "/etc/passwd" }), binding({ allowedRoots: ["/usr/local/bin"] }), caps, "posix").ok, false);
});

test("binds whole-entry bounded placeholder values and rejects extras/missing/mismatches", () => {
  const t = template({ executable: "/usr/local/bin/probe", argv: ["probe", "--ph-name"] });
  const b = binding({
    allowedRoots: ["/usr/local/bin"],
    allowedEnvKeys: ["LOG_LEVEL"],
    slots: [{ slotId: "name", kind: "string", length: 64 }],
    valueBinds: { name: "svcA" },
  });
  const r = planCustomCommand(t, b, caps, "posix");
  assert.equal(r.ok, true);
  if (r.ok) assert.deepEqual([...r.value.argv], ["probe", "svcA"]);

  // Missing a declared slot's binding.
  const bMissing = binding({
    allowedRoots: ["/usr/local/bin"],
    slots: [{ slotId: "name", kind: "string", length: 64 }],
    valueBinds: {},
  });
  assert.equal(planCustomCommand(t, bMissing, caps, "posix").ok, false);

  // Extra binding beyond declared slots.
  const bExtra = binding({
    allowedRoots: ["/usr/local/bin"],
    slots: [{ slotId: "name", kind: "string", length: 64 }],
    valueBinds: { name: "a", extra: "b" },
  });
  assert.equal(planCustomCommand(t, bExtra, caps, "posix").ok, false);

  // Wrong typed value for an integer slot.
  const tInt = template({ executable: "/usr/local/bin/probe", argv: ["probe", "--ph-idx"] });
  const bInt = binding({
    allowedRoots: ["/usr/local/bin"],
    slots: [{ slotId: "idx", kind: "integer", length: 32, min: 1, max: 10 }],
    valueBinds: { idx: "nope" },
  });
  assert.equal(planCustomCommand(tInt, bInt, caps, "posix").ok, false);
  // Out-of-range integer value.
  const bIntRange = binding({
    allowedRoots: ["/usr/local/bin"],
    slots: [{ slotId: "idx", kind: "integer", length: 32, min: 1, max: 10 }],
    valueBinds: { idx: 99 },
  });
  assert.equal(planCustomCommand(tInt, bIntRange, caps, "posix").ok, false);
  // In-range integer value binds correctly.
  const bIntOk = binding({
    allowedRoots: ["/usr/local/bin"],
    slots: [{ slotId: "idx", kind: "integer", length: 32, min: 1, max: 10 }],
    valueBinds: { idx: 3 },
  });
  const intResult = planCustomCommand(tInt, bIntOk, caps, "posix");
  assert.equal(intResult.ok, true);
  if (intResult.ok) assert.deepEqual([...intResult.value.argv], ["probe", "3"]);
  // Boolean binds as a whole-entry string literal.
  const tBool = template({ executable: "/usr/local/bin/probe", argv: ["probe", "--ph-en"] });
  const bBool = binding({
    allowedRoots: ["/usr/local/bin"],
    slots: [{ slotId: "en", kind: "boolean", length: 8 }],
    valueBinds: { en: true },
  });
  const boolResult = planCustomCommand(tBool, bBool, caps, "posix");
  assert.equal(boolResult.ok, true);
  if (boolResult.ok) assert.deepEqual([...boolResult.value.argv], ["probe", "true"]);
});

test("limits the number of declared slots", () => {
  const manySlots = Array.from({ length: 8 }, (_u, index) => ({ slotId: `s${String(index)}`, kind: "string", length: 16 }));
  const b = binding({ allowedRoots: ["/usr/local/bin"], slots: manySlots, valueBinds: {} });
  // No placeholder entries => declared slots never used => fail.
  const t = template({ executable: "/usr/local/bin/probe", argv: ["probe"] });
  assert.equal(planCustomCommand(t, b, caps, "posix").ok, false);

  const enoughSlots = Array.from({ length: 9 }, (_u, index) => ({ slotId: `s${String(index)}`, kind: "string", length: 16 }));
  const tooMany = binding({ allowedRoots: ["/usr/local/bin"], slots: enoughSlots, valueBinds: {} });
  assert.equal(planCustomCommand(t, tooMany, caps, "posix").ok, false);
});

test("env restricted to the explicit allowlist rejects allowlisted-omitted keys", () => {
  const b = binding({
    allowedRoots: ["/usr/local/bin"],
    allowedEnvKeys: [],
  });
  // Template env has an env entry not in the allowlist.
  assert.equal(planCustomCommand(template({ env: { LOG_LEVEL: "info", EXTRA: "x" } }), b, caps, "posix").ok, false);
  // With the allowlist excluding LOG_LEVEL, a plan using only it still fails.
  assert.equal(planCustomCommand(template({ env: { LOG_LEVEL: "info" } }), b, caps, "posix").ok, false);
});

test("hosts an allowlist larger than caps rejects", () => {
  const b = binding({
    allowedRoots: ["/usr/local/bin"],
    allowedEnvKeys: ["A", "B", "C", "D", "E", "F", "G", "H", "I"], // 9 > caps.maxEnvEntries (8)
  });
  const r = planCustomCommand(template(), b, caps, "posix");
  assert.equal(r.ok, false);
});

test("env value length limit and env key length limit are enforced", () => {
  const b = binding({
    allowedRoots: ["/usr/local/bin"],
    allowedEnvKeys: ["AVERYLONGENVVARIABlename"], // 22 chars, still <= 32
  });
  assert.equal(planCustomCommand(template({ env: { AVERYLONGENVVARIABNAME: "x" } }), b, caps, "posix").ok, false); // key not in allowlist
});

test("caps must permit the manifest per-action limits", () => {
  const tightCaps: CommandPlanGlobalCaps = {
    maxTimeoutMs: 1000,
    maxOutputBytes: 1024,
    maxExecutableLength: 200,
    maxSlots: 8,
    maxEnvEntries: 8,
  };
  // manifest timeout (5000) > cap (1000) -> fail
  assert.equal(planCustomCommand(template(), binding(), tightCaps, "posix").ok, false);
  // manifest output (8192) > cap (1024) -> fail
  const r = planCustomCommand(
    { ...template(), timeoutMs: 500, maxOutputBytes: 8192 },
    binding(),
    { ...tightCaps, maxOutputBytes: 1024 },
    "posix",
  );
  assert.equal(r.ok, false);
});

test("executable byte cap is applied to roots and executable", () => {
  const shortCaps = { ...caps, maxExecutableLength: 8 };
  assert.equal(planCustomCommand(template(), binding(), shortCaps, "posix").ok, false);
});

test("caps themselves are validated against manifest maxima", () => {
  const badTimeout: CommandPlanGlobalCaps = { maxTimeoutMs: 60_001, maxOutputBytes: 1024, maxExecutableLength: 200, maxSlots: 8, maxEnvEntries: 8 };
  assert.equal(planCustomCommand(template(), binding(), badTimeout, "posix").ok, false);
  const badSlots: CommandPlanGlobalCaps = { maxTimeoutMs: 60_000, maxOutputBytes: 1024, maxExecutableLength: 200, maxSlots: 0, maxEnvEntries: 8 };
  assert.equal(planCustomCommand(template(), binding(), badSlots, "posix").ok, false);
  const badLength: CommandPlanGlobalCaps = { maxTimeoutMs: 60_000, maxOutputBytes: 1024, maxExecutableLength: 201, maxSlots: 8, maxEnvEntries: 8 };
  assert.equal(planCustomCommand(template(), binding(), badLength, "posix").ok, false);
});

test("non-throwing: rejects exotic inputs without ever invoking getters or throwing", () => {
  const badValues = [
    undefined, null, 42, "string", [], {}, new Date(),
    Object.create({}) as unknown,
    { ...template(), argv: "x" } as unknown as CustomActionTemplate,
  ];
  for (const t of badValues) {
    const r = planCustomCommand(t as unknown as CustomActionTemplate, binding(), caps, "posix");
    assert.equal(r.ok, false);
  }
  for (const b of [null, undefined, 42, "x", [], {}] as readonly unknown[]) {
    const r = planCustomCommand(template(), b as unknown as CustomCommandBinding, caps, "posix");
    assert.equal(r.ok, false);
  }
  // Hostile accessor: getter must not be invoked, and the call must not throw.
  let getterCalls = 0;
  const hostile = { ...binding() };
  Object.defineProperty(hostile, "callerId", { enumerable: true, get() { getterCalls += 1; return "caller-1"; } });
  assert.doesNotThrow(() => planCustomCommand(template(), hostile, caps, "posix"));
  assert.equal(getterCalls, 0);
});

test("non-throwing: rejects hostile/stale Proxies", () => {
  const revocable = Proxy.revocable({}, {});
  revocable.revoke();
  assert.doesNotThrow(() => planCustomCommand(template(), revocable.proxy as unknown as CustomCommandBinding, caps, "posix"));
  assert.equal(planCustomCommand(template(), revocable.proxy as unknown as CustomCommandBinding, caps, "posix").ok, false);
  for (const trap of ["getPrototypeOf", "ownKeys", "getOwnPropertyDescriptor"] as const) {
    const target = trap === "getOwnPropertyDescriptor" ? {} : {};
    const hostile = new Proxy(target, { [trap]() { throw new Error("hostile"); } } as ProxyHandler<object>);
    assert.doesNotThrow(() => planCustomCommand(template(), hostile as unknown as CustomCommandBinding, caps, "posix"));
    assert.equal(planCustomCommand(template(), hostile as unknown as CustomCommandBinding, caps, "posix").ok, false);
  }
});

test("fails closed for an unplanable flavor and a stale Proxy", () => {
  assert.equal(planCustomCommand(template(), binding(), caps, "bogus" as "posix").ok, false);
  const { proxy, revoke } = Proxy.revocable({ ...binding() }, {});
  revoke();
  assert.doesNotThrow(() => planCustomCommand(template(), proxy as unknown as CustomCommandBinding, caps, "posix"));
  assert.equal(planCustomCommand(template(), proxy as unknown as CustomCommandBinding, caps, "posix").ok, false);
});

test("fails closed: sensitive values, shell metachars, traversal, cross-flavor chars", () => {
  const cases: [CustomActionTemplate, CustomCommandBinding][] = [
    [template({ executable: "https://evil/probe" }), binding()],
    [template({ executable: "http://localhost:5173/probe" }), binding()],
    [template({ executable: "/usr/local/bin/probe;rm -rf /" }), binding()],
    [template({ executable: "/usr/local/bin/sub/../etc/probe" }), binding()],
    [template({ executable: "/usr/local/bin\\win" }), binding()], // backslash in posix
    [template({ executable: "C:\\ProgramData\\LANMM\\probe.exe" }), binding({ allowedRoots: ["/usr/local/bin"] })], // win32 exe on posix flavor
  ];
  for (const [t, b] of cases) {
    assert.equal(planCustomCommand(t, b, caps, "posix").ok, false, JSON.stringify(t.executable));
  }
});

test("fails closed: win32 reserved names and unsafe characters", () => {
  const cases = [
    "C:\\ProgramData\\LANMM\\CON",
    "C:\\ProgramData\\LANMM\\file?.txt",
    "C:\\ProgramData\\LANMM\\a/b", // forward slash in win32 path
  ];
  for (const exe of cases) {
    const t = template({ executable: exe });
    assert.equal(planCustomCommand(t, binding({ allowedRoots: ["C:\\ProgramData\\LANMM"] }), caps, "win32").ok, false, exe);
  }
});

test("fails closed: duplicate placeholder entries and unset slots", () => {
  const t = template({ executable: "/usr/local/bin/probe", argv: ["probe", "--ph-a", "--ph-a"] });
  const b = binding({
    allowedRoots: ["/usr/local/bin"],
    slots: [{ slotId: "a", kind: "string", length: 16 }],
    valueBinds: { a: "x" },
  });
  // Two argv placeholder entries but only one slot -> fail.
  assert.equal(planCustomCommand(t, b, caps, "posix").ok, false);

  const t2 = template({ executable: "/usr/local/bin/probe", argv: ["probe"] });
  const b2 = binding({
    allowedRoots: ["/usr/local/bin"],
    slots: [{ slotId: "a", kind: "string", length: 16 }],
    valueBinds: {},
  });
  // Declared slot never used -> fail.
  assert.equal(planCustomCommand(t2, b2, caps, "posix").ok, false);
});

test("fails closed: bad caller/provider identities and empty allowlisted roots", () => {
  assert.equal(planCustomCommand(template(), { ...binding(), providerId: "bad/id" }, caps, "posix").ok, false);
  assert.equal(planCustomCommand(template(), { ...binding(), callerId: "x/y" }, caps, "posix").ok, false);
  assert.equal(planCustomCommand(template(), { ...binding(), providerId: "" }, caps, "posix").ok, false);
  assert.equal(planCustomCommand(template(), { ...binding(), allowedRoots: [] }, caps, "posix").ok, false);
  assert.equal(planCustomCommand(template(), { ...binding(), allowedRoots: undefined as unknown as readonly string[] }, caps, "posix").ok, false);
});

test("detachment: mutating the source does not change the computed plan", () => {
  const source = binding() as unknown as Record<string, unknown>;
  source.callerId = "changed";
  const r = planCustomCommand(template(), source, caps, "posix");
  assert.ok(r.ok);
  if (!r.ok) return;
  const before = JSON.stringify(r.value);
  source.callerId = "changed2";
  const after = JSON.stringify(r.value);
  assert.equal(before, after);
  assert.throws(() => { (r.value as unknown as Record<string, unknown>).callerId = "x"; });
});

test("stable machine code for every failure", () => {
  const failures = [
    planCustomCommand({}, binding(), caps, "posix"),
    planCustomCommand(template(), {}, caps, "posix"),
    planCustomCommand(template(), binding(), caps, "bogus" as "posix"),
  ];
  for (const failure of failures) {
    assert.equal(failure.ok, false);
    if (!failure.ok) assert.equal(failure.error, ERR_CUSTOM_COMMAND_PLAN);
  }
});

// Document the public shape for typecheck use.
export type _PlanReference = CustomCommandPlan;
