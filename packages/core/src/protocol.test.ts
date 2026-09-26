import assert from "node:assert/strict";
import test from "node:test";
import {
  CURRENT_PROTOCOL_VERSION,
  isProtocolVersionCompatible,
  parseJsonValue,
  parseProtocolId,
  parseProtocolVersion,
  parseUtcTimestamp,
} from "./protocol.js";

test("current version is a frozen { major: 1, minor: 0 }", () => {
  assert.deepStrictEqual(CURRENT_PROTOCOL_VERSION, { major: 1, minor: 0 });
  assert.throws(() => {
    (CURRENT_PROTOCOL_VERSION as { minor: number }).minor = 1;
  });
});

// --- parseProtocolVersion ---------------------------------------------------

test("accepts plain objects with exactly major/minor", () => {
  assert.deepStrictEqual(parseProtocolVersion({ major: 1, minor: 0 }), {
    ok: true,
    value: { major: 1, minor: 0 },
  });
  assert.deepStrictEqual(parseProtocolVersion({ major: 3, minor: 7 }), {
    ok: true,
    value: { major: 3, minor: 7 },
  });
  assert.deepStrictEqual(parseProtocolVersion({ major: 0, minor: 0 }), {
    ok: true,
    value: { major: 0, minor: 0 },
  });
});

test("accepts Object.create(null) with exactly major/minor", () => {
  const obj = Object.create(null);
  obj.major = 2;
  obj.minor = 5;
  assert.deepStrictEqual(parseProtocolVersion(obj), { ok: true, value: { major: 2, minor: 5 } });
});

test("accepts Object.create(Object.prototype) with exactly major/minor", () => {
  const obj = Object.create(Object.prototype);
  obj.major = 1;
  obj.minor = 9;
  assert.deepStrictEqual(parseProtocolVersion(obj), { ok: true, value: { major: 1, minor: 9 } });
});

test("rejects non-object inputs with a stable machine code (no throw)", () => {
  assert.deepStrictEqual(parseProtocolVersion(null), { ok: false, error: "ERR_INVALID_TYPE" });
  assert.deepStrictEqual(parseProtocolVersion(undefined), { ok: false, error: "ERR_INVALID_TYPE" });
  assert.deepStrictEqual(parseProtocolVersion("1.0"), { ok: false, error: "ERR_INVALID_TYPE" });
  assert.deepStrictEqual(parseProtocolVersion(1), { ok: false, error: "ERR_INVALID_TYPE" });
  assert.deepStrictEqual(parseProtocolVersion(true), { ok: false, error: "ERR_INVALID_TYPE" });
  assert.deepStrictEqual(parseProtocolVersion([1, 2]), { ok: false, error: "ERR_INVALID_TYPE" });
});

test("rejects extra string or symbol keys", () => {
  assert.deepStrictEqual(parseProtocolVersion({ major: 1, minor: 0, legacy: true }), {
    ok: false,
    error: "ERR_EXTRA_KEY",
  });
  assert.deepStrictEqual(parseProtocolVersion({ major: 1, minor: 0, [Symbol("extra")]: true }), {
    ok: false,
    error: "ERR_EXTRA_KEY",
  });
});

test("rejects Object.create(null) with extra keys", () => {
  const obj = Object.create(null);
  obj.major = 1;
  obj.minor = 0;
  obj.extra = 1;
  assert.deepStrictEqual(parseProtocolVersion(obj), { ok: false, error: "ERR_EXTRA_KEY" });
});

test("rejects missing major or minor", () => {
  assert.deepStrictEqual(parseProtocolVersion({ minor: 0 }), { ok: false, error: "ERR_MISSING_KEY" });
  assert.deepStrictEqual(parseProtocolVersion({ major: 1 }), { ok: false, error: "ERR_MISSING_KEY" });
  assert.deepStrictEqual(parseProtocolVersion({}), { ok: false, error: "ERR_MISSING_KEY" });
});

test("rejects non-finite values (NaN, Infinity, -Infinity)", () => {
  assert.deepStrictEqual(parseProtocolVersion({ major: NaN, minor: 0 }), {
    ok: false,
    error: "ERR_NON_FINITE",
  });
  assert.deepStrictEqual(parseProtocolVersion({ major: Infinity, minor: 0 }), {
    ok: false,
    error: "ERR_NON_FINITE",
  });
  assert.deepStrictEqual(parseProtocolVersion({ major: -Infinity, minor: 0 }), {
    ok: false,
    error: "ERR_NON_FINITE",
  });
});

test("rejects negative values", () => {
  assert.deepStrictEqual(parseProtocolVersion({ major: -1, minor: 0 }), {
    ok: false,
    error: "ERR_NEGATIVE_VALUE",
  });
  assert.deepStrictEqual(parseProtocolVersion({ major: 1, minor: -1 }), {
    ok: false,
    error: "ERR_NEGATIVE_VALUE",
  });
});

test("rejects fractional / non-integer values", () => {
  assert.deepStrictEqual(parseProtocolVersion({ major: 1.5, minor: 0 }), {
    ok: false,
    error: "ERR_NON_INTEGER",
  });
  assert.deepStrictEqual(parseProtocolVersion({ major: 1, minor: 0.25 }), {
    ok: false,
    error: "ERR_NON_INTEGER",
  });
});

test("rejects values outside the safe-integer range", () => {
  assert.deepStrictEqual(parseProtocolVersion({ major: Number.MAX_SAFE_INTEGER + 1, minor: 0 }), {
    ok: false,
    error: "ERR_OUT_OF_RANGE",
  });
  assert.deepStrictEqual(
    parseProtocolVersion({ major: 1, minor: Number.MAX_SAFE_INTEGER }),
    { ok: true, value: { major: 1, minor: Number.MAX_SAFE_INTEGER } },
  );
});

test("rejects string-typed numeric fields (no coercion)", () => {
  assert.deepStrictEqual(parseProtocolVersion({ major: "1", minor: 0 }), {
    ok: false,
    error: "ERR_INVALID_TYPE",
  });
});

// --- isProtocolVersionCompatible --------------------------------------------

test("compatible when majors match and peer.minor <= local.minor", () => {
  assert.equal(isProtocolVersionCompatible({ major: 1, minor: 0 }, { major: 1, minor: 0 }), true);
  assert.equal(isProtocolVersionCompatible({ major: 1, minor: 5 }, { major: 1, minor: 3 }), true);
});

test("incompatible when majors differ", () => {
  assert.equal(isProtocolVersionCompatible({ major: 1, minor: 5 }, { major: 2, minor: 0 }), false);
  assert.equal(isProtocolVersionCompatible({ major: 2, minor: 0 }, { major: 1, minor: 0 }), false);
});

test("incompatible when peer.minor > local.minor (same major)", () => {
  assert.equal(isProtocolVersionCompatible({ major: 1, minor: 0 }, { major: 1, minor: 1 }), false);
});

test("incompatible when either input is unparseable (no throw)", () => {
  assert.equal(isProtocolVersionCompatible(null, { major: 1, minor: 0 }), false);
  assert.equal(isProtocolVersionCompatible({ major: 1, minor: 0 }, null), false);
  assert.equal(isProtocolVersionCompatible("nope", { major: 1, minor: 0 }), false);
  assert.equal(isProtocolVersionCompatible({ major: 1 }, { minor: 0 }), false);
  assert.equal(isProtocolVersionCompatible([1, 2], { major: 1, minor: 0 }), false);
});

// --- parseProtocolId --------------------------------------------------------

test("accepts each kind for a minimal valid id", () => {
  assert.deepStrictEqual(parseProtocolId("request", "a"), { ok: true, value: "a" });
  assert.deepStrictEqual(parseProtocolId("job", "b"), { ok: true, value: "b" });
  assert.deepStrictEqual(parseProtocolId("host", "c"), { ok: true, value: "c" });
  assert.deepStrictEqual(parseProtocolId("correlation", "d"), { ok: true, value: "d" });
});

test("accepts length 128 exactly", () => {
  const id128 = "a".repeat(128);
  assert.deepStrictEqual(parseProtocolId("request", id128), { ok: true, value: id128 });
});

test("rejects length 129 (too long)", () => {
  const id129 = "a".repeat(129);
  assert.deepStrictEqual(parseProtocolId("request", id129), {
    ok: false,
    error: "ERR_INVALID_LENGTH",
  });
});

test("accepts a representative valid id with allowed separators", () => {
  assert.deepStrictEqual(
    parseProtocolId("request", "svc-1.a_b:c-d"),
    { ok: true, value: "svc-1.a_b:c-d" },
  );
  assert.deepStrictEqual(
    parseProtocolId("request", "a.b_c:d-e"),
    { ok: true, value: "a.b_c:d-e" },
  );
});

test("rejects leading separator (must start alphanumeric)", () => {
  assert.deepStrictEqual(parseProtocolId("request", ".abc"), {
    ok: false,
    error: "ERR_INVALID_FORMAT",
  });
  assert.deepStrictEqual(parseProtocolId("request", "-abc"), {
    ok: false,
    error: "ERR_INVALID_FORMAT",
  });
});

test("rejects whitespace (leading, internal, trailing)", () => {
  assert.deepStrictEqual(parseProtocolId("request", " a"), {
    ok: false,
    error: "ERR_INVALID_FORMAT",
  });
  assert.deepStrictEqual(parseProtocolId("request", "a b"), {
    ok: false,
    error: "ERR_INVALID_FORMAT",
  });
  assert.deepStrictEqual(parseProtocolId("request", "a "), {
    ok: false,
    error: "ERR_INVALID_FORMAT",
  });
});

test("rejects control chars", () => {
  assert.deepStrictEqual(parseProtocolId("request", "a\tb"), {
    ok: false,
    error: "ERR_INVALID_FORMAT",
  });
  assert.deepStrictEqual(parseProtocolId("request", "a\nb"), {
    ok: false,
    error: "ERR_INVALID_FORMAT",
  });
});

test("rejects slash and backslash", () => {
  assert.deepStrictEqual(parseProtocolId("request", "a/b"), {
    ok: false,
    error: "ERR_INVALID_FORMAT",
  });
  assert.deepStrictEqual(parseProtocolId("request", "a\\b"), {
    ok: false,
    error: "ERR_INVALID_FORMAT",
  });
});

test("rejects query/hash delimiters", () => {
  assert.deepStrictEqual(parseProtocolId("request", "a?b"), {
    ok: false,
    error: "ERR_INVALID_FORMAT",
  });
  assert.deepStrictEqual(parseProtocolId("request", "a#b"), {
    ok: false,
    error: "ERR_INVALID_FORMAT",
  });
});

test("rejects percent encoding literally", () => {
  assert.deepStrictEqual(parseProtocolId("request", "a%20b"), {
    ok: false,
    error: "ERR_INVALID_FORMAT",
  });
});

test("rejects non-ASCII unicode", () => {
  assert.deepStrictEqual(parseProtocolId("request", "café"), {
    ok: false,
    error: "ERR_INVALID_FORMAT",
  });
  assert.deepStrictEqual(parseProtocolId("request", "👍"), {
    ok: false,
    error: "ERR_INVALID_FORMAT",
  });
});

test("rejects empty string", () => {
  assert.deepStrictEqual(parseProtocolId("request", ""), {
    ok: false,
    error: "ERR_INVALID_LENGTH",
  });
});

test("rejects non-string input immediately (no coercion)", () => {
  assert.deepStrictEqual(parseProtocolId("request", 123), {
    ok: false,
    error: "ERR_INVALID_TYPE",
  });
  assert.deepStrictEqual(parseProtocolId("request", null), {
    ok: false,
    error: "ERR_INVALID_TYPE",
  });
  assert.deepStrictEqual(parseProtocolId("request", undefined), {
    ok: false,
    error: "ERR_INVALID_TYPE",
  });
  assert.deepStrictEqual(parseProtocolId("request", { major: 1 }), {
    ok: false,
    error: "ERR_INVALID_TYPE",
  });
});

test("each kind rejects non-string input with the same stable code", () => {
  assert.deepStrictEqual(parseProtocolId("job", 1), { ok: false, error: "ERR_INVALID_TYPE" });
  assert.deepStrictEqual(parseProtocolId("host", null), { ok: false, error: "ERR_INVALID_TYPE" });
  assert.deepStrictEqual(parseProtocolId("correlation", "x y"), {
    ok: false,
    error: "ERR_INVALID_FORMAT",
  });
});

test("rejects custom-prototype objects", () => {
  const obj = Object.create({ inherited: true });
  obj.major = 1;
  obj.minor = 0;
  assert.deepStrictEqual(parseProtocolVersion(obj), {
    ok: false,
    error: "ERR_INVALID_TYPE",
  });
});

test("rejects accessors without invoking them", () => {
  let invoked = false;
  const obj = {
    get major() {
      invoked = true;
      throw new Error("must not be invoked");
    },
    minor: 0,
  };
  assert.deepStrictEqual(parseProtocolVersion(obj), {
    ok: false,
    error: "ERR_INVALID_TYPE",
  });
  assert.equal(invoked, false);
});

test("returns a validation failure when proxy reflection throws", () => {
  const proxy = new Proxy(
    {},
    {
      getPrototypeOf() {
        throw new Error("hostile proxy");
      },
    },
  );
  assert.doesNotThrow(() => parseProtocolVersion(proxy));
  assert.deepStrictEqual(parseProtocolVersion(proxy), {
    ok: false,
    error: "ERR_INVALID_TYPE",
  });
});

// --- parseUtcTimestamp ------------------------------------------------------

test("accepts a standard valid timestamp", () => {
  assert.deepStrictEqual(parseUtcTimestamp("2024-01-15T12:30:45.123Z"), {
    ok: true,
    value: "2024-01-15T12:30:45.123Z",
  });
});

test("accepts leap day Feb 29 on a leap year (round-trips)", () => {
  assert.deepStrictEqual(parseUtcTimestamp("2024-02-29T00:00:00.000Z"), {
    ok: true,
    value: "2024-02-29T00:00:00.000Z",
  });
});

test("accepts year 0000 if JS round-trips it", () => {
  const result = parseUtcTimestamp("0000-01-01T00:00:00.000Z");
  assert.equal(result.ok, true);
});

test("accepts year 9999 if JS round-trips it", () => {
  const result = parseUtcTimestamp("9999-12-31T23:59:59.999Z");
  assert.equal(result.ok, true);
});

test("rejects invalid leap day Feb 30 (non-existent date)", () => {
  const result = parseUtcTimestamp("2024-02-30T00:00:00.000Z");
  assert.equal(result.ok, false);
});

test("rejects rollover month 13", () => {
  const result = parseUtcTimestamp("2024-13-01T00:00:00.000Z");
  assert.equal(result.ok, false);
});

test("rejects timezone offset +05:00 instead of Z", () => {
  const result = parseUtcTimestamp("2024-01-15T12:30:45.123+05:00");
  assert.equal(result.ok, false);
});

test("rejects missing milliseconds (no dot)", () => {
  const result = parseUtcTimestamp("2024-01-15T12:30:45Z");
  assert.equal(result.ok, false);
});

test("rejects short millisecond count (two digits)", () => {
  const result = parseUtcTimestamp("2024-01-15T12:30:45.12Z");
  assert.equal(result.ok, false);
});

test("rejects long millisecond count (four digits)", () => {
  const result = parseUtcTimestamp("2024-01-15T12:30:45.1234Z");
  assert.equal(result.ok, false);
});

test("rejects lowercase t separator", () => {
  const result = parseUtcTimestamp("2024-01-15t12:30:45.123Z");
  assert.equal(result.ok, false);
});

test("rejects lowercase z suffix", () => {
  const result = parseUtcTimestamp("2024-01-15T12:30:45.123z");
  assert.equal(result.ok, false);
});

test("rejects date-only value (no time)", () => {
  const result = parseUtcTimestamp("2024-01-15");
  assert.equal(result.ok, false);
});

test("rejects leading whitespace", () => {
  const result = parseUtcTimestamp(" 2024-01-15T12:30:45.123Z");
  assert.equal(result.ok, false);
});

test("rejects trailing whitespace", () => {
  const result = parseUtcTimestamp("2024-01-15T12:30:45.123Z ");
  assert.equal(result.ok, false);
});

test("rejects expanded year (five digits)", () => {
  const result = parseUtcTimestamp("00000-01-15T12:30:45.123Z");
  assert.equal(result.ok, false);
});

test("rejects signed year +2024", () => {
  const result = parseUtcTimestamp("+2024-01-15T12:30:45.123Z");
  assert.equal(result.ok, false);
});

test("rejects null input", () => {
  const result = parseUtcTimestamp(null);
  assert.deepStrictEqual(result, { ok: false, error: "ERR_INVALID_TYPE" });
});

test("rejects number input", () => {
  const result = parseUtcTimestamp(12345);
  assert.deepStrictEqual(result, { ok: false, error: "ERR_INVALID_TYPE" });
});

test("rejects object input", () => {
  const result = parseUtcTimestamp({});
  assert.deepStrictEqual(result, { ok: false, error: "ERR_INVALID_TYPE" });
});

test("never throws for any unknown input", () => {
  const inputs: unknown[] = [null, undefined, 0, -1, NaN, Infinity, true, [], {}, function () {}];
  for (const inp of inputs) {
    assert.doesNotThrow(() => parseUtcTimestamp(inp));
  }
});

test("rejects Feb 29 on non-leap year", () => {
  const result = parseUtcTimestamp("2023-02-29T00:00:00.000Z");
  assert.equal(result.ok, false);
});

// --- parseJsonValue: primitives and arrays ---------------------------------

const jsonLimits = (overrides: Partial<{
  maxDepth: number;
  maxNodes: number;
  maxObjectKeys: number;
  maxArrayLength: number;
  maxStringLength: number;
}> = {}) => ({
  maxDepth: 8,
  maxNodes: 1024,
  maxObjectKeys: 128,
  maxArrayLength: 256,
  maxStringLength: 4096,
  ...overrides,
});

test("accepts JSON primitives and nested dense arrays", () => {
  for (const value of [null, true, false, 0, -1.5, "text"] as const) {
    assert.deepStrictEqual(parseJsonValue(value), { ok: true, value });
  }
  assert.deepStrictEqual(parseJsonValue([null, true, 1, "x", [2]]), {
    ok: true,
    value: [null, true, 1, "x", [2]],
  });
});

test("rejects non-finite numbers and unsupported values", () => {
  for (const value of [NaN, Infinity, -Infinity]) {
    assert.deepStrictEqual(parseJsonValue(value), { ok: false, error: "ERR_NON_FINITE" });
  }
  for (const value of [undefined, 1n, Symbol("x"), () => undefined]) {
    assert.deepStrictEqual(parseJsonValue(value), { ok: false, error: "ERR_INVALID_TYPE" });
  }
});

test("enforces exact string and array length boundaries", () => {
  const limits = jsonLimits({ maxStringLength: 3, maxArrayLength: 2 });
  assert.equal(parseJsonValue("abc", limits).ok, true);
  assert.deepStrictEqual(parseJsonValue("abcd", limits), {
    ok: false,
    error: "ERR_LIMIT_EXCEEDED",
  });
  assert.equal(parseJsonValue([1, 2], limits).ok, true);
  assert.deepStrictEqual(parseJsonValue([1, 2, 3], limits), {
    ok: false,
    error: "ERR_LIMIT_EXCEEDED",
  });
});

test("counts root depth and nodes without off-by-one errors", () => {
  assert.equal(parseJsonValue([[]], jsonLimits({ maxDepth: 1 })).ok, true);
  assert.deepStrictEqual(parseJsonValue([[[]]], jsonLimits({ maxDepth: 1 })), {
    ok: false,
    error: "ERR_LIMIT_EXCEEDED",
  });
  assert.equal(parseJsonValue([1, 2], jsonLimits({ maxNodes: 3 })).ok, true);
  assert.deepStrictEqual(parseJsonValue([1, 2], jsonLimits({ maxNodes: 2 })), {
    ok: false,
    error: "ERR_LIMIT_EXCEEDED",
  });
});

test("rejects sparse arrays and extra string or symbol properties", () => {
  const sparse = new Array(2);
  sparse[0] = 1;
  assert.deepStrictEqual(parseJsonValue(sparse), {
    ok: false,
    error: "ERR_INVALID_STRUCTURE",
  });

  const withExtra: unknown[] & { note?: string } = [1];
  withExtra.note = "no";
  assert.deepStrictEqual(parseJsonValue(withExtra), {
    ok: false,
    error: "ERR_INVALID_STRUCTURE",
  });

  const withSymbol: unknown[] = [1];
  Object.defineProperty(withSymbol, Symbol("extra"), { value: true });
  assert.deepStrictEqual(parseJsonValue(withSymbol), {
    ok: false,
    error: "ERR_INVALID_STRUCTURE",
  });
});

test("rejects array accessors without invoking them", () => {
  let invoked = false;
  const value: unknown[] = [];
  Object.defineProperty(value, "0", {
    enumerable: true,
    configurable: true,
    get() {
      invoked = true;
      throw new Error("must not run");
    },
  });
  Object.defineProperty(value, "length", { value: 1 });
  assert.deepStrictEqual(parseJsonValue(value), {
    ok: false,
    error: "ERR_INVALID_STRUCTURE",
  });
  assert.equal(invoked, false);
});

test("rejects cycles and shared array references", () => {
  const cyclic: unknown[] = [];
  cyclic.push(cyclic);
  assert.deepStrictEqual(parseJsonValue(cyclic), {
    ok: false,
    error: "ERR_INVALID_STRUCTURE",
  });

  const shared: unknown[] = [1];
  assert.deepStrictEqual(parseJsonValue([shared, shared]), {
    ok: false,
    error: "ERR_INVALID_STRUCTURE",
  });
});

test("returns a detached and deeply frozen array", () => {
  const child: unknown[] = [1];
  const input: unknown[] = [child];
  const result = parseJsonValue(input);
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(Object.isFrozen(result.value), true);
  assert.equal(Array.isArray(result.value), true);
  const outputChild = (result.value as readonly unknown[])[0];
  assert.equal(Object.isFrozen(outputChild), true);
  child[0] = 9;
  input.push(2);
  assert.deepStrictEqual(result.value, [[1]]);
});

test("accepts exact complete limit objects with plain or null prototypes", () => {
  assert.equal(parseJsonValue([1], jsonLimits()).ok, true);
  const nullPrototype = Object.assign(Object.create(null), jsonLimits());
  assert.equal(parseJsonValue([1], nullPrototype).ok, true);
});

test("rejects malformed limit objects", () => {
  const malformed: unknown[] = [
    null,
    {},
    { ...jsonLimits(), extra: 1 },
    { ...jsonLimits(), maxDepth: 0 },
    { ...jsonLimits(), maxDepth: 1.5 },
    { ...jsonLimits(), maxNodes: Number.MAX_SAFE_INTEGER + 1 },
    { ...jsonLimits(), maxDepth: 65 },
    Object.assign(Object.create({ inherited: true }), jsonLimits()),
  ];
  for (const limits of malformed) {
    assert.deepStrictEqual(parseJsonValue([1], limits), {
      ok: false,
      error: "ERR_INVALID_LIMITS",
    });
  }

  const symbolLimits = { ...jsonLimits(), [Symbol("extra")]: 1 };
  assert.deepStrictEqual(parseJsonValue([1], symbolLimits), {
    ok: false,
    error: "ERR_INVALID_LIMITS",
  });
});

test("rejects limit accessors and hostile proxies without throwing", () => {
  let invoked = false;
  const accessorLimits = {
    ...jsonLimits(),
    get maxDepth() {
      invoked = true;
      throw new Error("must not run");
    },
  };
  assert.deepStrictEqual(parseJsonValue([1], accessorLimits), {
    ok: false,
    error: "ERR_INVALID_LIMITS",
  });
  assert.equal(invoked, false);

  const proxy = new Proxy({}, {
    getPrototypeOf() {
      throw new Error("hostile proxy");
    },
  });
  assert.doesNotThrow(() => parseJsonValue([1], proxy));
  assert.deepStrictEqual(parseJsonValue([1], proxy), {
    ok: false,
    error: "ERR_INVALID_LIMITS",
  });
});

test("returns a validation failure for hostile array reflection", () => {
  const proxy = new Proxy([], {
    ownKeys() {
      throw new Error("hostile proxy");
    },
  });
  assert.doesNotThrow(() => parseJsonValue(proxy));
  assert.deepStrictEqual(parseJsonValue(proxy), {
    ok: false,
    error: "ERR_INVALID_STRUCTURE",
  });
});

test("does not throw for revoked value or limits proxies", () => {
  const valueProxy = Proxy.revocable([], {});
  valueProxy.revoke();
  assert.doesNotThrow(() => parseJsonValue(valueProxy.proxy));
  assert.deepStrictEqual(parseJsonValue(valueProxy.proxy), {
    ok: false,
    error: "ERR_INVALID_STRUCTURE",
  });

  const limitsProxy = Proxy.revocable(jsonLimits(), {});
  limitsProxy.revoke();
  assert.doesNotThrow(() => parseJsonValue([], limitsProxy.proxy));
  assert.deepStrictEqual(parseJsonValue([], limitsProxy.proxy), {
    ok: false,
    error: "ERR_INVALID_LIMITS",
  });
});

// --- parseJsonValue: plain object support -----------------------------------

test("accepts plain Object.prototype and null-prototype nested objects", () => {
  const plain = { a: 1, b: [2, "x"] };
  const resultPlain = parseJsonValue(plain);
  assert.equal(resultPlain.ok, true);

  const nullProto = Object.create(null);
  nullProto.a = 3;
  nullProto.b = [4];
  const resultNull = parseJsonValue(nullProto);
  assert.equal(resultNull.ok, true);

  // Verify output has null prototype and is frozen.
  if (resultPlain.ok) {
    assert.equal(Object.getPrototypeOf(resultPlain.value), null);
    assert.equal(Object.isFrozen(resultPlain.value), true);
  }
});

test("accepts deeply nested mixed containers", () => {
  const input: unknown[] = [
    { a: [1, { b: [2] }] },
  ];
  const result = parseJsonValue(input[0], jsonLimits({ maxDepth: 4 }));
  assert.equal(result.ok, true);
});

test("enforces exact maxObjectKeys boundary", () => {
  const limits = jsonLimits({ maxObjectKeys: 2 });
  const obj1: Record<string, number> = { a: 1, b: 2 };
  assert.equal(parseJsonValue(obj1, limits).ok, true);

  const obj2: Record<string, number> = { a: 1, b: 2, c: 3 };
  assert.deepStrictEqual(parseJsonValue(obj2, limits), {
    ok: false,
    error: "ERR_LIMIT_EXCEEDED",
  });
});

test("rejects overlong object keys", () => {
  const longKey = "a".repeat(4097);
  const obj: Record<string, number> = {};
  (obj as unknown as Record<string, number>)[longKey] = 1;
  assert.deepStrictEqual(parseJsonValue(obj), {
    ok: false,
    error: "ERR_LIMIT_EXCEEDED",
  });
});

test("rejects custom prototype objects", () => {
  const obj = Object.create({ inherited: true }) as Record<string, number>;
  obj.a = 1;
  assert.deepStrictEqual(parseJsonValue(obj), {
    ok: false,
    error: "ERR_INVALID_TYPE",
  });
});

test("rejects symbol-keyed own properties", () => {
  const symKey = Symbol("k");
  const obj: Record<string | symbol, number> = { a: 1 };
  (obj as unknown as Record<string | symbol, number>)[symKey] = 2;
  assert.deepStrictEqual(parseJsonValue(obj), {
    ok: false,
    error: "ERR_INVALID_STRUCTURE",
  });
});

test("does not invoke accessors during inspection", () => {
  let invoked = false;
  const obj: Record<string, unknown> = {};
  Object.defineProperty(obj, "a", {
    enumerable: true,
    configurable: true,
    get() {
      invoked = true;
      throw new Error("must not run");
    },
  });
  assert.deepStrictEqual(parseJsonValue(obj), {
    ok: false,
    error: "ERR_INVALID_STRUCTURE",
  });
  assert.equal(invoked, false);
});

test("handles hostile and revoked proxy objects", () => {
  const hostileProxy = new Proxy({}, {
    getPrototypeOf() {
      throw new Error("hostile proxy");
    },
  });
  assert.doesNotThrow(() => parseJsonValue(hostileProxy));
  assert.deepStrictEqual(parseJsonValue(hostileProxy), {
    ok: false,
    error: "ERR_INVALID_TYPE",
  });

  const revoked = Proxy.revocable({}, {});
  revoked.revoke();
  assert.doesNotThrow(() => parseJsonValue(revoked.proxy));
  // Revoked proxy with empty-handler still delegates to target (valid plain object).
  assert.deepStrictEqual(parseJsonValue(revoked.proxy), {
    ok: false,
    error: "ERR_INVALID_STRUCTURE",
  });
});

test("rejects object cycles (self-reference)", () => {
  const obj: Record<string, unknown> = {};
  obj.a = obj;
  assert.deepStrictEqual(parseJsonValue(obj), {
    ok: false,
    error: "ERR_INVALID_STRUCTURE",
  });
});

test("rejects shared object references in same array", () => {
  const obj: Record<string, number> = { a: 1 };
  assert.deepStrictEqual(parseJsonValue([obj, obj]), {
    ok: false,
    error: "ERR_INVALID_STRUCTURE",
  });
});

test("rejects mixed array-object cycle and shared ref across containers", () => {
  const arr: unknown[] = [];
  const obj: Record<string, unknown> = {};
  arr.push(obj);
  obj.arr = arr;
  assert.deepStrictEqual(parseJsonValue(arr), {
    ok: false,
    error: "ERR_INVALID_STRUCTURE",
  });

  // Shared object ref across containers.
  const sharedObj: Record<string, number> = { a: 1 };
  assert.deepStrictEqual(parseJsonValue([sharedObj, [sharedObj]]), {
    ok: false,
    error: "ERR_INVALID_STRUCTURE",
  });
});

test("deep clone and freeze output", () => {
  const inner: Record<string, number> = { a: 1 };
  const input: unknown[] = [inner];
  const result = parseJsonValue(input);
  assert.equal(result.ok, true);
  if (!result.ok) return;

  // Verify all levels frozen.
  assert.equal(Object.isFrozen(result.value), true);
  assert.equal(Array.isArray(result.value), true);
  const outputInner = (result.value as readonly unknown[])[0] as Record<string, number>;
  assert.equal(Object.getPrototypeOf(outputInner), null);
  assert.equal(Object.isFrozen(outputInner), true);

  // Mutate input after parse.
  inner.a = 999;
  input.push(2);
  const finalResult = result.value as readonly unknown[];
  assert.equal(finalResult.length, 1);
  assert.deepStrictEqual((finalResult[0] as Record<string, number>).a, 1);
});

test("keeps __proto__, constructor, prototype as inert own data keys", () => {
  const obj: Record<string, number> = {};
  Object.defineProperty(obj, "__proto__", { value: 1 });
  Object.defineProperty(obj, "constructor", { value: 2 });
  Object.defineProperty(obj, "prototype", { value: 3 });

  const result = parseJsonValue(obj);
  assert.equal(result.ok, true);
  if (!result.ok) return;

  const output = result.value as Record<string, number>;
  // Verify null prototype.
  assert.equal(Object.getPrototypeOf(output), null);
  // __proto__ on a null-prototype object is an own property; use descriptor to verify value.
  const protoDesc = Object.getOwnPropertyDescriptor(output, "__proto__");
  assert.ok(protoDesc !== undefined);
  assert.deepStrictEqual((protoDesc as PropertyDescriptor).value, 1);
  const keys = Reflect.ownKeys(output) as string[];
  assert.ok(keys.includes("__proto__"));
  assert.ok(keys.includes("constructor"));
  assert.ok(keys.includes("prototype"));
});

test("depth and node accounting across mixed containers", () => {
  // Object at depth 0, array child at depth 1, object grandchild at depth 2.
  const result = parseJsonValue(
    { a: [1] },
    jsonLimits({ maxDepth: 2 }),
  );
  assert.equal(result.ok, true);

  // Depth boundary: obj→arr→obj should fail at depth 3 with maxDepth=2.
  const deepResult = parseJsonValue(
    { a: [{ b: 1 }] },
    jsonLimits({ maxDepth: 2 }),
  );
  assert.deepStrictEqual(deepResult, {
    ok: false,
    error: "ERR_LIMIT_EXCEEDED",
  });

  // Node counting across mixed types.
  const nodeResult = parseJsonValue(
    { a: [1, 2] },
    jsonLimits({ maxNodes: 4 }),
  );
  assert.equal(nodeResult.ok, true);

  // obj(1) + arr(1) + num(1) + num(1) = 4 nodes; one more should fail.
  const nodeOverResult = parseJsonValue(
    { a: [1, 2, 3] },
    jsonLimits({ maxNodes: 4 }),
  );
  assert.deepStrictEqual(nodeOverResult, {
    ok: false,
    error: "ERR_LIMIT_EXCEEDED",
  });
});
