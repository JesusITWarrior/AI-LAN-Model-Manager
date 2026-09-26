import assert from "node:assert/strict";
import test from "node:test";
import {
  CURRENT_PROTOCOL_VERSION,
  isProtocolVersionCompatible,
  parseProtocolId,
  parseProtocolVersion,
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
