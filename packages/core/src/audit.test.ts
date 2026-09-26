import assert from "node:assert/strict";
import test from "node:test";
import { computeAuditHash, createAuditEvent, parseAuditEventBody, verifyAuditChain, verifyAuditEvent } from "./audit.js";

const body = (sequence = 1, previousHash: string | null = null, overrides: Record<string, unknown> = {}) => ({
  sequence, occurredAt: "2026-09-26T13:00:00.000Z", actorKind: "controller", actorId: "controller-1",
  action: "model.load", outcome: "observed", requestId: "request-1", jobId: "job-1", hostId: "host-1",
  details: { z: 1, a: [true, -0, "✓"] }, previousHash, ...overrides,
});
function event(sequence = 1, previousHash: string | null = null, overrides: Record<string, unknown> = {}) {
  const created = createAuditEvent(body(sequence, previousHash, overrides));
  assert.equal(created.ok, true); if (!created.ok) throw new Error("fixture"); return created.value;
}

test("canonical hashing is stable across key order, -0, and Unicode", () => {
  const a = computeAuditHash(body(1, null, { details: { z: -0, a: "✓" } }));
  const b = computeAuditHash(body(1, null, { details: { a: "✓", z: 0 } }));
  assert.equal(a.ok && b.ok, true); if (a.ok && b.ok) assert.equal(a.value, b.value);
  assert.match(a.ok ? a.value : "", /^[0-9a-f]{64}$/);
});

test("strictly parses immutable bodies and enforces the first-link invariant", () => {
  const parsed = parseAuditEventBody(body()); assert.equal(parsed.ok, true);
  if (parsed.ok) { assert.equal(Object.getPrototypeOf(parsed.value), null); assert.equal(Object.isFrozen(parsed.value), true); assert.equal(Object.isFrozen(parsed.value.details), true); }
  assert.equal(parseAuditEventBody(body(1, "a".repeat(64))).ok, false);
  assert.equal(parseAuditEventBody(body(2, null)).ok, false);
  assert.equal(parseAuditEventBody({ ...body(), extra: true }).ok, false);
});

test("creates flat immutable events and resists source mutation", () => {
  const input = body(); const created = createAuditEvent(input); assert.equal(created.ok, true); if (!created.ok) return;
  assert.equal(Object.getPrototypeOf(created.value), null); assert.equal(Object.isFrozen(created.value), true);
  assert.equal(Object.prototype.hasOwnProperty.call(created.value, "body"), false);
  input.details.a[0] = false;
  const details = created.value.details as { readonly a: readonly unknown[] }; assert.equal(details.a[0], true);
});

test("event verification detects tampering and ordered expectation mismatches", () => {
  const valid = event(); assert.equal(verifyAuditEvent(valid).valid, true);
  const tampered = { ...valid, details: { changed: true } };
  assert.deepStrictEqual(verifyAuditEvent(tampered), { valid: false, reasons: ["hash-mismatch"] });
  const reasons = verifyAuditEvent(valid, "a".repeat(64), 2);
  assert.deepStrictEqual(reasons, { valid: false, reasons: ["previous-hash-mismatch", "sequence-mismatch"] });
  assert.deepStrictEqual(verifyAuditEvent(valid, "bad", "bad"), { valid: false, reasons: ["previous-hash-mismatch", "sequence-mismatch"] });
});

test("invalid event roots, hashes, accessors, and proxies never throw", () => {
  assert.deepStrictEqual(verifyAuditEvent(null), { valid: false, reasons: ["invalid-event"] });
  assert.deepStrictEqual(verifyAuditEvent({ ...event(), hash: "BAD" }), { valid: false, reasons: ["invalid-event"] });
  let invoked = false; const accessor = { ...event() }; Object.defineProperty(accessor, "hash", { get() { invoked = true; throw new Error("no"); } });
  assert.deepStrictEqual(verifyAuditEvent(accessor), { valid: false, reasons: ["invalid-event"] }); assert.equal(invoked, false);
  const revoked = Proxy.revocable(event(), {}); revoked.revoke(); assert.doesNotThrow(() => verifyAuditEvent(revoked.proxy));
});

test("verifies empty and valid linked chains", () => {
  const empty = verifyAuditChain([]); assert.equal(empty.valid, true);
  const first = event(); const second = event(2, first.hash); const third = event(3, second.hash);
  const verified = verifyAuditChain([first, second, third]); assert.equal(verified.valid, true);
  if (verified.valid) { assert.equal(Object.isFrozen(verified.events), true); assert.equal(verified.events.length, 3); }
});

test("chain verification stops at first tamper, link, sequence, or density error", () => {
  const first = event(); const second = event(2, first.hash); const third = event(3, second.hash);
  const tampered = { ...second, outcome: "failed" };
  const badHash = verifyAuditChain([first, tampered, third]); assert.equal(badHash.valid, false); if (!badHash.valid) assert.equal(badHash.index, 1);
  const wrongLink = event(2, "b".repeat(64)); const linkResult = verifyAuditChain([first, wrongLink]); assert.equal(linkResult.valid, false);
  const reordered = verifyAuditChain([second, first]); assert.equal(reordered.valid, false);
  const duplicate = verifyAuditChain([first, first]); assert.equal(duplicate.valid, false);
  const sparse = new Array(2); sparse[0] = first; const sparseResult = verifyAuditChain(sparse); assert.equal(sparseResult.valid, false);
  const decorated = [first] as unknown[] & { note?: string }; decorated.note = "no"; assert.equal(verifyAuditChain(decorated).valid, false);
});

test("body and chain parsers reject hostile inputs without throwing", () => {
  const hostile = new Proxy({}, { ownKeys() { throw new Error("hostile"); } });
  assert.doesNotThrow(() => parseAuditEventBody(hostile));
  const revoked = Proxy.revocable([], {}); revoked.revoke(); assert.doesNotThrow(() => verifyAuditChain(revoked.proxy));
});
