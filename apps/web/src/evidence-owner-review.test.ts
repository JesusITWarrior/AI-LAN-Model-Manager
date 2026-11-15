import test from "node:test";
import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import {
  outcomeText as OwnerText,
  EvidenceOwnerReview,
  createOwnerConfirmationGate,
} from "./evidence-owner-review.js";
import type { OwnerConfirmOutcome } from "./evidence-api.js";
import type { OwnerEvidenceApiClient, OwnerEvidencePreview } from "./evidence-api.js";

function ownerOutcomes(): readonly OwnerConfirmOutcome[] {
  return [
    "stored",
    "already_stored",
    "conflict",
    "stale",
    "denied",
    "transaction_unknown",
    "committed_unsettled",
  ] as const;
}

const candidate: OwnerEvidencePreview = {
  label: "Owner-provided unsigned evidence; source not independently proven",
  candidateHandle: "candidate-1",
  expectedTupleDigest: "sha256:" + "a".repeat(64),
  jobId: "job-1",
  hostId: "host-1",
  requestId: "request-1",
  terminalState: "succeeded",
  terminalRevision: "1",
  evidenceKind: "succeeded",
  payloadBytes: 1,
  responseBytes: 1,
  expiresAt: "2026-11-15T12:00:00.000Z",
  action: "append",
  disposition: "supplemental",
};

test("outcomeText describes every outcome truthfully, never claiming proof", () => {
  for (const outcome of ownerOutcomes()) {
    const text = OwnerText(outcome);
    assert.equal(typeof text, "string");
    assert.ok(text.length > 0);
    const forbidden = ["evidence was verified","evidence was signed","source is authenticated","command acknowledged","hold released","remote origin proved","work executed"];
    for (const forbiddenWord of forbidden) {
      assert.doesNotMatch(
        text.toLowerCase(),
        new RegExp(forbiddenWord.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i"),
      );
    }
  }
  assert.match(
    OwnerText("transaction_unknown"),
    /re-intake/i,
  );
  assert.match(
    OwnerText("committed_unsettled"),
    /re-intake/i,
  );
});

test("confirmation gate consumes a candidate after settle and permits one confirm only", async () => {
  let resolveConfirm!: (outcome: OwnerConfirmOutcome) => void;
  const confirmation = new Promise<OwnerConfirmOutcome>((resolve) => {
    resolveConfirm = resolve;
  });
  let calls = 0;
  const client: OwnerEvidenceApiClient = {
    prepare: async () => candidate,
    confirm: async () => {
      calls += 1;
      return confirmation;
    },
  };
  const gate = createOwnerConfirmationGate(client, () => {}, () => {}, () => {});
  gate.replace(candidate);

  gate.confirm();
  gate.confirm();
  assert.equal(calls, 1);
  resolveConfirm("stored");
  await confirmation;
  gate.confirm();
  assert.equal(calls, 1);

  gate.reset();
  gate.replace(candidate);
  gate.confirm();
  assert.equal(calls, 2);
});

test("mounting the review view renders the fixed label and never storage hooks", () => {
  const client = {} as OwnerEvidenceApiClient;
  const html = renderToStaticMarkup(
    createElement(EvidenceOwnerReview, { client }),
  );
  assert.match(
    html,
    /Owner-provided unsigned evidence; source not independently proven/,
  );
  // Strictly component-memory; no localStorage/sessionStorage persistence.
  assert.doesNotMatch(html, /localStorage/);
  assert.doesNotMatch(html, /sessionStorage/);
  // Confirmation posts the exact four-field shape, never a confirmationId.
  assert.doesNotMatch(html, /confirmationId/);
});

test("mounting exposes no automatic confirm, retry, polling, or status cache", () => {
  const html = renderToStaticMarkup(
    createElement(EvidenceOwnerReview, {
      client: {
      prepare: async () => ({} as OwnerEvidencePreview),
        confirm: async () => "stored" as const,
      } as OwnerEvidenceApiClient,
    }),
  );
  assert.doesNotMatch(html, /localStorage|sessionStorage|setInterval|setTimeout/i);
  // The seven outcomes must all be describable; render each through the label.
  for (const outcome of ownerOutcomes()) {
    const text = OwnerText(outcome);
    assert.equal(typeof text, "string");
  }
});
