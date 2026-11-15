import React, { useMemo, useRef, useState, useCallback, type ChangeEvent } from "react";
import { OWNER_EVIDENCE_LABEL, type OwnerEvidenceApiClient, type OwnerEvidencePreview, type OwnerConfirmOutcome } from "./evidence-api.js";

/**
 * Owner-evidence review — a source-only preview that replays already-wired native
 * evidence. This slice never executes work, releases a hold, acknowledges a
 * command, or proves remote origin. Confirmation is a single explicit click that
 * posts exactly {candidateHandle, expectedTupleDigest, action, disposition}.
 *
 * Byte bounds and server-side authority are unchanged. Selected bytes are held
 * only until prepare settles, then released. Candidate handle and tuple digest
 * stay in component memory only — never localStorage/sessionStorage.
 */

export function outcomeText(outcome: OwnerConfirmOutcome): string {
  switch (outcome) {
    case "stored":
      return "Evidence appended. Confirmation succeeded, but this did not verify, sign, or prove remote origin.";
    case "already_stored":
      return "Evidence already present. No duplicate was written, but this did not verify, sign, or prove remote origin.";
    case "conflict":
      return "Conflicts with current state. Nothing was written. No verification, signature, hold release, or remote-origin proof is implied.";
    case "stale":
      return "Candidate is no longer current. This cannot execute work, release a hold, acknowledge a command, or prove remote origin. Reintake again with an explicit confirmation.";
    case "denied":
      return "Denied by the controller. This cannot execute work, release a hold, acknowledge a command, or prove remote origin.";
    case "transaction_unknown":
      return "Confirmation outcome is unknown. This requires fresh explicit re-intake. Intake evidence again, then confirm once; it never implies verification, signature, authenticated source, ACK, execution, or hold release.";
    case "committed_unsettled":
      return "Evidence was recorded, but confirmation could not be finalized. This requires fresh explicit re-intake. Intake evidence again, then confirm once; it never implies verification, signature, authenticated source, ACK, execution, or hold release.";
  }
}

export function createOwnerConfirmationGate(
  client: OwnerEvidenceApiClient,
  onOutcome: (outcome: OwnerConfirmOutcome) => void,
  onError: (error: unknown) => void,
  onBusy: (busy: boolean) => void,
) {
  let candidate: OwnerEvidencePreview | null = null;
  let consumed = false;

  return {
    replace(next: OwnerEvidencePreview) {
      candidate = next;
      consumed = false;
    },
    reset() {
      candidate = null;
      consumed = false;
    },
    confirm() {
      if (consumed || candidate === null) return;
      consumed = true;
      const current = candidate;
      onBusy(true);
      void client
        .confirm(current.candidateHandle, current.expectedTupleDigest)
        .then(onOutcome, onError)
        .finally(() => onBusy(false));
    },
  };
}

export function EvidenceOwnerReview({ client }: { client: OwnerEvidenceApiClient }) {
  const [preview, setPreview] = useState<OwnerEvidencePreview | null>(null);
  const [fileState, setFileState] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirmBusy, setConfirmBusy] = useState(false);
  const [outcome, setOutcome] = useState<OwnerConfirmOutcome | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);

  const previewRef = useRef<OwnerEvidencePreview | null>(null);
  const confirmationGate = useMemo(
    () =>
      createOwnerConfirmationGate(
        client,
        (result) => {
          setOutcome(result);
        },
        (e: unknown) => {
          setError(
            e instanceof Error
              ? e.message
              : "The confirmation request failed.",
          );
        },
        setConfirming,
      ),
    [client],
  );

  const handleFile = useCallback(
    async (event: ChangeEvent<HTMLInputElement>) => {
      const input = event.target;
      const file: File | undefined = input.files ? input.files[0] : undefined;
      if (!file) return;
      setError(null);
      setOutcome(null);
      previewRef.current = null;
      confirmationGate.reset();
      setPreview(null);
      setFileState(file.name);
      setBusy(true);
      try {
        const selected: { arrayBuffer(): Promise<ArrayBuffer> } = file;
        const result = await client.prepare(selected);
        previewRef.current = result;
        confirmationGate.replace(result);
        setPreview(result);
      } catch (e) {
        setError(
          e instanceof Error
            ? e.message
            : "Evidence file could not be prepared.",
        );
        setPreview(null);
        previewRef.current = null;
        confirmationGate.reset();
      } finally {
        setBusy(false);
        setFileState(null);
        if (input) input.value = "";
      }
    },
    [client, confirmationGate],
  );

  const handleConfirm = useCallback(() => {
    setOutcome(null);
    setError(null);
    confirmationGate.confirm();
  }, [confirmationGate]);

  const clearAll = useCallback(() => {
    setPreview(null);
    setOutcome(null);
    setError(null);
    previewRef.current = null;
    confirmationGate.reset();
  }, [confirmationGate]);

  return (
    <section className="notice">
      <h3>{OWNER_EVIDENCE_LABEL}</h3>
      <p>
        This view replays owner-native evidence that was already staged by the
        controller. Nothing here executes work, releases a hold, acknowledges a
        command, or proves remote origin.
      </p>

      {preview === null ? (
        <div className="controls">
          <label>
            Select evidence file
            <input
              type="file"
              accept="application/json"
              onChange={handleFile}
              disabled={busy}
            />
          </label>
        </div>
      ) : (
        <div className="review-preview">
          <dl>
            <dt>Label</dt>
            <dd>{preview.label}</dd>
            <dt>Candidate handle</dt>
            <dd>{preview.candidateHandle}</dd>
            <dt>Expected tuple digest</dt>
            <dd>{preview.expectedTupleDigest}</dd>
            <dt>Job ID</dt>
            <dd>{preview.jobId}</dd>
            <dt>Host ID</dt>
            <dd>{preview.hostId}</dd>
            <dt>Request ID</dt>
            <dd>{preview.requestId}</dd>
            <dt>Terminal state</dt>
            <dd>{preview.terminalState}</dd>
            <dt>Terminal revision</dt>
            <dd>{preview.terminalRevision}</dd>
            <dt>Evidence kind</dt>
            <dd>{preview.evidenceKind}</dd>
            <dt>Payload bytes</dt>
            <dd>{preview.payloadBytes}</dd>
            <dt>Response bytes</dt>
            <dd>{preview.responseBytes}</dd>
            <dt>Expires at</dt>
            <dd>{preview.expiresAt}</dd>
            <dt>Action</dt>
            <dd>{preview.action}</dd>
            <dt>Disposition</dt>
            <dd>{preview.disposition}</dd>
          </dl>
          <p>
        {OWNER_EVIDENCE_LABEL}
          </p>
          <div className="controls">
            <button type="button" onClick={handleConfirm} disabled={confirming}>
              {confirming ? "Confirming…" : "Confirm supplemental evidence"}
            </button>
            <button type="button" onClick={clearAll}>Reset</button>
          </div>
        </div>
      )}

      {outcome !== null && (
        <div className="notice" role="alert">
          <strong>{outcome}</strong>
          <p>{outcomeText(outcome)}</p>
          {(outcome === "transaction_unknown" ||
            outcome === "committed_unsettled") && (
            <p>
              Requires fresh explicit re-intake: intake evidence again, then
              confirm once.
            </p>
          )}
        </div>
      )}

      {error && (
        <div className="notice" role="alert">
          <strong>Error</strong>
          <p>{error}</p>
        </div>
      )}

      <p className="muted">
        Retained evidence bytes never persist. No automatic confirm, retry,
        polling, status cache, or authority persistence occurs.
      </p>
    </section>
  );
}
