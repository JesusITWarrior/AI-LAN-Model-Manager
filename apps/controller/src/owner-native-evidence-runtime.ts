import type { DatabaseSync } from "node:sqlite";
import type { OriginPolicyOptions } from "./origin.js";
import { createAllowedOrigins } from "./origin.js";
import { OwnerNativeEvidenceIntakeService, type OwnerNativeEvidenceIntakeResult } from "./owner-native-evidence-intake.js";
import { OwnerNativeEvidenceOwnerConfirmService, type OwnerConfirmResult } from "./owner-native-evidence-snapshot.js";
import type { SessionManager } from "./session-manager.js";

export type OwnerNativeEvidenceRuntimeInput = Readonly<{
  db: DatabaseSync;
  sessions: SessionManager;
  allowedOrigins: readonly string[];
  clock: () => string;
  originOptions?: OriginPolicyOptions;
}>;

export type OwnerNativeEvidenceRuntime = Readonly<{
  prepare(input: unknown): OwnerNativeEvidenceIntakeResult;
  confirm(input: unknown): OwnerConfirmResult;
  close(): void;
}>;

/** Owns a single intake/confirm pair backed by the intake's sole candidate registry. */
export function createOwnerNativeEvidenceRuntime(input: OwnerNativeEvidenceRuntimeInput): OwnerNativeEvidenceRuntime {
  const originOptions: OriginPolicyOptions = Object.freeze({ allowLoopbackHttpDevelopment: input.originOptions?.allowLoopbackHttpDevelopment === true });
  const allowedOrigins = createAllowedOrigins([...input.allowedOrigins], originOptions);
  const intake = new OwnerNativeEvidenceIntakeService(input.db, input.sessions, allowedOrigins, input.clock, originOptions);
  let confirm: OwnerNativeEvidenceOwnerConfirmService;
  try {
    confirm = new OwnerNativeEvidenceOwnerConfirmService(input.db, intake.candidateRegistry, input.sessions,
      allowedOrigins, input.clock, originOptions);
  } catch (error) {
    intake.close();
    throw error;
  }
  let closed = false;
  return Object.freeze({
    prepare(value: unknown): OwnerNativeEvidenceIntakeResult {
      if (closed) return Object.freeze({ ok: false as const, error: "ERR_OWNER_NATIVE_EVIDENCE_INTAKE" as const });
      return intake.prepare(value);
    },
    confirm(value: unknown): OwnerConfirmResult {
      if (closed) return Object.freeze({ outcome: "denied" as const });
      return confirm.confirm(value);
    },
    close(): void {
      if (closed) return;
      closed = true;
      intake.close();
    },
  });
}
