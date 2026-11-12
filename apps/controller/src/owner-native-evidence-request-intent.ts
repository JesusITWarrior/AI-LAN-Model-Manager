import { types } from "node:util";
import { guardManagementRequest } from "./guard.js";
import {
  OWNER_NATIVE_EVIDENCE_ACTION,
  OWNER_NATIVE_EVIDENCE_DISPOSITION,
  OwnerNativeEvidenceCandidateRegistry,
} from "./owner-native-evidence-candidates.js";
import { createAllowedOrigins } from "./origin.js";
import type { SessionManager } from "./session-manager.js";

const REQUEST_KEYS = ["method", "cookieHeader", "originHeader", "csrfHeader"] as const;
const BODY_KEYS = ["candidateHandle", "expectedTupleDigest", "action", "disposition"] as const;
const HEX_DIGEST = /^[a-f0-9]{64}$/;
const HANDLE = /^[^\u0000-\u001f\u007f]{1,128}$/;
const REQUEST_INTENT_ERROR = Object.freeze(Object.assign(Object.create(null), {
  ok: false as const,
  error: "ERR_NATIVE_EVIDENCE_REQUEST_INTENT" as const,
}));

type Data = Record<string, unknown>;

function ownData(input: unknown, keys: readonly string[]): Data | null {
  try {
    if (typeof input !== "object" || input === null || Array.isArray(input) || types.isProxy(input)) return null;
    const prototype = Object.getPrototypeOf(input);
    if (prototype !== Object.prototype && prototype !== null) return null;
    const ownKeys = Reflect.ownKeys(input);
    if (ownKeys.length !== keys.length || ownKeys.some(key => typeof key !== "string" || !keys.includes(key))) return null;
    const descriptors = Object.getOwnPropertyDescriptors(input);
    const result = Object.create(null) as Data;
    for (const key of keys) {
      const descriptor = descriptors[key];
      if (!descriptor || !("value" in descriptor)) return null;
      result[key] = descriptor.value as unknown;
    }
    return result;
  } catch {
    return null;
  }
}

function validRequestFields(value: Data): boolean {
  return value.method === "POST" &&
    typeof value.cookieHeader === "string" && value.cookieHeader.length <= 4096 &&
    (value.originHeader === null || (typeof value.originHeader === "string" && value.originHeader.length <= 2048)) &&
    (value.csrfHeader === null || (typeof value.csrfHeader === "string" && value.csrfHeader.length <= 128));
}

function validBodyFields(value: Data): boolean {
  return typeof value.candidateHandle === "string" && HANDLE.test(value.candidateHandle) &&
    typeof value.expectedTupleDigest === "string" && HEX_DIGEST.test(value.expectedTupleDigest) &&
    value.action === OWNER_NATIVE_EVIDENCE_ACTION && value.disposition === OWNER_NATIVE_EVIDENCE_DISPOSITION;
}

export type OwnerNativeEvidenceRequestIntent = Readonly<{
  method: "POST";
  candidateHandle: string;
  expectedTupleDigest: string;
  action: typeof OWNER_NATIVE_EVIDENCE_ACTION;
  disposition: typeof OWNER_NATIVE_EVIDENCE_DISPOSITION;
  consentCaptured: false;
  appendAuthorized: false;
  currentHistoryAndCertificateRevalidated: false;
}>;

export type OwnerNativeEvidenceRequestIntentResult =
  | Readonly<{ ok: true; intent: OwnerNativeEvidenceRequestIntent }>
  | typeof REQUEST_INTENT_ERROR;

/**
 * Read-only request-boundary validator. A successful result is display/flow data only:
 * it is not consent, a capability, a lease, or authority to append evidence.
 */
export class OwnerNativeEvidenceRequestIntentValidator {
  private readonly allowedOrigins: readonly string[];

  constructor(
    private readonly manager: SessionManager,
    private readonly registry: OwnerNativeEvidenceCandidateRegistry,
    allowedOrigins: readonly string[],
  ) {
    // Revalidate and defensively copy trusted composition input so later caller mutation
    // cannot widen or replace the origin policy used by this validator.
    this.allowedOrigins = createAllowedOrigins(allowedOrigins);
  }

  validate(requestInput: unknown, bodyInput: unknown): OwnerNativeEvidenceRequestIntentResult {
    try {
      const request = ownData(requestInput, REQUEST_KEYS);
      if (!request || request.method !== "POST") return REQUEST_INTENT_ERROR;
      const body = ownData(bodyInput, BODY_KEYS);
      if (!body || !validRequestFields(request) || !validBodyFields(body)) return REQUEST_INTENT_ERROR;

      const guard = guardManagementRequest(this.manager, this.allowedOrigins, {
        method: "POST",
        cookieHeader: request.cookieHeader as string,
        originHeader: request.originHeader as string | null,
        csrfHeader: request.csrfHeader as string | null,
      });
      if (!guard.ok) return REQUEST_INTENT_ERROR;

      const candidateHandle = body.candidateHandle as string;
      const expectedTupleDigest = body.expectedTupleDigest as string;
      const inspected = this.registry.inspect(guard, candidateHandle);
      if (!inspected.ok || inspected.summary.handle !== candidateHandle ||
          inspected.summary.tupleDigest !== expectedTupleDigest ||
          inspected.summary.action !== OWNER_NATIVE_EVIDENCE_ACTION ||
          inspected.summary.disposition !== OWNER_NATIVE_EVIDENCE_DISPOSITION) return REQUEST_INTENT_ERROR;

      // inspect itself authenticates the session before reading its clock. Recheck after
      // inspection to fail closed if a reentrant/injected clock revoked it in between.
      if (!this.manager.binding(guard.session)) return REQUEST_INTENT_ERROR;

      const intent: OwnerNativeEvidenceRequestIntent = Object.freeze(Object.assign(Object.create(null), {
        method: "POST" as const,
        candidateHandle,
        expectedTupleDigest,
        action: OWNER_NATIVE_EVIDENCE_ACTION,
        disposition: OWNER_NATIVE_EVIDENCE_DISPOSITION,
        consentCaptured: false as const,
        appendAuthorized: false as const,
        currentHistoryAndCertificateRevalidated: false as const,
      }));
      return Object.freeze(Object.assign(Object.create(null), { ok: true as const, intent }));
    } catch {
      return REQUEST_INTENT_ERROR;
    }
  }
}
