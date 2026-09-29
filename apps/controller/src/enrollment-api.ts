import { parsePairingBinding, type CertificateAuthorityMetadata, type HostCertificateMetadata, type PairingBinding } from "@lan-model-manager/core";
import type { CertificateEnrollmentAuthorization } from "./certificate-types.js";
import type { PairingPresentation, PairingProofInput } from "./pairing-types.js";

const HEX64 = /^[a-f0-9]{64}$/;
const JSON_HEADERS = Object.freeze({ "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });

type PairingEnrollmentManager = {
  pendingAgentProof(input: unknown): boolean;
  verifyAgentProof(input: unknown): unknown;
  consume(challengeId: unknown): CertificateEnrollmentAuthorization | null;
};
type CertificateEnrollmentManager = {
  initialize(): CertificateAuthorityMetadata;
  enroll(authorization: CertificateEnrollmentAuthorization, csrPem: string): { readonly certificate: HostCertificateMetadata; readonly ca: CertificateAuthorityMetadata; readonly caCertificatePem: string } | null;
};

export interface EnrollmentApiDependencies {
  /** Resolve the exact public binding to an authoritative candidate, create its challenge, and mark it presented. */
  readonly begin: (binding: PairingBinding) => Promise<PairingPresentation | null>;
  readonly pairing: PairingEnrollmentManager;
  readonly certificates: CertificateEnrollmentManager;
}
export interface EnrollmentApiRequest {
  readonly method: string;
  readonly url: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body?: string;
}
export interface EnrollmentApiResponse {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: Readonly<Record<string, unknown>>;
}

type BeginInput = { readonly binding: PairingBinding; readonly caFingerprint: string };
type CompleteInput = PairingProofInput & { readonly caFingerprint: string; readonly csrPem: string };

function response(status: number, value?: Readonly<Record<string, unknown>>, code?: string, message?: string): EnrollmentApiResponse {
  return Object.freeze({ status, headers: JSON_HEADERS, body: Object.freeze(value ? { ok: true, value } : { ok: false, error: Object.freeze({ code, message }) }) });
}
const invalid = (status = 400, code = "INVALID_REQUEST", message = "Invalid request.") => response(status, undefined, code, message);
const failed = () => response(400, undefined, "ENROLLMENT_FAILED", "Enrollment failed.");

function ownObject(value: unknown, keys: readonly string[]): Record<string, PropertyDescriptor> | null {
  try {
    if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return null;
    const own = Reflect.ownKeys(value);
    if (own.length !== keys.length || own.some(key => typeof key !== "string" || !keys.includes(key))) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    return keys.every(key => descriptors[key] && "value" in descriptors[key]!) ? descriptors : null;
  } catch { return null; }
}
function sameBinding(left: PairingBinding, right: PairingBinding): boolean {
  return left.candidateId === right.candidateId && left.address === right.address && left.port === right.port && left.protocolMajor === right.protocolMajor && left.protocolMinor === right.protocolMinor;
}
function beginInput(value: unknown): BeginInput | null {
  const d = ownObject(value, ["binding", "caFingerprint"]);
  if (!d || typeof d.caFingerprint!.value !== "string" || !HEX64.test(d.caFingerprint!.value)) return null;
  const binding = parsePairingBinding(d.binding!.value);
  return binding.ok ? Object.freeze({ binding: binding.value, caFingerprint: d.caFingerprint!.value }) : null;
}
function completeInput(value: unknown): CompleteInput | null {
  const d = ownObject(value, ["challengeId", "controllerNonce", "agentNonce", "proof", "binding", "caFingerprint", "csrPem"]);
  if (!d || typeof d.caFingerprint!.value !== "string" || !HEX64.test(d.caFingerprint!.value) || typeof d.csrPem!.value !== "string" || d.csrPem!.value.length < 1 || d.csrPem!.value.length > 16_384) return null;
  const binding = parsePairingBinding(d.binding!.value);
  if (!binding.ok) return null;
  return Object.freeze({ challengeId: d.challengeId!.value, controllerNonce: d.controllerNonce!.value, agentNonce: d.agentNonce!.value, proof: d.proof!.value, binding: binding.value, caFingerprint: d.caFingerprint!.value, csrPem: d.csrPem!.value }) as CompleteInput;
}

/** Pure enrollment router. It has no listener and accepts only pairing proof credentials. */
export async function routeEnrollmentRequest(deps: EnrollmentApiDependencies, request: EnrollmentApiRequest): Promise<EnrollmentApiResponse> {
  try {
    let url: URL;
    try { url = new URL(request.url, "http://127.0.0.1"); } catch { return invalid(); }
    if (url.origin !== "http://127.0.0.1" || url.search || url.hash || !url.pathname.startsWith("/agent/v1/enrollment/")) return invalid(404, "NOT_FOUND", "Not found.");
    const known = url.pathname === "/agent/v1/enrollment/begin" || url.pathname === "/agent/v1/enrollment/complete";
    if (!known) return invalid(404, "NOT_FOUND", "Not found.");
    if (request.method !== "POST") return invalid(405, "METHOD_NOT_ALLOWED", "Method not allowed.");
    if (request.headers.authorization !== undefined || request.headers.cookie !== undefined || request.headers["x-csrf-token"] !== undefined) return invalid(401, "UNAUTHORIZED", "Enrollment proof required.");
    if ((request.headers["content-type"] ?? "").split(";", 1)[0]!.trim().toLowerCase() !== "application/json") return invalid(415, "UNSUPPORTED_MEDIA_TYPE", "JSON content type required.");
    const parsed = parseJsonWithoutDuplicateKeys(request.body ?? "");
    if (parsed === null) return invalid();
    const ca = deps.certificates.initialize();
    if (url.pathname.endsWith("/begin")) {
      const input = beginInput(parsed);
      if (!input || input.caFingerprint !== ca.fingerprint) return failed();
      const challenge = await deps.begin(input.binding);
      if (!challenge || !sameBinding(challenge.binding, input.binding)) return failed();
      return response(200, Object.freeze({ challengeId: challenge.challengeId, controllerNonce: challenge.controllerNonce, binding: challenge.binding, expiresAt: challenge.expiresAt, operatorCode: challenge.code, caFingerprint: ca.fingerprint }));
    }
    const input = completeInput(parsed);
    if (!input || input.caFingerprint !== ca.fingerprint) return failed();
    const proof = { challengeId: input.challengeId, controllerNonce: input.controllerNonce, agentNonce: input.agentNonce, proof: input.proof, binding: input.binding };
    if (deps.pairing.pendingAgentProof(proof)) return response(409, undefined, "OWNER_CONFIRMATION_PENDING", "Owner confirmation pending.");
    if (!deps.pairing.verifyAgentProof(proof)) return failed();
    const authorization = deps.pairing.consume(input.challengeId);
    if (!authorization) return failed();
    const enrolled = deps.certificates.enroll(authorization, input.csrPem);
    if (!enrolled || enrolled.ca.fingerprint !== input.caFingerprint || enrolled.caCertificatePem !== ca.certificatePem) return failed();
    return response(200, Object.freeze({ challengeId: input.challengeId, caFingerprint: enrolled.ca.fingerprint, caCertificatePem: enrolled.caCertificatePem, certificateFingerprint: enrolled.certificate.fingerprint, certificateSerial: enrolled.certificate.serial, certificatePem: enrolled.certificate.certificatePem, notBefore: enrolled.certificate.notBefore, notAfter: enrolled.certificate.notAfter }));
  } catch { return failed(); }
}

/** Parse JSON only after a grammar scan proves that every object key is unique. */
export function parseJsonWithoutDuplicateKeys(text: string): unknown | null {
  if (typeof text !== "string" || text.length === 0) return null;
  let index = 0;
  const whitespace = () => { while (index < text.length && /[\t\n\r ]/.test(text[index]!)) index++; };
  const stringToken = (): string | null => {
    if (text[index] !== '"') return null;
    const start = index++;
    while (index < text.length) {
      const character = text[index++];
      if (character === '"') { try { return JSON.parse(text.slice(start, index)) as string; } catch { return null; } }
      if (character === "\\") { if (index >= text.length) return null; const escaped = text[index++]!; if (escaped === "u") { if (!/^[a-fA-F0-9]{4}$/.test(text.slice(index, index + 4))) return null; index += 4; } else if (!'"\\/bfnrt'.includes(escaped)) return null; }
      else if (character!.charCodeAt(0) < 0x20) return null;
    }
    return null;
  };
  const value = (depth: number): boolean => {
    if (depth > 16) return false;
    whitespace();
    if (text[index] === '"') return stringToken() !== null;
    if (text[index] === "{") {
      index++; whitespace(); const keys = new Set<string>();
      if (text[index] === "}") { index++; return true; }
      while (index < text.length) { const key = stringToken(); if (key === null || keys.has(key)) return false; keys.add(key); whitespace(); if (text[index++] !== ":" || !value(depth + 1)) return false; whitespace(); const next = text[index++]; if (next === "}") return true; if (next !== ",") return false; whitespace(); }
      return false;
    }
    if (text[index] === "[") { index++; whitespace(); if (text[index] === "]") { index++; return true; } while (index < text.length) { if (!value(depth + 1)) return false; whitespace(); const next = text[index++]; if (next === "]") return true; if (next !== ",") return false; } return false; }
    const rest = text.slice(index), token = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(rest)?.[0];
    if (!token) return false; index += token.length; return true;
  };
  try { whitespace(); if (!value(0)) return null; whitespace(); if (index !== text.length) return null; return JSON.parse(text); } catch { return null; }
}
