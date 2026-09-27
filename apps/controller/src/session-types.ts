export const SESSION_COOKIE_NAME="__Host-lanmm_session";
export const SESSION_TOKEN_BYTES=32;
export const SESSION_ABSOLUTE_TTL_MS=24*60*60*1000;
export const SESSION_IDLE_TTL_MS=30*60*1000;
export type SessionErrorCode="ERR_SESSION_INPUT"|"ERR_SESSION_DATABASE"|"ERR_SESSION_UNAUTHENTICATED"|"ERR_SESSION_STALE";
export class SessionError extends Error {readonly code:SessionErrorCode;constructor(code:SessionErrorCode){super(code);this.name="SessionError";this.code=code;}}
export interface SessionMetadata {readonly ownerId:string;readonly credentialVersion:number;readonly sessionVersion:number;readonly createdAt:string;readonly lastSeenAt:string;readonly absoluteExpiresAt:string;readonly idleExpiresAt:string;readonly revokedAt:string|null}
export interface CreatedSession {readonly sessionToken:string;readonly csrfToken:string;readonly metadata:SessionMetadata;readonly maxAgeSeconds:number}
export interface StoredSession extends SessionMetadata {readonly sessionDigest:string;readonly csrfDigest:string}
export interface SessionPolicy {readonly absoluteTtlMs:number;readonly idleTtlMs:number;readonly touchAfterMs:number}
