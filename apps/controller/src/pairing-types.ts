import type { PairingBinding,PairingRecord } from "@lan-model-manager/core";
export const PAIRING_CODE_ALPHABET="23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
export const PAIRING_CODE_LENGTH=8;
export const PAIRING_MAX_ATTEMPTS=5;
export const PAIRING_MAX_TTL_MS=10*60*1000;
export type PairingErrorCode="ERR_PAIRING_INPUT"|"ERR_PAIRING_UNAUTHORIZED"|"ERR_PAIRING_CONFLICT"|"ERR_PAIRING_EXPIRED"|"ERR_PAIRING_STATE"|"ERR_PAIRING_PROOF"|"ERR_PAIRING_DATABASE";
export class PairingError extends Error {readonly code:PairingErrorCode;constructor(code:PairingErrorCode){super(code);this.name="PairingError";this.code=code;}}
export interface PairingPresentation {readonly challengeId:string;readonly code:string;readonly controllerNonce:string;readonly binding:PairingBinding;readonly createdAt:string;readonly expiresAt:string}
export interface PairingProofInput {readonly challengeId:string;readonly controllerNonce:string;readonly agentNonce:string;readonly proof:string;readonly binding:PairingBinding}
export interface EnrollmentAuthorization {readonly challengeId:string;readonly ownerId:string;readonly binding:PairingBinding;readonly transcriptDigest:string;readonly authorizedAt:string}
export interface NewPairingRow {readonly challengeId:string;readonly ownerId:string;readonly ownerVersion:number;readonly binding:PairingBinding;readonly codeDigest:string;readonly controllerNonceDigest:string;readonly createdAt:string;readonly expiresAt:string}
export type {PairingBinding,PairingRecord};
