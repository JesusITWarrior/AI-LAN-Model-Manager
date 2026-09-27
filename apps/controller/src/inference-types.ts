export const INFERENCE_SCOPES=Object.freeze(["inference:invoke","model:list"] as const);
export type InferenceScope=typeof INFERENCE_SCOPES[number];
export const INFERENCE_TOKEN_BYTES=32;
export const INFERENCE_DEFAULT_TTL_MS=60*60*1000;
export const INFERENCE_MIN_TTL_MS=60*1000;
export const INFERENCE_MAX_TTL_MS=24*60*60*1000;
export type InferenceTokenErrorCode="ERR_INFERENCE_INPUT"|"ERR_INFERENCE_DATABASE"|"ERR_INFERENCE_UNAUTHORIZED"|"ERR_INFERENCE_STALE";
export class InferenceTokenError extends Error {readonly code:InferenceTokenErrorCode;constructor(code:InferenceTokenErrorCode){super(code);this.name="InferenceTokenError";this.code=code;}}
export interface InferenceTokenMetadata {readonly tokenId:string;readonly ownerId:string;readonly label:string;readonly scopes:readonly InferenceScope[];readonly credentialVersion:number;readonly createdAt:string;readonly lastUsedAt:string|null;readonly expiresAt:string|null;readonly revokedAt:string|null}
export interface StoredInferenceToken extends InferenceTokenMetadata {readonly tokenDigest:string}
export interface IssuedInferenceToken {readonly token:string;readonly metadata:InferenceTokenMetadata}
export type InferenceAuthorizationResult={readonly ok:true;readonly token:InferenceTokenMetadata}|{readonly ok:false;readonly status:401;readonly challenge:"Bearer"};
