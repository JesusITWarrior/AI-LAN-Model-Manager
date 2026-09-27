import { createHash,randomBytes,timingSafeEqual } from "node:crypto";
import { INFERENCE_TOKEN_BYTES } from "./inference-types.js";
const TOKEN=new RegExp("^[A-Za-z0-9_-]{43}$");
export function parseAuthorizationBearer(input:unknown):string|null {if(typeof input!=="string"||Buffer.byteLength(input)>256||/[\u0000-\u001f\u007f,]/.test(input))return null;const match=/^Bearer ([A-Za-z0-9_-]{43})$/.exec(input);return match?.[1]??null;}
export function generateInferenceToken(random:(size:number)=>Uint8Array=(size)=>randomBytes(size)):string {const bytes=random(INFERENCE_TOKEN_BYTES);if(!(bytes instanceof Uint8Array)||bytes.length!==INFERENCE_TOKEN_BYTES)throw new Error("ERR_INFERENCE_INPUT");return Buffer.from(bytes).toString("base64url");}
export function validInferenceToken(input:unknown):input is string{return typeof input==="string"&&TOKEN.test(input);}
export function inferenceTokenDigest(token:string):string{return createHash("sha256").update(token,"utf8").digest("hex");}
export function equalInferenceDigest(left:unknown,right:unknown):boolean {if(typeof left!=="string"||typeof right!=="string"||!/^[a-f0-9]{64}$/.test(left)||!/^[a-f0-9]{64}$/.test(right))return false;return timingSafeEqual(Buffer.from(left,"hex"),Buffer.from(right,"hex"));}
