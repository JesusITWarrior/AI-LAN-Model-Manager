import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { SESSION_TOKEN_BYTES } from "./session-types.js";
const TOKEN=/^[A-Za-z0-9_-]{43}$/;const DIGEST=/^[a-f0-9]{64}$/;
export function generateSessionToken(random:(size:number)=>Uint8Array=(size)=>randomBytes(size)):string {const bytes=random(SESSION_TOKEN_BYTES);if(!(bytes instanceof Uint8Array)||bytes.length!==SESSION_TOKEN_BYTES)throw new Error("ERR_SESSION_INPUT");return Buffer.from(bytes).toString("base64url");}
export function validSessionToken(value:unknown):value is string{return typeof value==="string"&&TOKEN.test(value);}
export function digestSessionToken(value:string):string{return createHash("sha256").update(value,"utf8").digest("hex");}
export function equalDigest(left:unknown,right:unknown):boolean {if(typeof left!=="string"||typeof right!=="string"||!DIGEST.test(left)||!DIGEST.test(right))return false;return timingSafeEqual(Buffer.from(left,"hex"),Buffer.from(right,"hex"));}
