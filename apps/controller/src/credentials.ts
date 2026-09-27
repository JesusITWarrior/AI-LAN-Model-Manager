import { randomBytes, scrypt, timingSafeEqual } from "node:crypto";

export const PASSWORD_MIN_BYTES = 12;
export const PASSWORD_MAX_BYTES = 1024;
export const SCRYPT_N = 1 << 14;
export const SCRYPT_R = 8;
export const SCRYPT_P = 1;
export const SCRYPT_KEY_LENGTH = 64;
export const SCRYPT_SALT_BYTES = 16;
export const SCRYPT_MAX_N = 1 << 18;
export const SCRYPT_MAX_R = 16;
export const SCRYPT_MAX_P = 4;
export const SCRYPT_MAX_KEY_LENGTH = 64;
export const SCRYPT_MAX_MEMORY = 256 * 1024 * 1024;

export type CredentialErrorCode = "ERR_PASSWORD_INPUT" | "ERR_CREDENTIAL_FORMAT" | "ERR_CREDENTIAL_DERIVE";
export class CredentialError extends Error {
  readonly code: CredentialErrorCode;
  constructor(code: CredentialErrorCode) { super(code); this.name = "CredentialError"; this.code = code; }
}

export interface ScryptParameters { readonly N:number; readonly r:number; readonly p:number; readonly keyLength:number }
export interface ParsedCredential extends ScryptParameters { readonly salt:Uint8Array; readonly digest:Uint8Array }
export interface PasswordCryptoEngine {
  random(size:number):Uint8Array;
  derive(password:Uint8Array,salt:Uint8Array,parameters:ScryptParameters):Promise<Uint8Array>;
  equal(left:Uint8Array,right:Uint8Array):boolean;
}

function requiredMemory({N,r,p}:ScryptParameters):number { return 128*r*(N+p+2)+4096; }
function parametersAllowed(parameters:ScryptParameters):boolean {
  return Number.isSafeInteger(parameters.N)&&parameters.N>=SCRYPT_N&&parameters.N<=SCRYPT_MAX_N&&(parameters.N&(parameters.N-1))===0&&
    Number.isSafeInteger(parameters.r)&&parameters.r>=1&&parameters.r<=SCRYPT_MAX_R&&
    Number.isSafeInteger(parameters.p)&&parameters.p>=1&&parameters.p<=SCRYPT_MAX_P&&
    Number.isSafeInteger(parameters.keyLength)&&parameters.keyLength>=32&&parameters.keyLength<=SCRYPT_MAX_KEY_LENGTH&&
    requiredMemory(parameters)<=SCRYPT_MAX_MEMORY;
}

const defaultEngine:PasswordCryptoEngine={
  random:(size)=>randomBytes(size),
  derive:(password,salt,parameters)=>new Promise((resolve,reject)=>{
    scrypt(password,salt,parameters.keyLength,{N:parameters.N,r:parameters.r,p:parameters.p,maxmem:requiredMemory(parameters)},(error,key)=>error?reject(error):resolve(key));
  }),
  equal:(left,right)=>left.length===right.length&&timingSafeEqual(left,right),
};

export function validatePassword(input:unknown):input is string {
  if(typeof input!=="string")return false;
  const bytes=Buffer.byteLength(input,"utf8");
  if(bytes<PASSWORD_MIN_BYTES||bytes>PASSWORD_MAX_BYTES)return false;
  for(const character of input){const code=character.codePointAt(0)!;if(code===0||code<=0x1f||(code>=0x7f&&code<=0x9f))return false;}
  return true;
}

export function normalizeUsername(input:unknown):string|null {
  if(typeof input!=="string"||input.length<1||input.length>64||!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(input))return null;
  return input.toLowerCase();
}

const BASE64URL=/^[A-Za-z0-9_-]+$/;
const DECIMAL=/^[1-9][0-9]*$/;
function positive(value:string):number|null {if(!DECIMAL.test(value))return null;const number=Number(value);return Number.isSafeInteger(number)&&number>0?number:null;}
export function encodeCredential(parameters:ScryptParameters,salt:Uint8Array,digest:Uint8Array):string {
  return ["lanmm","scrypt","1",parameters.N,parameters.r,parameters.p,parameters.keyLength,Buffer.from(salt).toString("base64url"),Buffer.from(digest).toString("base64url")].join("$");
}
export function parseCredential(input:unknown):ParsedCredential|null {
  if(typeof input!=="string"||input.length>512)return null;
  const parts=input.split("$");
  if(parts.length!==9||parts[0]!=="lanmm"||parts[1]!=="scrypt"||parts[2]!=="1")return null;
  const N=positive(parts[3]!),r=positive(parts[4]!),p=positive(parts[5]!),keyLength=positive(parts[6]!);
  if(N===null||r===null||p===null||keyLength===null||!BASE64URL.test(parts[7]!)||!BASE64URL.test(parts[8]!))return null;
  const salt=Buffer.from(parts[7]!,"base64url"),digest=Buffer.from(parts[8]!,"base64url");
  const parsed={N,r,p,keyLength,salt,digest};
  if(!parametersAllowed(parsed)||salt.length<16||salt.length>64||digest.length!==keyLength)return null;
  return parsed;
}

export async function hashPassword(password:unknown,engine:PasswordCryptoEngine=defaultEngine):Promise<string> {
  if(!validatePassword(password))throw new CredentialError("ERR_PASSWORD_INPUT");
  const parameters={N:SCRYPT_N,r:SCRYPT_R,p:SCRYPT_P,keyLength:SCRYPT_KEY_LENGTH};
  const salt=engine.random(SCRYPT_SALT_BYTES);
  if(!(salt instanceof Uint8Array)||salt.length!==SCRYPT_SALT_BYTES)throw new CredentialError("ERR_CREDENTIAL_DERIVE");
  try {const digest=await engine.derive(Buffer.from(password,"utf8"),salt,parameters);if(digest.length!==parameters.keyLength)throw new Error();return encodeCredential(parameters,salt,digest);} catch {throw new CredentialError("ERR_CREDENTIAL_DERIVE");}
}

export async function verifyCredential(encoded:unknown,password:unknown,engine:PasswordCryptoEngine=defaultEngine):Promise<boolean> {
  if(!validatePassword(password))return false;
  const parsed=parseCredential(encoded);
  if(parsed===null)return false; // rejected before derive: protects against attacker-controlled parameters
  try {
    const derived=await engine.derive(Buffer.from(password,"utf8"),parsed.salt,parsed);
    return derived.length===parsed.digest.length&&engine.equal(derived,parsed.digest);
  } catch {return false;}
}

// A syntactically valid constant-cost target for missing-user authentication.
export const DUMMY_CREDENTIAL=encodeCredential(
  {N:SCRYPT_N,r:SCRYPT_R,p:SCRYPT_P,keyLength:SCRYPT_KEY_LENGTH},
  Buffer.alloc(SCRYPT_SALT_BYTES,0x5a),
  Buffer.alloc(SCRYPT_KEY_LENGTH,0xa5),
);
