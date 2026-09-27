import { randomBytes } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { DUMMY_CREDENTIAL, hashPassword, normalizeUsername, validatePassword, verifyCredential, type PasswordCryptoEngine } from "./credentials.js";
import { OwnerRepository, OwnerRepositoryError, type OwnerMetadata } from "./owner-repository.js";

export type OwnerBootstrapErrorCode="ERR_OWNER_BOOTSTRAP_INPUT"|"ERR_OWNER_ALREADY_INITIALIZED"|"ERR_OWNER_BOOTSTRAP_DATABASE";
export class OwnerBootstrapError extends Error {readonly code:OwnerBootstrapErrorCode;constructor(code:OwnerBootstrapErrorCode){super(code);this.name="OwnerBootstrapError";this.code=code;}}
export interface OwnerBootstrapInput {readonly username:string;readonly password:string}
export interface OwnerAuthenticationInput {readonly username:string;readonly password:string}
export interface OwnerBootstrapService {bootstrapOwner(input:unknown):Promise<OwnerMetadata>;authenticate(input:unknown):Promise<boolean>;isInitialized():boolean;getOwner():OwnerMetadata|null}
interface ServiceOptions {readonly now?:()=>string;readonly ownerId?:()=>string;readonly crypto?:PasswordCryptoEngine}
const TIME=/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
function fields(input:unknown):{username:string;password:string}|null {
  try {if(typeof input!=="object"||input===null||Array.isArray(input))return null;const proto=Object.getPrototypeOf(input);if(proto!==Object.prototype&&proto!==null)return null;const keys=Reflect.ownKeys(input);if(keys.length!==2||keys.some(key=>typeof key!=="string"||(key!=="username"&&key!=="password")))return null;const descriptors=Object.getOwnPropertyDescriptors(input);const username=descriptors.username,password=descriptors.password;if(!username||!("value" in username)||!password||!("value" in password))return null;if(typeof username.value!=="string"||typeof password.value!=="string")return null;return{username:username.value,password:password.value};}catch{return null;}
}
const defaultId=()=>randomBytes(16).toString("hex");
export function createOwnerBootstrapService(db:DatabaseSync,options:ServiceOptions={}):OwnerBootstrapService {
  const repository=new OwnerRepository(db),now=options.now??(()=>new Date().toISOString()),ownerId=options.ownerId??defaultId;
  async function bootstrapOwner(input:unknown):Promise<OwnerMetadata>{
    const parsed=fields(input),normalized=parsed?normalizeUsername(parsed.username):null;
    if(!parsed||normalized===null||!validatePassword(parsed.password))throw new OwnerBootstrapError("ERR_OWNER_BOOTSTRAP_INPUT");
    if(repository.isInitialized())throw new OwnerBootstrapError("ERR_OWNER_ALREADY_INITIALIZED");
    const credentialHash=await hashPassword(parsed.password,options.crypto);
    const id=ownerId(),createdAt=now();
    if(!/^[a-f0-9]{32}$/.test(id)||!TIME.test(createdAt)||Number.isNaN(Date.parse(createdAt))||new Date(createdAt).toISOString()!==createdAt)throw new OwnerBootstrapError("ERR_OWNER_BOOTSTRAP_DATABASE");
    try {
      db.exec("BEGIN IMMEDIATE");
      if(repository.isInitialized()){db.exec("ROLLBACK");throw new OwnerBootstrapError("ERR_OWNER_ALREADY_INITIALIZED");}
      const result=repository.insertBootstrap({ownerId:id,username:parsed.username,normalizedUsername:normalized,credentialHash,createdAt});
      db.exec("COMMIT");return result;
    } catch(error){try{db.exec("ROLLBACK");}catch{}if(error instanceof OwnerBootstrapError)throw error;if(error instanceof OwnerRepositoryError&&error.code==="ERR_OWNER_CONFLICT")throw new OwnerBootstrapError("ERR_OWNER_ALREADY_INITIALIZED");throw new OwnerBootstrapError("ERR_OWNER_BOOTSTRAP_DATABASE");}
  }
  async function authenticate(input:unknown):Promise<boolean>{
    const parsed=fields(input),normalized=parsed?normalizeUsername(parsed.username):null;
    const password=parsed?.password??"invalid-password-placeholder";
    if(normalized===null||!validatePassword(password))return false;
    let record=null;try{record=repository.findCredential(normalized);}catch{return false;}
    const valid=await verifyCredential(record?.credentialHash??DUMMY_CREDENTIAL,password,options.crypto);
    return record!==null&&!record.disabled&&valid;
  }
  return Object.freeze({bootstrapOwner,authenticate,isInitialized:()=>repository.isInitialized(),getOwner:()=>repository.getMetadata()});
}
