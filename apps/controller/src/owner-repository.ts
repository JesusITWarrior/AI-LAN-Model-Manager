import type { DatabaseSync } from "node:sqlite";
import { normalizeUsername, parseCredential } from "./credentials.js";

export type OwnerRepositoryErrorCode="ERR_OWNER_INPUT"|"ERR_OWNER_DATABASE"|"ERR_OWNER_CONFLICT"|"ERR_OWNER_STALE";
export class OwnerRepositoryError extends Error {readonly code:OwnerRepositoryErrorCode;constructor(code:OwnerRepositoryErrorCode){super(code);this.name="OwnerRepositoryError";this.code=code;}}
export interface OwnerMetadata {readonly ownerId:string;readonly username:string;readonly disabled:boolean;readonly version:number;readonly createdAt:string;readonly updatedAt:string}
export interface OwnerCredentialRecord extends OwnerMetadata {readonly normalizedUsername:string;readonly credentialHash:string}
export interface NewOwnerRecord {readonly ownerId:string;readonly username:string;readonly normalizedUsername:string;readonly credentialHash:string;readonly createdAt:string}
const OWNER=/^[a-f0-9]{32}$/;const TIME=/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const validTime=(value:unknown):value is string=>typeof value==="string"&&TIME.test(value)&&!Number.isNaN(Date.parse(value))&&new Date(value).toISOString()===value;
const frozen=<T>(values:Record<string,unknown>):T=>Object.freeze(Object.assign(Object.create(null),values)) as T;
const fail=():never=>{throw new OwnerRepositoryError("ERR_OWNER_DATABASE");};
function query<T>(fn:()=>T):T{try{return fn();}catch(error){if(error instanceof OwnerRepositoryError)throw error;return fail();}}
function metadata(row:Record<string,unknown>):OwnerMetadata {
  const ownerId=row.owner_id,username=row.username_display,normalized=row.username_normalized,disabled=row.disabled,version=row.credential_version,createdAt=row.created_at,updatedAt=row.updated_at;
  if(typeof ownerId!=="string"||!OWNER.test(ownerId)||typeof username!=="string"||normalizeUsername(username)!==normalized||typeof disabled!=="number"||(disabled!==0&&disabled!==1)||typeof version!=="number"||!Number.isSafeInteger(version)||version<1||!validTime(createdAt)||!validTime(updatedAt))return fail();
  return frozen<OwnerMetadata>({ownerId,username,disabled:disabled===1,version,createdAt,updatedAt});
}

export class OwnerRepository {
  constructor(private readonly db:DatabaseSync){}
  isInitialized():boolean{return query(()=>{const row=this.db.prepare("SELECT count(*) AS count FROM owners").get() as {count:number|bigint};return Number(row.count)>0;});}
  getMetadata():OwnerMetadata|null{return query(()=>{const row=this.db.prepare("SELECT owner_id,username_display,username_normalized,disabled,credential_version,created_at,updated_at FROM owners WHERE singleton_key=1").get() as Record<string,unknown>|undefined;return row?metadata(row):null;});}
  findCredential(normalizedUsername:unknown):OwnerCredentialRecord|null {
    if(typeof normalizedUsername!=="string"||normalizeUsername(normalizedUsername)!==normalizedUsername)throw new OwnerRepositoryError("ERR_OWNER_INPUT");
    return query(()=>{const row=this.db.prepare("SELECT * FROM owners WHERE singleton_key=1 AND username_normalized=?").get(normalizedUsername) as Record<string,unknown>|undefined;if(!row)return null;const base=metadata(row);if(typeof row.credential_hash!=="string"||parseCredential(row.credential_hash)===null)return fail();return frozen<OwnerCredentialRecord>({...base,normalizedUsername,credentialHash:row.credential_hash});});
  }
  insertBootstrap(record:NewOwnerRecord):OwnerMetadata {
    if(!OWNER.test(record.ownerId)||normalizeUsername(record.username)!==record.normalizedUsername||parseCredential(record.credentialHash)===null||!validTime(record.createdAt))throw new OwnerRepositoryError("ERR_OWNER_INPUT");
    return query(()=>{try{this.db.prepare("INSERT INTO owners(singleton_key,owner_id,username_display,username_normalized,credential_hash,disabled,credential_version,created_at,updated_at) VALUES(1,?,?,?,?,0,1,?,?)").run(record.ownerId,record.username,record.normalizedUsername,record.credentialHash,record.createdAt,record.createdAt);}catch{const row=this.db.prepare("SELECT count(*) AS count FROM owners").get() as {count:number|bigint};if(Number(row.count)>0)throw new OwnerRepositoryError("ERR_OWNER_CONFLICT");throw new OwnerRepositoryError("ERR_OWNER_DATABASE");}const result=this.getMetadata();if(!result)return fail();return result;});
  }
  setDisabled(ownerId:unknown,expectedVersion:unknown,disabled:unknown,updatedAt:unknown):OwnerMetadata {
    if(typeof ownerId!=="string"||!OWNER.test(ownerId)||typeof expectedVersion!=="number"||!Number.isSafeInteger(expectedVersion)||expectedVersion<1||typeof disabled!=="boolean"||!validTime(updatedAt))throw new OwnerRepositoryError("ERR_OWNER_INPUT");
    return query(()=>{const result=this.db.prepare("UPDATE owners SET disabled=?,credential_version=credential_version+1,updated_at=? WHERE singleton_key=1 AND owner_id=? AND credential_version=?").run(disabled?1:0,updatedAt,ownerId,expectedVersion);if(result.changes!==1)throw new OwnerRepositoryError("ERR_OWNER_STALE");const value=this.getMetadata();if(!value)return fail();return value;});
  }
}
export function createOwnerRepository(db:DatabaseSync):OwnerRepository{return new OwnerRepository(db);}
