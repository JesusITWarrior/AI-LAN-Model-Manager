import type { DatabaseSync, SQLInputValue } from "node:sqlite";
import { PersistenceError } from "./database.js";

export const MAX_SNAPSHOT_BYTES = 65_536;
export const MAX_INVENTORY_PROVIDERS = 128;
export const MAX_INVENTORY_MODELS = 10_000;
export type UpsertOutcome = "inserted" | "updated" | "ignored_stale";

export class RepositoryError extends Error {
  readonly code: "ERR_REPOSITORY_INPUT" | "ERR_REPOSITORY_DATABASE" | "ERR_RECONCILE_INPUT";
  constructor(code: RepositoryError["code"]) { super(code); this.name = "RepositoryError"; this.code = code; }
}

export interface HostRecord { readonly hostId:string; readonly displayName:string; readonly platform:"linux"|"darwin"|"windows"; readonly observedAt:string; readonly online:boolean; readonly freshness:"fresh"|"stale"|"offline"; readonly snapshot:unknown }
export interface ProviderRecord { readonly providerId:string; readonly hostId:string; readonly kind:"ollama"|"lmstudio"; readonly endpoint:string; readonly health:"ready"|"degraded"|"unavailable"|"failed"; readonly version:string; readonly versionKnown:boolean; readonly observedAt:string; readonly snapshot:unknown }
export interface ModelRecord { readonly modelId:string; readonly providerId:string; readonly hostId:string; readonly canonicalName:string; readonly state:"available"|"installed"|"running"; readonly type:"llm"|"embedding"|"unknown"; readonly digest:string; readonly digestKnown:boolean; readonly observedAt:string; readonly snapshot:unknown }
export interface HostInventorySnapshot { readonly cutoffObservedAt:string; readonly host:unknown; readonly providers:unknown; readonly models:unknown }
export interface ReconcileCounts { readonly host:UpsertOutcome; readonly providersInserted:number; readonly providersUpdated:number; readonly providersIgnoredStale:number; readonly providersDeleted:number; readonly modelsInserted:number; readonly modelsUpdated:number; readonly modelsIgnoredStale:number; readonly modelsDeleted:number }

const ID=/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const TIME=/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const ENDPOINT=/^https?:\/\/[^\s/?#@]+(?::\d{1,5})?$/;
const exact=(input:unknown, keys:readonly string[]):Record<string,PropertyDescriptor>|null=>{
  try { if(typeof input!=="object"||input===null||Array.isArray(input))return null; const p=Object.getPrototypeOf(input); if(p!==Object.prototype&&p!==null)return null; const own=Reflect.ownKeys(input); if(own.length!==keys.length||own.some(k=>typeof k!=="string"||!keys.includes(k))||keys.some(k=>!own.includes(k)))return null; const d=Object.getOwnPropertyDescriptors(input); if(keys.some(k=>!d[k]||!("value" in d[k])))return null; return d; } catch{return null;}
};
const value=(d:Record<string,PropertyDescriptor>,k:string):unknown=>d[k]?.value;
const validId=(v:unknown):v is string=>typeof v==="string"&&ID.test(v);
const validText=(v:unknown,max=256):v is string=>typeof v==="string"&&v.length>0&&v.length<=max&&v.trim()===v&&!/[\u0000-\u001f\u007f]/u.test(v);
const validTime=(v:unknown):v is string=>typeof v==="string"&&TIME.test(v)&&!Number.isNaN(Date.parse(v))&&new Date(v).toISOString()===v;
function strictArray(input:unknown, maximum:number):unknown[]{
  try {
    if(!Array.isArray(input))throw new RepositoryError("ERR_RECONCILE_INPUT");
    const descriptors=Object.getOwnPropertyDescriptors(input) as Record<string,PropertyDescriptor>;
    const length=descriptors["length"]?.value as unknown;
    if(!Number.isSafeInteger(length)||(length as number)<0||(length as number)>maximum)throw new RepositoryError("ERR_RECONCILE_INPUT");
    const count=length as number;
    const keys=Reflect.ownKeys(input);
    if(keys.some(key=>typeof key!=="string"||(key!=="length"&&!/^(0|[1-9]\d*)$/.test(key))))throw new RepositoryError("ERR_RECONCILE_INPUT");
    const output:unknown[]=[];
    for(let index=0;index<count;index++){const descriptor=descriptors[String(index)];if(!descriptor||!("value" in descriptor))throw new RepositoryError("ERR_RECONCILE_INPUT");output.push(descriptor.value);}
    return output;
  } catch(error){if(error instanceof RepositoryError)throw error;throw new RepositoryError("ERR_RECONCILE_INPUT");}
}

function sanitizeJson(input:unknown, depth=0, seen=new Set<object>()):unknown {
  if(depth>12)throw new RepositoryError("ERR_REPOSITORY_INPUT");
  if(input===null||typeof input==="string"||typeof input==="boolean")return input;
  if(typeof input==="number"){if(!Number.isFinite(input)||!Number.isSafeInteger(input))throw new RepositoryError("ERR_REPOSITORY_INPUT");return input;}
  if(typeof input!=="object")throw new RepositoryError("ERR_REPOSITORY_INPUT");
  if(seen.has(input))throw new RepositoryError("ERR_REPOSITORY_INPUT"); seen.add(input);
  try {
    if(Array.isArray(input)){const keys=Reflect.ownKeys(input);if(keys.some(k=>typeof k!=="string"||(k!=="length"&&!/^(0|[1-9]\d*)$/.test(k))))throw new RepositoryError("ERR_REPOSITORY_INPUT");const desc=Object.getOwnPropertyDescriptors(input);const out:unknown[]=[];for(let i=0;i<input.length;i++){const d=desc[String(i)];if(!d||!("value" in d))throw new RepositoryError("ERR_REPOSITORY_INPUT");out.push(sanitizeJson(d.value,depth+1,seen));}return Object.freeze(out);}
    const p=Object.getPrototypeOf(input);if(p!==Object.prototype&&p!==null)throw new RepositoryError("ERR_REPOSITORY_INPUT");const keys=Reflect.ownKeys(input);if(keys.some(k=>typeof k!=="string"||k.length===0||k.length>128))throw new RepositoryError("ERR_REPOSITORY_INPUT");const desc=Object.getOwnPropertyDescriptors(input);const out=Object.create(null) as Record<string,unknown>;for(const k of keys as string[]){const d=desc[k];if(!d||!("value" in d))throw new RepositoryError("ERR_REPOSITORY_INPUT");out[k]=sanitizeJson(d.value,depth+1,seen);}return Object.freeze(out);
  } finally {seen.delete(input);}
}
function snapshot(input:unknown):{value:unknown;json:string}{const safe=sanitizeJson(input);const json=JSON.stringify(safe);if(Buffer.byteLength(json)>MAX_SNAPSHOT_BYTES)throw new RepositoryError("ERR_REPOSITORY_INPUT");return{value:safe,json};}
const frozen=<T>(o:Record<string,unknown>):T=>Object.freeze(Object.assign(Object.create(null),o)) as T;
const deepCounts=(o:ReconcileCounts):ReconcileCounts=>frozen<ReconcileCounts>({...o});
const dbFail=():never=>{throw new RepositoryError("ERR_REPOSITORY_DATABASE");};
function query<T>(fn:()=>T):T{try{return fn();}catch(e){if(e instanceof RepositoryError||e instanceof PersistenceError)throw e;return dbFail();}}

const hostKeys=["hostId","displayName","platform","observedAt","online","freshness","snapshot"] as const;
export function parseHostRecord(input:unknown):HostRecord {const d=exact(input,hostKeys);if(!d)throw new RepositoryError("ERR_REPOSITORY_INPUT");const hostId=value(d,"hostId"),displayName=value(d,"displayName"),platform=value(d,"platform"),observedAt=value(d,"observedAt"),online=value(d,"online"),freshness=value(d,"freshness");if(!validId(hostId)||!validText(displayName)||!(["linux","darwin","windows"] as unknown[]).includes(platform)||!validTime(observedAt)||typeof online!=="boolean"||!(["fresh","stale","offline"] as unknown[]).includes(freshness))throw new RepositoryError("ERR_REPOSITORY_INPUT");const snap=snapshot(value(d,"snapshot"));return frozen<HostRecord>({hostId,displayName,platform,observedAt,online,freshness,snapshot:snap.value});}
const providerKeys=["providerId","hostId","kind","endpoint","health","version","versionKnown","observedAt","snapshot"] as const;
export function parseProviderRecord(input:unknown):ProviderRecord {const d=exact(input,providerKeys);if(!d)throw new RepositoryError("ERR_REPOSITORY_INPUT");const providerId=value(d,"providerId"),hostId=value(d,"hostId"),kind=value(d,"kind"),endpoint=value(d,"endpoint"),health=value(d,"health"),version=value(d,"version"),versionKnown=value(d,"versionKnown"),observedAt=value(d,"observedAt");if(!validId(providerId)||!validId(hostId)||!(["ollama","lmstudio"] as unknown[]).includes(kind)||typeof endpoint!=="string"||endpoint.length>2048||!ENDPOINT.test(endpoint)||!(["ready","degraded","unavailable","failed"] as unknown[]).includes(health)||typeof version!=="string"||version.length>128||typeof versionKnown!=="boolean"||(!versionKnown&&version!=="")||!validTime(observedAt))throw new RepositoryError("ERR_REPOSITORY_INPUT");const snap=snapshot(value(d,"snapshot"));return frozen<ProviderRecord>({providerId,hostId,kind,endpoint,health,version,versionKnown,observedAt,snapshot:snap.value});}
const modelKeys=["modelId","providerId","hostId","canonicalName","state","type","digest","digestKnown","observedAt","snapshot"] as const;
export function parseModelRecord(input:unknown):ModelRecord {const d=exact(input,modelKeys);if(!d)throw new RepositoryError("ERR_REPOSITORY_INPUT");const modelId=value(d,"modelId"),providerId=value(d,"providerId"),hostId=value(d,"hostId"),canonicalName=value(d,"canonicalName"),state=value(d,"state"),type=value(d,"type"),digest=value(d,"digest"),digestKnown=value(d,"digestKnown"),observedAt=value(d,"observedAt");if(!validId(modelId)||!validId(providerId)||!validId(hostId)||!validText(canonicalName,512)||!(["available","installed","running"] as unknown[]).includes(state)||!(["llm","embedding","unknown"] as unknown[]).includes(type)||typeof digest!=="string"||typeof digestKnown!=="boolean"||(digestKnown?!/^[a-f0-9]{64}$/.test(digest):digest!=="")||!validTime(observedAt))throw new RepositoryError("ERR_REPOSITORY_INPUT");const snap=snapshot(value(d,"snapshot"));return frozen<ModelRecord>({modelId,providerId,hostId,canonicalName,state,type,digest,digestKnown,observedAt,snapshot:snap.value});}

function decodeHost(r:Record<string,unknown>):HostRecord{return parseHostRecord({hostId:r.host_id,displayName:r.display_name,platform:r.platform,observedAt:r.observed_at,online:r.online===1,freshness:r.freshness,snapshot:JSON.parse(r.snapshot_json as string)});}
function decodeProvider(r:Record<string,unknown>):ProviderRecord{return parseProviderRecord({providerId:r.provider_id,hostId:r.host_id,kind:r.kind,endpoint:r.endpoint,health:r.health,version:r.version,versionKnown:r.version_known===1,observedAt:r.observed_at,snapshot:JSON.parse(r.snapshot_json as string)});}
function decodeModel(r:Record<string,unknown>):ModelRecord{return parseModelRecord({modelId:r.model_id,providerId:r.provider_id,hostId:r.host_id,canonicalName:r.canonical_name,state:r.state,type:r.type,digest:r.digest,digestKnown:r.digest_known===1,observedAt:r.observed_at,snapshot:JSON.parse(r.snapshot_json as string)});}

class BaseRepo { constructor(protected readonly db:DatabaseSync, protected readonly now:()=>string=()=>new Date().toISOString()){} protected existing(table:string,idColumn:string,id:string):string|null{return query(()=>{const r=this.db.prepare(`SELECT observed_at FROM ${table} WHERE ${idColumn}=?`).get(id) as {observed_at:string}|undefined;return r?.observed_at??null;});} }
export class HostRepository extends BaseRepo {
 upsert(input:unknown):UpsertOutcome{const v=parseHostRecord(input),s=snapshot(v.snapshot),old=this.existing("hosts","host_id",v.hostId);if(old!==null&&v.observedAt<=old)return"ignored_stale";return query(()=>{const now=this.now();this.db.prepare(`INSERT INTO hosts(host_id,display_name,platform,observed_at,online,freshness,snapshot_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(host_id) DO UPDATE SET display_name=excluded.display_name,platform=excluded.platform,observed_at=excluded.observed_at,online=excluded.online,freshness=excluded.freshness,snapshot_json=excluded.snapshot_json,updated_at=excluded.updated_at WHERE excluded.observed_at>hosts.observed_at`).run(v.hostId,v.displayName,v.platform,v.observedAt,v.online?1:0,v.freshness,s.json,now,now);return old===null?"inserted":"updated";});}
 get(id:unknown):HostRecord|null{if(!validId(id))throw new RepositoryError("ERR_REPOSITORY_INPUT");return query(()=>{const r=this.db.prepare("SELECT * FROM hosts WHERE host_id=?").get(id) as Record<string,unknown>|undefined;return r?decodeHost(r):null;});}
 list():readonly HostRecord[]{return Object.freeze(query(()=>(this.db.prepare("SELECT * FROM hosts ORDER BY host_id").all() as Record<string,unknown>[]).map(decodeHost)));}
}
export class ProviderRepository extends BaseRepo {
 upsert(input:unknown):UpsertOutcome{const v=parseProviderRecord(input),s=snapshot(v.snapshot),old=this.existing("providers","provider_id",v.providerId);if(old!==null&&v.observedAt<=old)return"ignored_stale";return query(()=>{const parent=this.db.prepare("SELECT host_id FROM providers WHERE provider_id=?").get(v.providerId) as {host_id:string}|undefined;if(parent&&parent.host_id!==v.hostId)throw new Error();const now=this.now();this.db.prepare(`INSERT INTO providers(provider_id,host_id,kind,endpoint,health,version,version_known,observed_at,snapshot_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(provider_id) DO UPDATE SET host_id=excluded.host_id,kind=excluded.kind,endpoint=excluded.endpoint,health=excluded.health,version=excluded.version,version_known=excluded.version_known,observed_at=excluded.observed_at,snapshot_json=excluded.snapshot_json,updated_at=excluded.updated_at WHERE excluded.observed_at>providers.observed_at`).run(v.providerId,v.hostId,v.kind,v.endpoint,v.health,v.version,v.versionKnown?1:0,v.observedAt,s.json,now,now);return old===null?"inserted":"updated";});}
 get(id:unknown):ProviderRecord|null{if(!validId(id))throw new RepositoryError("ERR_REPOSITORY_INPUT");return query(()=>{const r=this.db.prepare("SELECT * FROM providers WHERE provider_id=?").get(id) as Record<string,unknown>|undefined;return r?decodeProvider(r):null;});}
 listByHost(hostId:unknown):readonly ProviderRecord[]{if(!validId(hostId))throw new RepositoryError("ERR_REPOSITORY_INPUT");return Object.freeze(query(()=>(this.db.prepare("SELECT * FROM providers WHERE host_id=? ORDER BY provider_id").all(hostId) as Record<string,unknown>[]).map(decodeProvider)));}
}
export class ModelRepository extends BaseRepo {
 upsert(input:unknown):UpsertOutcome{const v=parseModelRecord(input),s=snapshot(v.snapshot),old=this.existing("models","model_id",v.modelId);if(old!==null&&v.observedAt<=old)return"ignored_stale";return query(()=>{const parent=this.db.prepare("SELECT host_id FROM providers WHERE provider_id=?").get(v.providerId) as {host_id:string}|undefined;const existing=this.db.prepare("SELECT provider_id,host_id FROM models WHERE model_id=?").get(v.modelId) as {provider_id:string;host_id:string}|undefined;if(!parent||parent.host_id!==v.hostId||existing&&(existing.provider_id!==v.providerId||existing.host_id!==v.hostId))throw new Error();const now=this.now();this.db.prepare(`INSERT INTO models(model_id,provider_id,host_id,canonical_name,state,type,digest,digest_known,observed_at,snapshot_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(model_id) DO UPDATE SET provider_id=excluded.provider_id,host_id=excluded.host_id,canonical_name=excluded.canonical_name,state=excluded.state,type=excluded.type,digest=excluded.digest,digest_known=excluded.digest_known,observed_at=excluded.observed_at,snapshot_json=excluded.snapshot_json,updated_at=excluded.updated_at WHERE excluded.observed_at>models.observed_at`).run(v.modelId,v.providerId,v.hostId,v.canonicalName,v.state,v.type,v.digest,v.digestKnown?1:0,v.observedAt,s.json,now,now);return old===null?"inserted":"updated";});}
 get(id:unknown):ModelRecord|null{if(!validId(id))throw new RepositoryError("ERR_REPOSITORY_INPUT");return query(()=>{const r=this.db.prepare("SELECT * FROM models WHERE model_id=?").get(id) as Record<string,unknown>|undefined;return r?decodeModel(r):null;});}
 listByProvider(providerId:unknown):readonly ModelRecord[]{if(!validId(providerId))throw new RepositoryError("ERR_REPOSITORY_INPUT");return Object.freeze(query(()=>(this.db.prepare("SELECT * FROM models WHERE provider_id=? ORDER BY canonical_name,model_id").all(providerId) as Record<string,unknown>[]).map(decodeModel)));}
 listByHost(hostId:unknown):readonly ModelRecord[]{if(!validId(hostId))throw new RepositoryError("ERR_REPOSITORY_INPUT");return Object.freeze(query(()=>(this.db.prepare("SELECT * FROM models WHERE host_id=? ORDER BY canonical_name,model_id").all(hostId) as Record<string,unknown>[]).map(decodeModel)));}
}

export class ControllerRepositories {
 readonly hosts:HostRepository;readonly providers:ProviderRepository;readonly models:ModelRepository;
 constructor(readonly db:DatabaseSync,now:()=>string=()=>new Date().toISOString()){this.hosts=new HostRepository(db,now);this.providers=new ProviderRepository(db,now);this.models=new ModelRepository(db,now);Object.freeze(this);}
 reconcileHostInventory(input:unknown):ReconcileCounts {
  const d=exact(input,["cutoffObservedAt","host","providers","models"]);if(!d)throw new RepositoryError("ERR_RECONCILE_INPUT");const cutoff=value(d,"cutoffObservedAt");if(!validTime(cutoff))throw new RepositoryError("ERR_RECONCILE_INPUT");const host=parseHostRecord(value(d,"host"));let providers:ProviderRecord[],models:ModelRecord[];try{providers=strictArray(value(d,"providers"),MAX_INVENTORY_PROVIDERS).map(parseProviderRecord);models=strictArray(value(d,"models"),MAX_INVENTORY_MODELS).map(parseModelRecord);}catch{throw new RepositoryError("ERR_RECONCILE_INPUT");}const pids=new Set<string>(),mids=new Set<string>();for(const p of providers){if(p.hostId!==host.hostId||pids.has(p.providerId))throw new RepositoryError("ERR_RECONCILE_INPUT");pids.add(p.providerId);}for(const m of models){if(m.hostId!==host.hostId||!pids.has(m.providerId)||mids.has(m.modelId))throw new RepositoryError("ERR_RECONCILE_INPUT");mids.add(m.modelId);}let hostOutcome:UpsertOutcome="ignored_stale",pi=0,pu=0,ps=0,pd=0,mi=0,mu=0,ms=0,md=0;
  return query(()=>{try{this.db.exec("BEGIN IMMEDIATE");hostOutcome=this.hosts.upsert(host);for(const p of providers){const o=this.providers.upsert(p);if(o==="inserted")pi++;else if(o==="updated")pu++;else ps++;}for(const m of models){const o=this.models.upsert(m);if(o==="inserted")mi++;else if(o==="updated")mu++;else ms++;}const oldModels=this.db.prepare("SELECT model_id,provider_id,observed_at FROM models WHERE host_id=?").all(host.hostId) as Array<{model_id:string;provider_id:string;observed_at:string}>;for(const r of oldModels){if(!mids.has(r.model_id)&&r.observed_at<=cutoff){this.db.prepare("DELETE FROM models WHERE model_id=? AND observed_at<=?").run(r.model_id,cutoff);md++;}}const oldProviders=this.db.prepare("SELECT provider_id,observed_at FROM providers WHERE host_id=?").all(host.hostId) as Array<{provider_id:string;observed_at:string}>;for(const r of oldProviders){if(!pids.has(r.provider_id)&&r.observed_at<=cutoff){const newer=this.db.prepare("SELECT 1 FROM models WHERE provider_id=? AND observed_at>? LIMIT 1").get(r.provider_id,cutoff);if(!newer){this.db.prepare("DELETE FROM providers WHERE provider_id=? AND observed_at<=?").run(r.provider_id,cutoff);pd++;}}}this.db.exec("COMMIT");return deepCounts({host:hostOutcome,providersInserted:pi,providersUpdated:pu,providersIgnoredStale:ps,providersDeleted:pd,modelsInserted:mi,modelsUpdated:mu,modelsIgnoredStale:ms,modelsDeleted:md});}catch(e){try{this.db.exec("ROLLBACK");}catch{}if(e instanceof RepositoryError)throw e;return dbFail();}});
 }
}
export function createControllerRepositories(db:DatabaseSync,options:{readonly now?:()=>string}={}):ControllerRepositories{return new ControllerRepositories(db,options.now);}
