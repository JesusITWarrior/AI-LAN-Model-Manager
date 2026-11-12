import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync,rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { constants as sqliteConstants,DatabaseSync } from "node:sqlite";
import { clearSessionCookie,parseSessionCookieHeader,serializeSessionCookie } from "./cookie-parser.js";
import { CONTROLLER_MIGRATIONS,migrateControllerDatabase,openControllerDatabase } from "./database.js";
import { guardManagementRequest } from "./guard.js";
import { createJobStores } from "./jobs-store.js";
import { createAllowedOrigins,originAllowed } from "./origin.js";
import { createOwnerBootstrapService } from "./owner-service.js";
import { SessionManager } from "./session-manager.js";
import type { PasswordCryptoEngine } from "./credentials.js";

const START="2026-09-27T10:00:00.000Z";
const cryptoEngine=():PasswordCryptoEngine=>({random:size=>Buffer.alloc(size,3),async derive(password,salt,p){const seed=createHash("sha256").update(password).update(salt).digest();return Buffer.alloc(p.keyLength,seed[0]);},equal:(a,b)=>Buffer.from(a).equals(Buffer.from(b))});
async function setup(db=openControllerDatabase(":memory:")){let now=START,counter=0;const owners=createOwnerBootstrapService(db,{now:()=>now,ownerId:()=>"a".repeat(32),crypto:cryptoEngine()});await owners.bootstrapOwner({username:"Admin",password:"owner-password-123"});const manager=new SessionManager(db,owners,{clock:()=>now,random:size=>Buffer.alloc(size,++counter),policy:{absoluteTtlMs:3_600_000,idleTtlMs:600_000,touchAfterMs:60_000}});return{db,owners,manager,setNow:(value:string)=>{now=value;}};}

test("migration3 upgrades to session migration4 with revocable rows",()=>{const dir=mkdtempSync(join(tmpdir(),"lanmm-session-upgrade-"));try{const path=join(dir,"db.sqlite3");let db=new DatabaseSync(path);migrateControllerDatabase(db,CONTROLLER_MIGRATIONS.slice(0,3));db.close();db=openControllerDatabase(path);assert.equal((db.prepare("PRAGMA user_version").get() as any).user_version,CONTROLLER_MIGRATIONS.length);const columns=(db.prepare("PRAGMA table_info(sessions)").all() as Array<{name:string}>).map(row=>row.name);assert.deepEqual(columns,["session_digest","csrf_digest","owner_id","credential_version","session_version","created_at","last_seen_at","absolute_expires_at","idle_expires_at","revoked_at"]);db.close();}finally{rmSync(dir,{recursive:true,force:true});}});

test("session creation returns unique raw tokens once and stores digests only",async()=>{const{db,manager}=await setup();try{const first=await manager.create({username:"admin",password:"owner-password-123"}),second=await manager.create({username:"admin",password:"owner-password-123"});assert.ok(first&&second);assert.notEqual(first.sessionToken,second.sessionToken);assert.notEqual(first.csrfToken,second.csrfToken);assert.ok(Object.isFrozen(first)&&Object.isFrozen(first.metadata));const json=JSON.stringify(db.prepare("SELECT * FROM sessions ORDER BY session_digest").all());for(const token of [first.sessionToken,first.csrfToken,second.sessionToken,second.csrfToken])assert.equal(json.includes(token),false);}finally{db.close();}});

test("session authentication and CSRF binding reject malformed and crossed tokens",async()=>{const{db,manager}=await setup();try{const first=await manager.create({username:"admin",password:"owner-password-123"}),second=await manager.create({username:"admin",password:"owner-password-123"});assert.ok(first&&second);assert.equal(manager.authenticate(first.sessionToken)?.ownerId,"a".repeat(32));assert.equal(manager.authenticateCsrf(first.sessionToken,first.csrfToken)?.ownerId,"a".repeat(32));assert.equal(manager.authenticateCsrf(first.sessionToken,second.csrfToken),null);for(const bad of ["",first.sessionToken+"x","../token",null])assert.equal(manager.authenticate(bad),null);}finally{db.close();}});

test("absolute and idle expiry are strict at the boundary",async()=>{const{db,manager,setNow}=await setup();try{const session=await manager.create({username:"admin",password:"owner-password-123"});assert.ok(session);setNow("2026-09-27T10:09:59.999Z");assert.ok(manager.authenticate(session.sessionToken));setNow("2026-09-27T10:10:00.000Z");assert.equal(manager.authenticate(session.sessionToken),null);const next=await manager.create({username:"admin",password:"owner-password-123"});assert.ok(next);setNow("2026-09-27T11:10:00.000Z");assert.equal(manager.authenticate(next.sessionToken),null);}finally{db.close();}});

test("touch extends idle only up to absolute expiry and stale/revoked sessions cannot revive",async()=>{const{db,manager,setNow}=await setup();try{const session=await manager.create({username:"admin",password:"owner-password-123"});assert.ok(session);setNow("2026-09-27T10:05:00.000Z");const touched=manager.touch(session.sessionToken);assert.equal(touched?.idleExpiresAt,"2026-09-27T10:15:00.000Z");assert.ok(manager.revoke(session.sessionToken));setNow("2026-09-27T10:06:00.000Z");assert.equal(manager.touch(session.sessionToken),null);assert.equal(manager.authenticate(session.sessionToken),null);}finally{db.close();}});

test("owner disablement and credential-version changes invalidate sessions",async()=>{const{db,owners,manager}=await setup();try{const session=await manager.create({username:"admin",password:"owner-password-123"});assert.ok(session);const owner=owners.getOwner()!;db.prepare("UPDATE owners SET credential_version=credential_version+1 WHERE owner_id=?").run(owner.ownerId);assert.equal(manager.authenticate(session.sessionToken),null);const newer=await manager.create({username:"admin",password:"owner-password-123"});assert.ok(newer);db.prepare("UPDATE owners SET disabled=1 WHERE owner_id=?").run(owner.ownerId);assert.equal(manager.authenticate(newer.sessionToken),null);}finally{db.close();}});

test("revoke all is atomic and file restart preserves active sessions",async()=>{const dir=mkdtempSync(join(tmpdir(),"lanmm-session-reopen-"));try{const path=join(dir,"db.sqlite3");let db=openControllerDatabase(path);let context=await setup(db);const one=await context.manager.create({username:"admin",password:"owner-password-123"}),two=await context.manager.create({username:"admin",password:"owner-password-123"});assert.ok(one&&two);db.close();db=openControllerDatabase(path);const owners=createOwnerBootstrapService(db,{crypto:cryptoEngine()});const manager=new SessionManager(db,owners,{clock:()=>START});assert.ok(manager.authenticate(one.sessionToken));assert.equal(manager.revokeAll(),2);assert.equal(manager.authenticate(one.sessionToken),null);assert.equal(manager.authenticate(two.sessionToken),null);db.close();}finally{rmSync(dir,{recursive:true,force:true});}});

test("cookie parser and serializers enforce the host-only secure policy",async()=>{const{db,manager}=await setup();try{const session=await manager.create({username:"admin",password:"owner-password-123"});assert.ok(session);const setCookie=serializeSessionCookie(session.sessionToken,session.maxAgeSeconds);assert.equal(setCookie,`__Host-lanmm_session=${session.sessionToken}; Max-Age=3600; Path=/; Secure; HttpOnly; SameSite=Strict`);assert.equal(parseSessionCookieHeader(`theme=dark; __Host-lanmm_session=${session.sessionToken}`),session.sessionToken);for(const bad of [`__Host-lanmm_session=${session.sessionToken}; __Host-lanmm_session=${session.sessionToken}`,"broken",`__Host-lanmm_session=${session.sessionToken}\n`,"x=".repeat(3000)])assert.equal(parseSessionCookieHeader(bad),null);assert.equal(clearSessionCookie(),"__Host-lanmm_session=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict");}finally{db.close();}});

test("origin policy is exact and loopback HTTP requires explicit development mode",()=>{const allowed=createAllowedOrigins(["https://manager.example:8443"]);assert.equal(originAllowed("https://manager.example:8443",allowed),true);for(const bad of [null,"null","http://manager.example:8443","https://sub.manager.example:8443","https://manager.example","https://user@manager.example:8443","https://manager.example:8443/path","https://manager.example:8443?x=1","https://manager.example:8443, https://evil.example"])assert.equal(originAllowed(bad,allowed),false);assert.throws(()=>createAllowedOrigins(["http://127.0.0.1:7340"]));const dev=createAllowedOrigins(["http://127.0.0.1:7340"],{allowLoopbackHttpDevelopment:true});assert.equal(originAllowed("http://127.0.0.1:7340",dev,{allowLoopbackHttpDevelopment:true}),true);});

test("combined guard authenticates safe methods and enforces exact origin plus header-bound CSRF",async()=>{const{db,manager}=await setup();try{const session=await manager.create({username:"admin",password:"owner-password-123"});assert.ok(session);const origins=createAllowedOrigins(["https://manager.example"]),cookie=`__Host-lanmm_session=${session.sessionToken}`;assert.equal(guardManagementRequest(manager,origins,{method:"GET",cookieHeader:cookie,originHeader:null,csrfHeader:null}).ok,true);assert.deepEqual({...guardManagementRequest(manager,origins,{method:"POST",cookieHeader:"",originHeader:"https://manager.example",csrfHeader:session.csrfToken})},{ok:false,status:401,code:"UNAUTHORIZED"});assert.deepEqual({...guardManagementRequest(manager,origins,{method:"POST",cookieHeader:cookie,originHeader:"https://evil.example",csrfHeader:session.csrfToken})},{ok:false,status:403,code:"FORBIDDEN"});assert.equal(guardManagementRequest(manager,origins,{method:"POST",cookieHeader:cookie,originHeader:"https://manager.example",csrfHeader:null}).ok,false);assert.equal(guardManagementRequest(manager,origins,{method:"POST",cookieHeader:cookie,originHeader:"https://manager.example",csrfHeader:session.csrfToken}).ok,true);}finally{db.close();}});

test("guard request DTO rejects getters, symbols, prototypes, and revoked proxies",async()=>{const{db,manager}=await setup();try{const origins=createAllowedOrigins(["https://manager.example"]);let calls=0;const accessor=Object.defineProperty({cookieHeader:"",originHeader:null,csrfHeader:null},"method",{enumerable:true,get(){calls++;return"GET";}});const revoked=Proxy.revocable({method:"GET",cookieHeader:"",originHeader:null,csrfHeader:null},{});revoked.revoke();for(const bad of [accessor,{method:"GET",cookieHeader:"",originHeader:null,csrfHeader:null,[Symbol("x")]:1},Object.assign(Object.create({}),{method:"GET",cookieHeader:"",originHeader:null,csrfHeader:null}),revoked.proxy])assert.equal(guardManagementRequest(manager,origins,bad).ok,false);assert.equal(calls,0);}finally{db.close();}});

test("private lifecycle session binding is unique, unforgeable from metadata, revocable and expiry bounded",async()=>{
 const {db,manager,setNow}=await setup();try{
  const one=await manager.create({username:"admin",password:"owner-password-123"}),two=await manager.create({username:"admin",password:"owner-password-123"});assert.ok(one&&two);
  assert.equal(one.metadata.sessionVersion,two.metadata.sessionVersion);
  const a=manager.binding(one.metadata),b=manager.binding(two.metadata);assert.ok(a&&b);assert.notEqual(a.id,b.id);assert.equal(a.expiresAt,one.metadata.idleExpiresAt);
  assert.equal(manager.binding({...one.metadata}),null);
  assert.equal(JSON.stringify(one.metadata).includes(a.id),false);
  assert.ok(manager.revoke(one.sessionToken));assert.equal(manager.binding(one.metadata),null);
  setNow(two.metadata.idleExpiresAt);assert.equal(manager.binding(two.metadata),null);
 }finally{db.close();}
});


test("transaction-bound session binding accepts only the live same-connection callback capability",async()=>{
 const {db,owners,manager}=await setup(),otherDb=openControllerDatabase(":memory:");try{
  const session=await manager.create({username:"admin",password:"owner-password-123"});assert.ok(session);
  const stores=createJobStores(db),otherStores=createJobStores(otherDb),before=JSON.stringify({owners:db.prepare("SELECT * FROM owners ORDER BY owner_id").all(),sessions:db.prepare("SELECT * FROM sessions ORDER BY session_digest").all()});
  let captured:unknown,blockedReads=0;
  stores.withAuditTransaction(tx=>{
   captured=tx;
   db.setAuthorizer((action,arg1)=>{if(action===sqliteConstants.SQLITE_READ&&(arg1==="sessions"||arg1==="owners")){blockedReads++;return sqliteConstants.SQLITE_DENY;}return sqliteConstants.SQLITE_OK;});
   try{
    const forged=Object.freeze({jobs:tx.jobs,audit:tx.audit});
    for(const invalid of [{...tx},forged,new Proxy(tx,{}),null])assert.equal(manager.bindingInTransaction(invalid,session.metadata),null);
    otherStores.withAuditTransaction(foreignTx=>assert.equal(manager.bindingInTransaction(foreignTx,session.metadata),null));
    assert.equal(blockedReads,0,"invalid transaction contexts must be rejected before session or owner reads");
   }finally{db.setAuthorizer(null);}
   const binding=manager.bindingInTransaction(tx,session.metadata);assert.ok(binding);assert.equal(Object.isFrozen(binding),true);assert.deepEqual(Object.keys(binding).sort(),["credentialVersion","expiresAt","id"]);assert.equal(JSON.stringify(binding).includes(session.sessionToken),false);assert.equal(JSON.stringify(binding).includes(session.csrfToken),false);
   assert.equal(manager.bindingInTransaction(tx,{...session.metadata}),null);
   const otherManager=new SessionManager(db,owners,{clock:()=>START});assert.equal(otherManager.bindingInTransaction(tx,session.metadata),null);
  });
  db.setAuthorizer((action,arg1)=>{if(action===sqliteConstants.SQLITE_READ&&(arg1==="sessions"||arg1==="owners")){blockedReads++;return sqliteConstants.SQLITE_DENY;}return sqliteConstants.SQLITE_OK;});
  try{assert.equal(manager.bindingInTransaction(captured,session.metadata),null);assert.equal(blockedReads,0,"expired callback context must be rejected before session reads");}finally{db.setAuthorizer(null);}
  assert.equal(JSON.stringify({owners:db.prepare("SELECT * FROM owners ORDER BY owner_id").all(),sessions:db.prepare("SELECT * FROM sessions ORDER BY session_digest").all()}),before,"binding revalidation is read-only");
 }finally{db.close();otherDb.close();}
});

test("transaction-bound session binding rechecks revocation, owner state, versions, and both expiries",async()=>{
 const {db,owners,manager,setNow}=await setup();try{
  const session=await manager.create({username:"admin",password:"owner-password-123"});assert.ok(session);const stores=createJobStores(db);
  const binding=()=>{const result:Array<ReturnType<SessionManager["bindingInTransaction"]>>=[];stores.withAuditTransaction(tx=>result.push(manager.bindingInTransaction(tx,session.metadata)));return result[0]??null;};
  assert.ok(binding());
  const ownerId=owners.getOwner()!.ownerId;
  db.prepare("UPDATE owners SET credential_version=credential_version+1 WHERE owner_id=?").run(ownerId);assert.equal(binding(),null);db.prepare("UPDATE owners SET credential_version=credential_version-1 WHERE owner_id=?").run(ownerId);
  db.prepare("UPDATE owners SET disabled=1 WHERE owner_id=?").run(ownerId);assert.equal(binding(),null);db.prepare("UPDATE owners SET disabled=0 WHERE owner_id=?").run(ownerId);
  db.prepare("UPDATE sessions SET session_version=session_version+1").run();assert.equal(binding(),null);db.prepare("UPDATE sessions SET session_version=session_version-1").run();
  db.prepare("UPDATE sessions SET revoked_at=?").run("2026-09-27T10:01:00.000Z");assert.equal(binding(),null);db.prepare("UPDATE sessions SET revoked_at=NULL").run();
  setNow(session.metadata.idleExpiresAt);assert.equal(binding(),null);setNow(START);
  db.prepare("UPDATE sessions SET idle_expires_at=?").run("2026-09-27T12:00:00.000Z");setNow(session.metadata.absoluteExpiresAt);assert.equal(binding(),null);
 }finally{db.close();}
});
