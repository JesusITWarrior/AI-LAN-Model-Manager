import test from "node:test";
import assert from "node:assert/strict";
const {browserController}=await import(new URL("../../web/test-support/lifecycle-controller.ts",import.meta.url).href);
test("real HTTP constrained settings require owner origin CSRF, reject unknowns, CAS and stale prepared proposal",{timeout:30_000},async()=>{
 const fixture=await browserController();try{
 const get=()=>fetch(fixture.base+"/api/v1/policy/settings",{headers:fixture.headers});const initial=await get();assert.equal(initial.status,200);const settings=(await initial.json() as any).value;assert.equal(settings.noPromptEnabled,false);assert.deepEqual(settings.allowedOperations,["observe","provider-status","model-status"]);
 const update={expectedVersion:settings.version,allowedOperations:[...settings.allowedOperations,"model-load"],approvalOperations:["model-load"],hardLimits:settings.hardLimits};const path="/api/v1/policy/settings";
 assert.equal((await fixture.post(path,update)).status,401);
 assert.equal((await fixture.post(path,update,{cookie:fixture.headers.cookie})).status,403);
 assert.equal((await fixture.post(path,update,{...fixture.headers,origin:"https://evil.test"})).status,403);
 for(const body of [{...update,version:99},{...update,allowPublicExposure:true},{...update,expectedVersion:null},{...update,allowedOperations:["model-load","model-load"]},{...update,approvalOperations:["model-unload"]},{...update,hardLimits:{...update.hardLimits,maxOperationsPerMinute:0}},...[-1,Number.MAX_SAFE_INTEGER+1,null].map(n=>({...update,hardLimits:{...update.hardLimits,minimumMemoryHeadroomBytes:n}}))])assert.equal((await fixture.post(path,body,fixture.headers)).status,400);
 assert.equal((await fixture.post(path,update,fixture.headers)).status,200);assert.equal((await fixture.post(path,update,fixture.headers)).status,409);
 const prepared=await fixture.post("/api/v1/lifecycle/proposals/prepare",{operation:"load",modelId:"model-1"},fixture.headers);assert.equal(prepared.status,200);const proposal=(await prepared.json() as any).value;
 assert.equal((await fixture.post(path,{...update,expectedVersion:2},fixture.headers)).status,200);
 const stale=await fixture.post("/api/v1/lifecycle/proposals/approve",{proposalId:proposal.proposalId},fixture.headers);assert.equal(stale.status,200);const staleText=await stale.text();assert.equal(JSON.parse(staleText).value.state,"stale");assert.doesNotMatch(staleText,/snapshot|cookie|secret|canonical_json|policy_hash/);
 assert.equal(fixture.jobs(),0);
 }finally{await fixture.close();}
});

test("two real owner sessions cannot clear unseen prompts through stale enable or disable",{timeout:30_000},async()=>{
 const fixture=await browserController();try{
  const login=await fixture.post("/auth/v1/login",{username:"Owner",password:"synthetic-password-for-http-tests"});assert.equal(login.status,200);const second={cookie:login.headers.get("set-cookie")!.split(";",1)[0]!,"x-csrf-token":(await login.json() as any).value.csrfToken};assert.notEqual(second.cookie,fixture.headers.cookie);
  const get=async(headers=fixture.headers)=>(await (await fetch(fixture.base+"/api/v1/policy/settings",{headers})).json() as any).value;
  const defaults=await get();const path="/api/v1/policy/settings",convenience="/api/v1/policy/convenience";
  assert.equal((await fixture.post(path,{expectedVersion:1,allowedOperations:[...defaults.allowedOperations,"model-load"],approvalOperations:["model-load"],hardLimits:defaults.hardLimits},fixture.headers)).status,200);
  const reviewed=await get();assert.equal(reviewed.version,2);
  assert.equal((await fixture.post(path,{expectedVersion:2,allowedOperations:[...reviewed.allowedOperations,"model-unload"],approvalOperations:["model-load","model-unload"],hardLimits:reviewed.hardLimits},second)).status,200);
  const latest=await get();const audit=async()=>await (await fetch(fixture.base+"/api/v1/audit?limit=200",{headers:fixture.headers})).text();const before=await audit();
  for(const body of [{enabled:true},{enabled:true,expectedVersion:null},{enabled:true,expectedVersion:2,extra:true}])assert.equal((await fixture.post(convenience,body,fixture.headers)).status,400);
  for(const enabled of [true,false]){assert.equal((await fixture.post(convenience,{enabled,expectedVersion:2},fixture.headers)).status,409);assert.deepEqual(await get(),latest);assert.equal(await audit(),before);}
  assert.equal((await fixture.post(convenience,{enabled:true,expectedVersion:3},fixture.headers)).status,200);const enabled=await get();assert.equal(enabled.version,4);assert.deepEqual(enabled.allowedOperations,latest.allowedOperations);assert.deepEqual(enabled.hardLimits,latest.hardLimits);assert.deepEqual(enabled.approvalOperations,[]);
  assert.equal((await fixture.post(convenience,{enabled:false,expectedVersion:4},second)).status,200);assert.deepEqual((await get()).approvalOperations,["model-load","model-unload"]);assert.equal(fixture.jobs(),0);
 }finally{await fixture.close();}
});
