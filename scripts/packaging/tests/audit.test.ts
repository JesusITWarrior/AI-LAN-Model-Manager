import test from"node:test";
import assert from"node:assert/strict";
import{readFileSync}from"node:fs";
import{fileURLToPath}from"node:url";
import{resolve}from"node:path";
import{evaluateReleaseAudit,REQUIRED_DOCS,REQUIRED_GATES,REQUIRED_SCRIPT_FILES,REQUIRED_TEST_FILES}from"../audit.js";

const good=()=>({
  dirtyTree:false,
  workflowTexts:["on:\n  workflow_dispatch:\n"],
  presentFiles:[...REQUIRED_DOCS,...REQUIRED_TEST_FILES,...REQUIRED_SCRIPT_FILES],
  publicDocs:["Artifacts are unsigned. Release signing is not operational."],
  gateResults:Object.fromEntries(REQUIRED_GATES.map(k=>[k,true])),
});

test("complete source and gate evidence passes",()=>assert.deepEqual(evaluateReleaseAudit(good()),{ok:true,failures:[]}));

test("release mode rejects dirty source",()=>{
  const result=evaluateReleaseAudit({...good(),dirtyTree:true});
  assert.equal(result.ok,false);
  assert.ok(result.failures.some(f=>f.error==="ERR_DIRTY_TREE"));
  assert.equal(evaluateReleaseAudit({...good(),dirtyTree:true,allowDirty:true}).ok,true);
});

test("automatic or absent workflow triggers fail closed",()=>{
  for(const text of["on:\n  push:\n","on:\n  pull_request:\n","on:\n  schedule:\n","on:\n  workflow_call:\n",""]) {
    assert.ok(evaluateReleaseAudit({...good(),workflowTexts:[text]}).failures.some(f=>f.error==="ERR_WORKFLOW_POLICY"));
  }
});

test("every required document test and script is mandatory",()=>{
  for(const [list,error]of[[REQUIRED_DOCS,"ERR_REQUIRED_DOCUMENT"],[REQUIRED_TEST_FILES,"ERR_REQUIRED_TEST"],[REQUIRED_SCRIPT_FILES,"ERR_REQUIRED_SCRIPT"]]as const){
    const present=good().presentFiles.filter(name=>name!==list[0]);
    assert.ok(evaluateReleaseAudit({...good(),presentFiles:present}).failures.some(f=>f.error===error));
  }
});

test("every underlying release gate must have positive evidence",()=>{
  for(const gate of REQUIRED_GATES){
    const results={...good().gateResults,[gate]:false};
    assert.ok(evaluateReleaseAudit({...good(),gateResults:results}).failures.some(f=>f.error==="ERR_REQUIRED_GATE"));
  }
});

test("public docs cannot claim unsigned artifacts are signed",()=>{
  for(const text of["Release artifacts are signed.","The package is cryptographically signed."]){
    assert.ok(evaluateReleaseAudit({...good(),publicDocs:[text]}).failures.some(f=>f.error==="ERR_UNSIGNED_SIGNING_CLAIM"));
  }
  for(const text of["Artifacts are unsigned.","Release packages are not signed.","Signing is planned but not operational."]){
    assert.equal(evaluateReleaseAudit({...good(),publicDocs:[text]}).ok,true);
  }
});

// ---- Owner-evidence documentation regression ----

const DOC_BASE=resolve(fileURLToPath(import.meta.url),"..","..","..","..");
function doc(name:string):string{return readFileSync(resolve(DOC_BASE,name),"utf8");}
const operatorDoc=doc("docs/operations/operator-console.md");
const architectureDoc=doc("docs/architecture.md");
const threatDoc=doc("docs/threat-model.md");

function mustContain(what:string[],hay:string[],label:string):void{
  for(const marker of what){
    assert.ok(hay.some(text=>text.includes(marker)),`${label}: expected content missing: "${marker}"`);
  }
}
function mustNotContain(what:string[],hay:string[],label:string):void{
  for(const forbidden of what){
    assert.ok(!hay.some(text=>text.includes(forbidden)),`${label}: unexpected misleading content present: "${forbidden}"`);
  }
}

test("operator-console documents the owner-evidence workflow",()=>{
  mustContain([
    "Owner-provided unsigned evidence; source not independently proven",
    "separate explicit",
    "stored",
    "already_stored",
    "conflict",
    "stale",
    "denied",
    "transaction_unknown",
    "committed_unsettled",
    "fresh explicit re-intake",
    "never executes or retries",
    "ACKs a command",
    "releases a hold",
  ],[operatorDoc],"operator-console.md");
  // Defect 1 correction: persisted `stored` writes one append-only row to
  // supplemental_native_evidence plus a matching supplemental_native_evidence_audit
  // event, and leaves jobs/history/commands/replay/holds unchanged.
  mustContain(
    ["persists one append-only row to `supplemental_native_evidence`",
     "does **not** modify jobs, history, commands, replay, or holds"],
    [operatorDoc],
    "operator-console.md stored semantics"
  );
  // Defect 1 negative: `stored` is never described as a read-only append.
  mustNotContain(
    ["read-only append"],
    [operatorDoc],
    "operator-console.md must not call stored a read-only append"
  );
});

test("architecture documents the owner-evidence lane boundaries",()=>{
  mustContain([
    "Owner-provided unsigned evidence",
    "volatile owner/session/credential-bound candidate registry",
    "same-transaction",
    "append-only row",
    "queue remains authoritative input and is left unchanged",
    "audit event",
    "native ACK",
    "hold release",
  ],[architectureDoc],"architecture.md");
  // Defect 2 negative: the transaction must not be described as appending only the
  // stored queue; the queue is authoritative input and stays unchanged.
  mustNotContain(
    ["append-only of the stored queue", "append-only of the queue"],
    [architectureDoc],
    "architecture.md must not claim append-only of the stored queue"
  );
});

test("threat model documents owner evidence as untrusted ingress",()=>{
  mustContain([
    "Owner evidence bytes are untrusted ingress",
    "strict UTF-8/JSON/duplicate-key/shape/cap",
    "same-origin session",
    "append-only",
    "audit commit",
    "may be false or benign",
    "remote possession",
    "fresh mTLS",
    "does **not** attest",
  ],[threatDoc],"threat-model.md");
  // Defect 3 negative: prepare must not claim the lane attests provenance/truthfulness.
  mustNotContain(
    ["attests provenance at prepare time"],
    [threatDoc],
    "threat-model.md must not claim the lane attests provenance at prepare time"
  );
});
