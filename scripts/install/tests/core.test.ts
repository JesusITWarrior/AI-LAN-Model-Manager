import test from "node:test";
import assert from "node:assert/strict";
import {mkdtemp, mkdir, readFile, writeFile, access, symlink} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {fileURLToPath} from "node:url";
import {spawnSync} from "node:child_process";
import {compareVersions,safeVersion,contained,createManifest,installPlan,installRelease,inventoryTree,safeRelative,uninstall,verifyManifest} from "../core.js";

const COMMIT="9f9f243e76991e4fd5e8365001f2074bdfe44ffd";
async function payload(root:string,version:string,body:string,role="agent"){const dir=join(root,`payload-${version}`);await mkdir(join(dir,"bin"),{recursive:true});await writeFile(join(dir,"bin",role==="agent"?"lan-model-agent":"lan-model-controller"),body,{mode:0o755});const files=await inventoryTree(dir);return{dir,manifest:createManifest({role,version,files,sourceCommit:COMMIT})};}
async function present(path:string){try{await access(path);return true}catch{return false}}

test("containment accepts descendants of a filesystem root without double separators",()=>{assert.equal(contained("/","/Program Files/LANModelManager"),true);assert.equal(contained("/","/../escape"),true);assert.equal(contained("/safe","/unsafe"),false);});

test("dry-run validates bytes and reports canonical rootless plan without mutation",async()=>{const root=await mkdtemp(join(tmpdir(),"lmm-install-")),p=await payload(root,"1.0.0","v1");const result=await installRelease({payload:p.dir,manifest:p.manifest,platform:"linux",root,dryRun:true});assert.equal(result.changed,false);assert.match(result.actions[1]!,/releases[\\/]agent[\\/]1\.0\.0$/);assert.equal(await present(join(root,"opt")),false);});

test("upgrade stages side-by-side, rolls back failed health, and preserves state",async()=>{const root=await mkdtemp(join(tmpdir(),"lmm-upgrade-")),v1=await payload(root,"1.0.0","v1"),v2=await payload(root,"1.1.0","v2"),restarts:string[]=[];await installRelease({payload:v1.dir,manifest:v1.manifest,platform:"linux",root,healthCheck:async()=>true});const plan=installPlan({platform:"linux",root,role:"agent",version:"1.0.0"});await writeFile(join(plan.state,"enrollment.key"),"keep-secret",{mode:0o600});const failed=await installRelease({payload:v2.dir,manifest:v2.manifest,platform:"linux",root,restart:async x=>{restarts.push(`${x.version}:${Boolean(x.rollback)}`)},healthCheck:async()=>false});assert.equal(failed.rolledBack,true);assert.equal((await readFile(plan.pointer,"utf8")).trim(),"1.0.0");assert.equal(await readFile(join(plan.state,"enrollment.key"),"utf8"),"keep-secret");assert.equal(await readFile(join(plan.layout.releaseRoot,"agent","1.1.0","bin","lan-model-agent"),"utf8"),"v2");assert.deepEqual(restarts,["1.1.0:false","1.0.0:true"]);});

test("Windows upgrade rolls back the pointer and preserves enrollment state",async()=>{const root=await mkdtemp(join(tmpdir(),"lmm-win-upgrade-")),v1=await payload(root,"1.0.0","v1"),v2=await payload(root,"1.1.0","v2");await installRelease({payload:v1.dir,manifest:v1.manifest,platform:"windows",root});const plan=installPlan({platform:"windows",root,role:"agent",version:"1.0.0"});await writeFile(join(plan.state,"enrollment.key"),"keep");const result=await installRelease({payload:v2.dir,manifest:v2.manifest,platform:"windows",root,healthCheck:async()=>false});assert.equal(result.rolledBack,true);assert.equal((await readFile(plan.pointer,"utf8")).trim(),"1.0.0");assert.equal(await readFile(join(plan.state,"enrollment.key"),"utf8"),"keep");});

test("successful switch and uninstall preserve data unless purge is explicit",async()=>{const root=await mkdtemp(join(tmpdir(),"lmm-uninstall-")),v1=await payload(root,"2.0.0","ok");await installRelease({payload:v1.dir,manifest:v1.manifest,platform:"linux",root});const plan=installPlan({platform:"linux",root,role:"agent",version:"2.0.0"});await writeFile(join(plan.state,"identity.crt"),"certificate");const kept=await uninstall({platform:"linux",root,role:"agent"});assert.deepEqual(kept.preserved,[plan.state,plan.config]);assert.equal(await readFile(join(plan.state,"identity.crt"),"utf8"),"certificate");await uninstall({platform:"linux",root,role:"agent",purge:true});assert.equal(await present(plan.state),false);});

test("repeat install is idempotent and downgrade is denied",async()=>{const root=await mkdtemp(join(tmpdir(),"lmm-idempotent-")),v2=await payload(root,"2.0.0","v2"),v1=await payload(root,"1.9.0","v1");await installRelease({payload:v2.dir,manifest:v2.manifest,platform:"linux",root});const same=await installRelease({payload:v2.dir,manifest:v2.manifest,platform:"linux",root});assert.equal(same.changed,false);assert.deepEqual(same.actions.slice(-1),["noop:same-version"]);await assert.rejects(installRelease({payload:v1.dir,manifest:v1.manifest,platform:"linux",root}),/ERR_INSTALL_DOWNGRADE/);});

test("pre-existing symlink ancestors cannot redirect privileged writes",async()=>{const root=await mkdtemp(join(tmpdir(),"lmm-link-root-")),outside=await mkdtemp(join(tmpdir(),"lmm-link-out-")),p=await payload(root,"1.0.0","good");await mkdir(join(root,"opt"),{recursive:true});await symlink(outside,join(root,"opt","lan-model-manager"),process.platform==="win32"?"junction":"dir");await assert.rejects(installRelease({payload:p.dir,manifest:p.manifest,platform:"linux",root}),/ERR_INSTALL_SYMLINK/);assert.equal(await present(join(outside,"releases")),false);});

test("checksum, provenance, traversal, and unbounded inputs fail closed",async()=>{const root=await mkdtemp(join(tmpdir(),"lmm-invalid-")),p=await payload(root,"1.0.0","good");await writeFile(join(p.dir,"bin","lan-model-agent"),"tampered");await assert.rejects(installRelease({payload:p.dir,manifest:p.manifest,platform:"linux",root}),/ERR_INSTALL_CHECKSUM/);assert.throws(()=>safeRelative("../escape"),/ERR_INSTALL_PATH/);assert.throws(()=>verifyManifest({...p.manifest,files:[...p.manifest.files,{...p.manifest.files[0],path:"bin/other"}]}),/ERR_INSTALL_PROVENANCE/);assert.throws(()=>installPlan({platform:"linux",root,role:"agent",version:"x"}),/ERR_INSTALL_VERSION/);});

test("Windows service environments are deterministic and strictly role-bound",async()=>{const expected={controller:["LANMM_DATA_DIR=%ProgramData%\\LANModelManager\\state\\controller"],agent:["LANMM_STATE_DIR=%ProgramData%\\LANModelManager\\state\\agent","LANMM_CERT_DIR=%ProgramData%\\LANModelManager\\state\\agent\\cert","LANMM_CACHE_DIR=%ProgramData%\\LANModelManager\\state\\agent\\cache"]};for(const role of ["controller","agent"] as const){const root=await mkdtemp(join(tmpdir(),`lmm-win-${role}-`)),p=await payload(root,"3.1.0",role,role);await installRelease({payload:p.dir,manifest:p.manifest,platform:"windows",root});const plan=installPlan({platform:"windows",root,role,version:"3.1.0"}),descriptor=JSON.parse(await readFile(plan.serviceFiles[0]!,"utf8"));assert.deepEqual(descriptor.environment,expected[role]);assert.equal(descriptor.environment.some((entry:string)=>role==="controller"?/^LANMM_(?:STATE|CERT|CACHE)_DIR=/.test(entry):/^LANMM_DATA_DIR=/.test(entry)),false);}const template=JSON.parse(await readFile(new URL("../templates/windows/service-descriptor.json",import.meta.url),"utf8"));assert.deepEqual(template.environments,expected);const ps=await readFile(new URL("../templates/windows/Install-LANModelService.ps1",import.meta.url),"utf8");assert.match(ps,/LANMM_STATE_DIR=\$state/);assert.match(ps,/LANMM_ENROLLMENT_CONTROLLER_URL=\$ControllerUrl/);assert.match(ps,/LANMM_ENROLLMENT_CA_CERT_FILE=\$caTarget/);assert.match(ps,/LANMM_ENROLLMENT_CA_FINGERPRINT_SHA256=\$CaFingerprint/);assert.match(ps,/LANMM_DISCOVERY_ADDRESS=\$CandidateAddress/);assert.match(ps,/LANMM_OLLAMA_ENDPOINT=http:\/\/127\.0\.0\.1:11434/);assert.match(ps,/Copy-Item -LiteralPath \$CaCertificatePath/);assert.match(ps,/-Value \$serviceEnvironment/);assert.match(ps,/Test-CanonicalIPv4/);assert.match(ps,/Test-PrivateIPv4/);assert.match(ps,/function Assert-SafePath/);assert.match(ps,/FileAttributes\]::ReparsePoint/);assert.match(ps,/ERR_INSTALL_SERVICE_OWNERSHIP/);assert.match(ps,/\$oldCim\.StartName-ine\$expectedAccount/);assert.match(ps,/\$oldCim\.PathName-cnotmatch\$releasePattern/);assert.match(ps,/\$oldEnvironment/);assert.match(ps,/\$oldCa/);assert.match(ps,/if\(\$createdService\)\{& sc\.exe delete/);assert.match(ps,/ERR_UPGRADE_ROLLBACK/);assert.match(ps,/ERR_INSTALL_ROLLBACK_FAILED/);assert.match(ps,/\$createdDirectories=New-Object Collections\.Generic\.List\[string\]/);assert.match(ps,/\$oldDirectoryAcls\[\$path\]=Get-Acl -LiteralPath \$path/);assert.match(ps,/Set-Acl -LiteralPath \$entry\.Key -AclObject \$entry\.Value -ErrorAction Stop/);assert.match(ps,/Get-ChildItem -LiteralPath \$path -Force -ErrorAction Stop/);assert.match(ps,/Remove-Item -LiteralPath \$path -Force -ErrorAction Stop/);assert.ok(ps.indexOf("$oldDirectoryAcls[$path]=Get-Acl")<ps.indexOf("& icacls.exe $path"));assert.ok(ps.indexOf("if($Role-eq'agent'){try{if($hadCa)")<ps.indexOf("foreach($entry in $oldDirectoryAcls.GetEnumerator())"));assert.ok(ps.indexOf("foreach($entry in $oldDirectoryAcls.GetEnumerator())")<ps.lastIndexOf("Start-Service -Name $name -ErrorAction Stop"));const agent=await readFile(new URL("../templates/windows/Install-LANModelAgent.ps1",import.meta.url),"utf8");assert.match(agent,/\$oldPointer/);assert.match(agent,/Move-Item -LiteralPath \$temp -Destination \$pointer -Force/);assert.match(agent,/ERR_INSTALL_TRANSACTION/);assert.match(agent,/function Assert-SafePath/);assert.match(agent,/Assert-SafePath \$pointer -AllowLeafFile/);assert.match(agent,/ERR_INSTALL_ROLLBACK_FAILED/);assert.match(agent,/-ReEnroll/);assert.match(agent,/\$directorySnapshots=@\(\)/);assert.match(agent,/Acl=\$acl/);assert.match(agent,/Set-Acl -LiteralPath \$snapshot\.Path -AclObject \$snapshot\.Acl -ErrorAction Stop/);assert.match(agent,/Remove-Item -LiteralPath \$snapshot\.Path -Recurse -Force -ErrorAction Stop/);assert.ok(agent.indexOf('$directorySnapshots=@()')<agent.indexOf('&$node @args'));assert.match(agent,/try\{\s*&\$node @args;if\(\$LASTEXITCODE-ne 0\)\{throw 'ERR_INSTALL_STAGE'\}\s*&powershell\.exe @serviceArgs/);});

test("Windows package exposes matched PowerShell 5.1 install and uninstall entrypoints",async()=>{const cli=await readFile(new URL("../cli.js",import.meta.url),"utf8"),installer=await readFile(new URL("../templates/windows/Install-LANModelAgent.ps1",import.meta.url),"utf8"),uninstaller=await readFile(new URL("../templates/windows/Uninstall-LANModelAgent.ps1",import.meta.url),"utf8"),service=await readFile(new URL("../templates/windows/Install-LANModelService.ps1",import.meta.url),"utf8");for(const source of[installer,uninstaller,service])assert.match(source,/#Requires -Version 5\.1/);assert.match(cli,/root=args\.root\?\?"\/"/);assert.match(installer,/cli\.js/);assert.match(installer,/Install-LANModelService\.ps1/);assert.match(installer,/--dry-run/);assert.match(uninstaller,/preserving enrollment state and configuration/);assert.match(uninstaller,/if\(\$Purge\)/);assert.match(uninstaller,/--purge/);assert.match(uninstaller,/--dry-run/);assert.doesNotMatch(installer+uninstaller,/['"]--root['"]/);assert.doesNotMatch(installer+uninstaller,/firewall|New-NetFirewallRule/i);});
test("Linux definitions are disabled until explicitly enabled and Windows uses virtual accounts",async()=>{for(const platform of ["linux","windows"] as const){const root=await mkdtemp(join(tmpdir(),`lmm-${platform}-`)),p=await payload(root,"3.0.0","binary");await installRelease({payload:p.dir,manifest:p.manifest,platform,root});const plan=installPlan({platform,root,role:"agent",version:"3.0.0"});if(platform==="linux"){const unit=await readFile(plan.serviceFiles[0]!,"utf8");assert.match(unit,/User=lanmodel-agent/);assert.match(unit,/NoNewPrivileges=yes/);assert.match(unit,/LANMM_STATE_DIR=/);assert.doesNotMatch(unit,/systemctl|enable --now/);}else{const descriptor=JSON.parse(await readFile(plan.serviceFiles[0]!,"utf8"));assert.equal(descriptor.account,"NT SERVICE\\LANModelAgent");assert.equal(descriptor.startup,"disabled");assert.equal(descriptor.firewallChanges,false);}}const ps=await readFile(new URL("../templates/windows/Install-LANModelService.ps1",import.meta.url),"utf8");assert.match(ps,/if\(-not \$WhatIfPreference -and -not \(Test-Path/);assert.ok(ps.indexOf("if($Action -eq 'Uninstall')")<ps.indexOf("$serviceEnvironment=if($Role -eq 'agent')"));assert.match(ps,/StartupType Disabled/);assert.match(ps,/if\(\$Activate/);assert.match(ps,/ERR_UPGRADE_ROLLBACK/);assert.match(ps,/ValidateSet\('controller','agent'\)/);});


test("Windows service paths use typed CIM and fail closed before activation",async()=>{
  const ps=await readFile(new URL("../templates/windows/Install-LANModelService.ps1",import.meta.url),"utf8");
  assert.doesNotMatch(ps,/sc\.exe[^\r\n]*binPath=/i);
  assert.match(ps,/Invoke-CimMethod -InputObject \$service -MethodName Change -Arguments @\{PathName=\$Path;StartMode=\$StartMode;StartName=\$Account\}/);
  assert.match(ps,/\$null-eq\$result\.ReturnValue-or\$result\.ReturnValue-ne 0/);
  assert.match(ps,/\$actual\.PathName-cne\$Path/);
  assert.match(ps,/\$actual\.StartName-ine\$Account/);
  assert.match(ps,/\$actual\.StartMode-ine\$expectedMode/);
  assert.match(ps,/Assert-ServiceConfiguration \$Name \$Path \$StartMode \$Account/);
  assert.match(ps,/try\{Set-ServiceConfiguration \$name \$oldCim\.PathName \$start \$oldCim\.StartName\}catch\{\$rollbackFailed=\$true\}/);
  assert.match(ps,/Assert-ServiceConfiguration \$name \('"\{0\}"'-f\$binary\) 'Manual' "NT SERVICE\\\$name";Start-Service/);
  assert.equal((ps.match(/Set-ServiceConfiguration \$name \('"\{0\}"'-f\$binary\) 'Disabled'/g)??[]).length,2,"create and upgrade must both verify the quoted path");
});

test("Windows native service configuration fixture (mock CIM; no live changes)",{skip:process.platform!=="win32"},()=>{
  const fixture=fileURLToPath(new URL("./windows-service-config.ps1",import.meta.url));
  const result=spawnSync("powershell.exe",["-NoProfile","-NonInteractive","-File",fixture],{encoding:"utf8",timeout:15000});
  assert.equal(result.error,undefined);
  assert.equal(result.status,0,result.stdout+result.stderr);
  assert.match(result.stdout,/PASS typed service configuration/);
});


test("version precedence follows SemVer identifiers without truncation or numeric overflow",()=>{
  const chain=["1.0.0-alpha","1.0.0-alpha.1","1.0.0-alpha.beta","1.0.0-beta","1.0.0-beta.2","1.0.0-beta.11","1.0.0-rc.1","1.0.0"];
  for(let i=0;i<chain.length;i++)for(let j=0;j<chain.length;j++)assert.equal(compareVersions(chain[i],chain[j]),Math.sign(i-j),`${chain[i]} vs ${chain[j]}`);
  const pairs=[
    ["0.1.0-alpha.8","0.1.0-alpha.10"],
    ["1.0.0-alpha-1","1.0.0-alpha-2"],
    ["1.0.0-alpha-1.8","1.0.0-alpha-1.10"],
    ["1.0.0-9","1.0.0-A"],["1.0.0-Z","1.0.0-a"],
    ["9007199254740992.0.0","9007199254740993.0.0"],
    ["1.9007199254740992.0","1.9007199254740993.0"],
    ["1.0.9007199254740992","1.0.9007199254740993"],
    ["1.0.0-9007199254740992","1.0.0-9007199254740993"],
    ["1.0.0-"+"9".repeat(119),"1.0.0-1"+"0".repeat(120)],
    ["1.2.3","1.2.4"],["1.2.99","1.3.0"],["1.99.99","2.0.0"]
  ];
  for(const [a,b] of pairs){assert.equal(compareVersions(a,b),-1,`${a} < ${b}`);assert.equal(compareVersions(b,a),1);assert.equal(compareVersions(a,a),0);assert.equal(compareVersions(b,b),0);}
  // Historical path-safe spellings remain accepted, with numeric components
  // compared by value; build metadata and unsafe/unbounded paths stay rejected.
  for(const version of ["01.002.0003-alpha.01","1.0.0-a-1","1.0.0-.","1.0.0-a."])assert.equal(safeVersion(version),version);
  assert.equal(compareVersions("01.002.0003-alpha.01","1.2.3-alpha.1"),0);
  for(const version of ["1.0.0+build","1.0.0-a..b","../1.0.0","1.0.0-","1.0.0-"+"a".repeat(123)]){
    assert.throws(()=>compareVersions(version,"1.0.0"),/ERR_INSTALL_VERSION/);
    assert.throws(()=>compareVersions("1.0.0",version),/ERR_INSTALL_VERSION/);
  }
});

test("Windows package CLI permits Alpha8 to Alpha10 and rejects reverse before mutation",async()=>{
  const root=await mkdtemp(join(tmpdir(),"lmm-win-alpha-")),v8=await payload(root,"0.1.0-alpha.8","alpha8"),v10=await payload(root,"0.1.0-alpha.10","alpha10");
  const cli=fileURLToPath(new URL("../cli.js",import.meta.url));
  for(const p of [v8,v10])await writeFile(join(p.dir,"manifest.json"),JSON.stringify(p.manifest));
  const run=(command:string,p:typeof v8,dryRun=false)=>spawnSync(process.execPath,[cli,command,"--platform","windows","--root",root,"--payload",p.dir,"--manifest",join(p.dir,"manifest.json"),...(dryRun?["--dry-run"]:[])],{encoding:"utf8"});
  let result=run("install",v8);assert.equal(result.status,0,result.stderr);
  const plan=installPlan({platform:"windows",root,role:"agent",version:v10.manifest.version});
  await writeFile(join(plan.state,"enrollment.key"),"keep-enrollment");await writeFile(join(plan.config,"keep.conf"),"keep-config");
  const before=await inventoryTree(join(root,"Program Files")),dataBefore=await inventoryTree(join(root,"ProgramData"));
  result=run("upgrade",v10,true);assert.equal(result.status,0,result.stderr);assert.equal(JSON.parse(result.stdout).changed,false);
  assert.deepEqual(await inventoryTree(join(root,"Program Files")),before);assert.deepEqual(await inventoryTree(join(root,"ProgramData")),dataBefore);
  result=run("upgrade",v10);assert.equal(result.status,0,result.stderr);assert.equal(JSON.parse(result.stdout).changed,true);assert.equal(await readFile(plan.pointer,"utf8"),v10.manifest.version+"\n");
  assert.equal(await readFile(join(plan.state,"enrollment.key"),"utf8"),"keep-enrollment");assert.equal(await readFile(join(plan.config,"keep.conf"),"utf8"),"keep-config");
  const installed=await inventoryTree(join(root,"Program Files")),installedData=await inventoryTree(join(root,"ProgramData"));
  for(const dryRun of [true,false]){result=run("upgrade",v8,dryRun);assert.notEqual(result.status,0);assert.match(result.stderr,/ERR_INSTALL_DOWNGRADE/);assert.deepEqual(await inventoryTree(join(root,"Program Files")),installed);assert.deepEqual(await inventoryTree(join(root,"ProgramData")),installedData);}
});
