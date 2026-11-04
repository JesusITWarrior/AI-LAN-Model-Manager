import test from "node:test";
import assert from "node:assert/strict";
import { build } from "esbuild";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { mkdtemp, rm, access } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
// Load the Node-only integration fixture at runtime; it is not part of the web TS project.
const { browserController } = await import(new URL("../test-support/lifecycle-controller.ts",import.meta.url).href);

test("mounted lifecycle review recovers lost prepared/approved proposals after real controller restart",{timeout:90_000},async()=>{
 const chromium=process.env.CHROMIUM_PATH??"/usr/bin/chromium-browser";
 await access(chromium); // A missing browser is a visible gate failure, never fake mounted coverage.
 const bundle=await build({entryPoints:[fileURLToPath(new URL("../test-support/lifecycle-mounted.tsx",import.meta.url))],bundle:true,write:false,platform:"browser",format:"iife",define:{"process.env.NODE_ENV":'"production"'}});
 const dir=await mkdtemp(join(tmpdir(),"lanmm-mounted-"));
 const controller=await browserController().catch(async(error:unknown)=>{await rm(dir,{recursive:true,force:true});throw error;});
 let browser:ReturnType<typeof spawn>|undefined,timer:ReturnType<typeof setTimeout>|undefined,version=1;
 let finish:(value:any)=>void=()=>{};const result=new Promise<any>(resolve=>{finish=resolve;});
 const requests:Array<{action:string;status:number}>=[];
 const server=createServer((req,res)=>{void(async()=>{
  const url=new URL(req.url!,"http://localhost");
  if(url.pathname==="/"){res.setHeader("content-type","text/html");res.end('<div id="root"></div><script src="/fixture.js"></script>');return;}
  if(url.pathname==="/fixture.js"){res.setHeader("content-type","text/javascript");res.end(bundle.outputFiles[0]!.text);return;}
  if(url.pathname==="/test/configure"){await controller.install(url.searchParams.get("approval")==="true",version++);res.end("ok");return;}
  if(url.pathname==="/test/restart"){await controller.restart();res.end("ok");return;}
  let body="";for await(const chunk of req)body+=chunk;
  if(url.pathname==="/test/result"){finish(JSON.parse(body));res.end("ok");return;}
  if(url.pathname.startsWith("/api/")){const upstream=await controller.post(url.pathname,JSON.parse(body),controller.headers);requests.push({action:url.pathname.split("/").at(-1)!,status:upstream.status});res.statusCode=upstream.status;res.setHeader("content-type","application/json");res.end(await upstream.text());return;}
  res.statusCode=404;res.end();
 })().catch(error=>{finish({ok:false,error:String(error)});res.statusCode=500;res.end("fixture failed");});});
 try{
  await new Promise<void>(resolve=>server.listen(0,"127.0.0.1",resolve));const address=server.address();assert.ok(address&&typeof address!=="string");
  browser=spawn(chromium,["--headless","--no-sandbox","--disable-gpu","--disable-background-networking","--no-first-run",`--user-data-dir=${join(dir,"profile")}`,`http://127.0.0.1:${address.port}/`],{stdio:"ignore",detached:true});
  browser.once("error",error=>finish({ok:false,error:String(error)}));
  timer=setTimeout(()=>finish({ok:false,error:"Mounted browser fixture timed out"}),65_000);
  const report=await result;assert.equal(report.ok,true,JSON.stringify(report));assert.equal(report.cases,6);
  assert.equal(requests.filter(r=>r.status===409).length,7);for(const action of ["status","submit","cancel"])assert.equal(requests.filter(r=>r.action===action&&r.status===409).length,action==="status"?3:2);
  assert.equal(requests.filter(r=>r.action==="prepare").length,14,"only explicit prepare clicks");
  assert.equal(requests.filter(r=>r.action==="submit"&&r.status===200).length,0,"forget never reexecutes");assert.equal(controller.jobs(),0,"no durable jobs created");
 }finally{
  clearTimeout(timer);
  try {
   if(browser&&browser.exitCode===null&&browser.signalCode===null){const exited=new Promise<void>(resolve=>browser!.once("exit",()=>resolve()));if(browser.pid)process.kill(-browser.pid,"SIGKILL");await exited;}
  } finally {
   try {server.closeAllConnections();await new Promise<void>(resolve=>server.close(()=>resolve()));}
   finally {try {await controller.close();} finally {await rm(dir,{recursive:true,force:true});}}
  }
 }
});
