import test from "node:test";
import assert from "node:assert/strict";
import { build } from "esbuild";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { access, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

test("lifecycle review keeps exact targets, reasons and actions inside narrow and wide panels",{timeout:90_000},async()=>{
 const chromium=process.env.CHROMIUM_PATH??"/usr/bin/chromium-browser";await access(chromium);
 const bundle=await build({entryPoints:[fileURLToPath(new URL("../test-support/lifecycle-layout.tsx",import.meta.url))],bundle:true,write:false,platform:"browser",format:"iife",define:{"process.env.NODE_ENV":'"production"'}});
 const css=await readFile(new URL("./styles.css",import.meta.url),"utf8");
 const dir=await mkdtemp(join(tmpdir(),"lanmm-lifecycle-layout-"));
 let browser:ReturnType<typeof spawn>|undefined,timer:ReturnType<typeof setTimeout>|undefined;
 let finish:(value:any)=>void=()=>{};const result=new Promise<any>(resolve=>{finish=resolve;});
 const server=createServer((req,res)=>{void(async()=>{
  if(req.url==="/test/result"){let body="";for await(const chunk of req)body+=chunk;finish(JSON.parse(body));res.end("ok");return;}
  if(req.url==="/fixture.js"){res.setHeader("content-type","text/javascript");res.end(bundle.outputFiles[0]!.text);return;}
  if(req.url==="/styles.css"){res.setHeader("content-type","text/css");res.end(css);return;}
  res.setHeader("content-type","text/html");res.end('<!doctype html><meta name="viewport" content="width=device-width, initial-scale=1"><link rel="stylesheet" href="/styles.css"><div id="root"></div><script src="/fixture.js"></script>');
 })().catch(error=>{finish({ok:false,error:String(error)});res.statusCode=500;res.end();});});
 try{
  await new Promise<void>(resolve=>server.listen(0,"127.0.0.1",resolve));const address=server.address();assert.ok(address&&typeof address!=="string");
  browser=spawn(chromium,["--headless","--no-sandbox","--disable-gpu","--disable-background-networking","--no-first-run",`--user-data-dir=${join(dir,"profile")}`,`http://127.0.0.1:${address.port}/`],{stdio:"ignore",detached:true});
  browser.once("error",error=>finish({ok:false,error:String(error)}));timer=setTimeout(()=>finish({ok:false,error:"Lifecycle viewport fixture timed out"}),65_000);
  const report=await result;assert.equal(report.ok,true,JSON.stringify(report));assert.deepEqual(report.widths,[320,375,768,1050,1280,1920]);assert.equal(report.cases,54);
 }finally{
  clearTimeout(timer);
  try{if(browser&&browser.exitCode===null&&browser.signalCode===null){const exited=new Promise<void>(resolve=>browser!.once("exit",()=>resolve()));if(browser.pid)process.kill(-browser.pid,"SIGKILL");await exited;}}
  finally{server.closeAllConnections();await new Promise<void>(resolve=>server.close(()=>resolve()));await rm(dir,{recursive:true,force:true});}
 }
});
