import assert from "node:assert/strict";
import test from "node:test";
import {canonicalCertificateSerial,sameCertificateSerial} from "./certificates.js";
import {parseTransportSignedEnvelope} from "./transport.js";

test("certificate serial identity is positive uppercase numeric hex; legacy byte padding is equivalent",()=>{
 for(const [legacy,numeric]of [["01","1"],["01111111111111111111111111111111","1111111111111111111111111111111"],["0ABCDEF123456789","ABCDEF123456789"],["1111","1111"]]){
  assert.equal(canonicalCertificateSerial(legacy),numeric);assert.equal(sameCertificateSerial(legacy,numeric),true);
 }
 for(const value of ["","0","00","-1","0x01","ab","1 ","A".repeat(41),null,1]){assert.equal(canonicalCertificateSerial(value),null);assert.equal(sameCertificateSerial(value,value),false);}
 assert.equal(sameCertificateSerial("0ABC","ABCD"),false);
});

test("signed envelope parsing accepts one-digit and legacy serials without changing signed field bytes",()=>{
 const raw={protocolVersion:{major:1,minor:0},messageType:"transport.hello",hostId:"agent-1",requestId:"serial-request",sequence:1,sentAt:"2026-11-04T00:00:00.000Z",nonce:"serial-nonce",bodyDigest:"a".repeat(64),certFingerprint:"b".repeat(64),certSerial:"01",signature:"a".repeat(16),payload:{}};
 for(const serial of ["1","01","0ABCDEF123456789"]){const parsed=parseTransportSignedEnvelope({...raw,certSerial:serial});assert.ok(parsed.ok);assert.equal(parsed.value.certSerial,serial);}
 for(const serial of ["0","00","ab","-1","A".repeat(41)])assert.equal(parseTransportSignedEnvelope({...raw,certSerial:serial}).ok,false);
});
