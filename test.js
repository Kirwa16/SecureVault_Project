 "use strict";
const test=require("node:test"),assert=require("node:assert/strict"),{Keychain}=require("./password-manager");
test("init, CRUD, list and restore",async()=>{const k=await Keychain.init("master");await k.set("example.com","secret");assert.equal(await k.get("example.com"),"secret");const [r,c]=await k.dump();const x=await Keychain.load("master",r,c);assert.equal(await x.get("example.com"),"secret");assert.deepEqual(await x.list(),["example.com"]);assert.equal(await x.remove("example.com"),true);});
test("wrong password rejected",async()=>{const k=await Keychain.init("master");const [r]=await k.dump();await assert.rejects(()=>Keychain.load("wrong",r),/Incorrect master password/);});
test("trusted checksum rejects tampering",async()=>{const k=await Keychain.init("master");const [r]=await k.dump();await assert.rejects(()=>Keychain.load("master",r,"bad"),/integrity check failed/);});
test("rejects passwords longer than 64 characters",async()=>{const k=await Keychain.init("master");await assert.rejects(()=>k.set("example.com","x".repeat(65)),/64 characters/);});
