 "use strict";
const express=require("express"),fs=require("fs"),path=require("path");
const {Keychain}=require("./password-manager");
const app=express(),PORT=Number(process.env.PORT||3000),DIR=path.join(__dirname,"data");
const VAULT=path.join(DIR,"vault.json"),CHECK=path.join(DIR,"vault.check");
let keychain=null,saveQueue=Promise.resolve();
app.use(express.json({limit:"1mb"}));app.use(express.static(path.join(__dirname,"public")));
const unlocked=(req,res,next)=>keychain?next():res.status(423).json({error:"Vault is locked."});
async function persist(){
 const [repr,check]=await keychain.dump();await fs.promises.mkdir(DIR,{recursive:true});
 await fs.promises.writeFile(VAULT+".tmp",repr,{mode:0o600});await fs.promises.writeFile(CHECK+".tmp",check,{mode:0o600});
 await fs.promises.rename(VAULT+".tmp",VAULT);await fs.promises.rename(CHECK+".tmp",CHECK);
}
const save=()=>{saveQueue=saveQueue.then(persist);return saveQueue;};
app.get("/api/status",(q,s)=>s.json({unlocked:!!keychain,vaultExists:fs.existsSync(VAULT)}));
app.post("/api/unlock",async(q,s)=>{
 try{const p=q.body?.masterPassword;if(typeof p!=="string"||!p)return s.status(400).json({error:"Enter your master password."});
 if(keychain)return s.json({unlocked:true});
 if(fs.existsSync(VAULT)){const repr=await fs.promises.readFile(VAULT,"utf8"),check=fs.existsSync(CHECK)?(await fs.promises.readFile(CHECK,"utf8")).trim():undefined;keychain=await Keychain.load(p,repr,check);}
 else{keychain=await Keychain.init(p);await save();}
 s.json({unlocked:true});
 }catch(e){s.status(401).json({error:e.message});}
});
app.post("/api/lock",unlocked,async(q,s)=>{try{await save();keychain=null;s.json({locked:true});}catch{s.status(500).json({error:"Could not save vault."});}});
app.get("/api/items",unlocked,async(q,s)=>s.json({items:(await keychain.list()).map(domain=>({domain}))}));
app.post("/api/items",unlocked,async(q,s)=>{try{const {domain,password}=q.body||{};if(typeof domain!=="string"||!domain.trim())return s.status(400).json({error:"Enter a website or domain."});if(typeof password!=="string")return s.status(400).json({error:"Password must be text."});await keychain.set(domain.trim(),password);await save();s.status(201).json({saved:true});}catch(e){s.status(400).json({error:e.message});}});
app.get("/api/items/password",unlocked,async(q,s)=>{try{const domain=String(q.query.domain||""),password=await keychain.get(domain);if(password===null)return s.status(404).json({error:"Login not found."});s.json({domain,password});}catch(e){s.status(400).json({error:e.message});}});
app.delete("/api/items",unlocked,async(q,s)=>{try{const removed=await keychain.remove(String(q.body?.domain||""));if(removed)await save();s.json({removed});}catch(e){s.status(400).json({error:e.message});}});
app.get("/api/security",unlocked,async(q,s)=>{const [repr]=await keychain.dump(),d=JSON.parse(repr);s.json({encryption:"AES-256-GCM per password record",domainIndex:"HMAC-SHA-256",keyDerivation:"PBKDF2-HMAC-SHA-256, 1,500,000 iterations",saltBytes:Buffer.from(d.salt,"base64").length,encryptedRecords:Object.keys(d.kvs).length,domainNamesInSerializedVault:false,passwordsInSerializedVault:false});});
app.listen(PORT,"127.0.0.1",()=>console.log(`SecureVault: http://127.0.0.1:${PORT} (local demo only)`));
