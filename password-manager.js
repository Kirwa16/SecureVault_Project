 "use strict";
const {stringToBuffer,bufferToString,encodeBuffer,decodeBuffer,getRandomBytes}=require("./lib");
const {subtle}=require("crypto").webcrypto;
const ITER=1500000,SALT=16,IV=12,MAX=64,MAX_BYTES=256,BLOCK=260;
const CHECK="SECUREVAULT_KEY_CHECK_V1", CHECK_AAD="securevault/key-check/v1", DIR_AAD="securevault/directory/v1";
async function derive(password,salt){
 const p=await subtle.importKey("raw",stringToBuffer(password),"PBKDF2",false,["deriveBits"]);
 return Buffer.from(await subtle.deriveBits({name:"PBKDF2",salt,iterations:ITER,hash:"SHA-256"},p,256));
}
async function hmac(key,msg){
 const k=await subtle.importKey("raw",key,{name:"HMAC",hash:"SHA-256"},false,["sign"]);
 return Buffer.from(await subtle.sign("HMAC",k,msg));
}
async function secrets(root){
 const index=await hmac(root,stringToBuffer("securevault/index/v1"));
 const enc=await hmac(root,stringToBuffer("securevault/encryption/v1"));
 const aes=await subtle.importKey("raw",enc,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]);
 return {index,aes};
}
async function tag(index,name){return encodeBuffer(await hmac(index,stringToBuffer(name)));}
async function hash(s){return encodeBuffer(await subtle.digest("SHA-256",stringToBuffer(s)));}
function equal(a,b){if(typeof a!=="string"||typeof b!=="string")return false;const x=Buffer.from(a),y=Buffer.from(b);return x.length===y.length&&require("crypto").timingSafeEqual(x,y);}
function pack(value){
 if(typeof value!=="string")throw new TypeError("Password must be a string.");
 if(value.length>MAX)throw new RangeError("Passwords cannot exceed 64 characters.");
 const b=stringToBuffer(value);if(b.length>MAX_BYTES)throw new RangeError("Password is too large.");
 const out=Buffer.alloc(BLOCK);out.writeUInt32BE(b.length);b.copy(out,4);out.set(getRandomBytes(BLOCK-4-b.length),4+b.length);return out;
}
function unpack(value){const b=Buffer.from(value);if(b.length!==BLOCK)throw Error("Invalid password record.");const n=b.readUInt32BE();if(n>MAX_BYTES)throw Error("Malformed password record.");return bufferToString(b.subarray(4,4+n));}
async function seal(aes,value,aad){const iv=getRandomBytes(IV);const ct=await subtle.encrypt({name:"AES-GCM",iv,additionalData:stringToBuffer(aad),tagLength:128},aes,stringToBuffer(value));return {iv:encodeBuffer(iv),ciphertext:encodeBuffer(ct)};}
async function unseal(aes,r,aad){if(!r||typeof r.iv!=="string"||typeof r.ciphertext!=="string")throw Error("Malformed encrypted record.");const iv=decodeBuffer(r.iv);if(iv.length!==IV)throw Error("Invalid IV.");return bufferToString(await subtle.decrypt({name:"AES-GCM",iv,additionalData:stringToBuffer(aad),tagLength:128},aes,decodeBuffer(r.ciphertext)));}
class Keychain{
 constructor(data,key,domains=[]){this.data=data;this.key=key;this.domains=domains;}
 static async init(password){
  if(typeof password!=="string")throw TypeError("Master password must be a string.");
  const salt=getRandomBytes(SALT),key=await secrets(await derive(password,salt));
  const keyCheck=await seal(key.aes,CHECK,CHECK_AAD),directory=await seal(key.aes,"[]",DIR_AAD);
  return new Keychain({salt:encodeBuffer(salt),keyCheck,directory,kvs:{}},key,[]);
 }
 static async load(password,repr,trustedDataCheck){
  if(typeof password!=="string")throw TypeError("Master password must be a string.");
  let data;try{data=JSON.parse(repr);}catch{throw Error("Invalid keychain representation.");}
  if(!data||typeof data.salt!=="string"||!data.keyCheck||!data.directory||!data.kvs||typeof data.kvs!=="object"||Array.isArray(data.kvs))throw Error("Invalid keychain representation.");
  if(trustedDataCheck!==undefined&&!equal(await hash(repr),trustedDataCheck))throw Error("Keychain integrity check failed.");
  const salt=decodeBuffer(data.salt);if(salt.length!==SALT)throw Error("Invalid salt.");
  const key=await secrets(await derive(password,salt));
  try{if(await unseal(key.aes,data.keyCheck,CHECK_AAD)!==CHECK)throw Error();}catch{throw Error("Incorrect master password or corrupted keychain.");}
  let domains;try{domains=JSON.parse(await unseal(key.aes,data.directory,DIR_AAD));if(!Array.isArray(domains)||domains.some(x=>typeof x!=="string"))throw Error();}catch{throw Error("Directory authentication failed.");}
  return new Keychain(data,key,domains);
 }
 async _saveDirectory(){this.data.directory=await seal(this.key.aes,JSON.stringify(this.domains),DIR_AAD);}
 async list(){return [...this.domains];}
 async dump(){const repr=JSON.stringify(this.data);return [repr,await hash(repr)];}
 async get(name){
  if(typeof name!=="string")throw TypeError("Domain must be a string.");
  const t=await tag(this.key.index,name),r=this.data.kvs[t];if(!r)return null;
  try{const iv=decodeBuffer(r.iv);const pt=await subtle.decrypt({name:"AES-GCM",iv,additionalData:stringToBuffer(t),tagLength:128},this.key.aes,decodeBuffer(r.ciphertext));return unpack(pt);}catch{throw Error("Record authentication failed; possible tampering detected.");}
 }
 async set(name,value){
  if(typeof name!=="string"||!name.trim())throw TypeError("Domain must be a non-empty string.");
  const t=await tag(this.key.index,name),iv=getRandomBytes(IV),ct=await subtle.encrypt({name:"AES-GCM",iv,additionalData:stringToBuffer(t),tagLength:128},this.key.aes,pack(value));
  this.data.kvs[t]={iv:encodeBuffer(iv),ciphertext:encodeBuffer(ct)};if(!this.domains.includes(name))this.domains.push(name);await this._saveDirectory();
 }
 async remove(name){
  if(typeof name!=="string")throw TypeError("Domain must be a string.");
  const t=await tag(this.key.index,name);if(!Object.hasOwn(this.data.kvs,t))return false;
  delete this.data.kvs[t];this.domains=this.domains.filter(x=>x!==name);await this._saveDirectory();return true;
 }
}
module.exports={Keychain};
