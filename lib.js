"use strict";
const crypto = require("crypto");
const stringToBuffer = s => Buffer.from(s, "utf8");
const bufferToString = b => Buffer.from(b).toString("utf8");
const encodeBuffer = b => Buffer.from(b).toString("base64");
function decodeBuffer(s) {
  if (typeof s !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s)) throw new TypeError("Invalid Base64 value.");
  return Buffer.from(s, "base64");
}
const getRandomBytes = n => crypto.randomBytes(n);
module.exports = {stringToBuffer,bufferToString,encodeBuffer,decodeBuffer,getRandomBytes};
