"use strict";

let Secp256k1 = require("@dashincubator/secp256k1");

/** @typedef {Required<import('dashtx').TxKeyUtils>} TxKeyUtils */
/**
 * @typedef KeyUtilsPartial
 * @prop {KeySet} set
 * @prop {KeySignAsn1} signAsn1
 * @prop {KeySignMagic} magicSign
 * @prop {KeySignP1363} signP1363
 * @prop {ASN1ToP1363Signature} asn1ToP1363Signature
 */
/** @typedef {TxKeyUtils & KeyUtilsPartial} KeyUtils */

/**
 * @callback KeySet
 * @param {String} id - typically address
 * @param {KeyInfo} keyInfo
 */

/**
 * @callback KeySignAsn1
 * @param {Uint8Array} privateKey
 * @param {Uint8Array} hashBytes
 * @returns {Promise<Uint8Array>}
 */

/**
 * @callback KeySignMagic
 * @param {Object} opts
 * @param {Uint8Array} opts.privKeyBytes
 * @param {Uint8Array} opts.doubleSha256Bytes
 * @returns {Promise<Uint8Array>}
 */

/**
 * @callback KeySignP1363
 * @param {Uint8Array} privateKey
 * @param {Uint8Array} hashBytes
 * @param {Uint8Array} [sigBytes] - preallocated 64 bytes
 * @returns {Promise<Uint8Array>}
 */

/**
 * @callback ASN1ToP1363Signature
 * @param {Uint8Array} asn1Sig
 * @param {Uint8Array} [sigBytes]
 * @returns {Uint8Array} - p1363Sig
 */

/** @type {KeyUtils} */
let KeyUtils = module.exports;

/**
 * @typedef KeyInfo
 * @prop {String} address
 * @prop {Uint8Array} privateKey
 * @prop {Uint8Array} publicKey
 * @prop {String} pubKeyHash
 */

/** @type Object.<String, KeyInfo> */
let keysMap = {};

KeyUtils.set = function (id, keyInfo) {
  if (!id) {
    throw new Error(`key identifier is not defined)`);
  }
  keysMap[id] = keyInfo;
};

KeyUtils.sign = async function (privKeyBytes, hashBytes) {
  let asn1Bytes = await KeyUtils.signAsn1(privKeyBytes, hashBytes);
  return asn1Bytes;
};

KeyUtils.signAsn1 = async function (privKeyBytes, hashBytes) {
  let testing = true;
  let sigOpts = { canonical: true };
  if (!testing) {
    Object.assign({ extraEntropy: true });
  }
  let sigBytes = await Secp256k1.sign(hashBytes, privKeyBytes, sigOpts);
  return sigBytes;
};

KeyUtils.magicSign = async function ({ privKeyBytes, doubleSha256Bytes }) {
  if (doubleSha256Bytes?.length !== 32) {
    throw new Error(`'doubleSha256Bytes' must be a 32-byte double sha256 hash`);
  }

  let MAGIC_OFFSET = 27 + 4; // 27 because bitcoin, 4 because "compressed" key
  let testing = true;
  let sigOpts = { canonical: true, der: false, recovered: true };
  if (!testing) {
    Object.assign({ extraEntropy: true });
  }
  let recoverySig = await Secp256k1.sign(
    doubleSha256Bytes,
    privKeyBytes,
    sigOpts,
  );
  let magicSig = new Uint8Array(65);
  // the magic byte is prepended (the signature is NOT reversed)
  magicSig[0] = MAGIC_OFFSET + recoverySig[1];
  magicSig.set(recoverySig[0], 1);
  return magicSig;
};

KeyUtils.signP1363 = async function (privKeyBytes, hashBytes, sigBytes) {
  let asn1Bytes = await KeyUtils.signAsn1(privKeyBytes, hashBytes);
  let p1363Bytes = KeyUtils.asn1ToP1363Signature(asn1Bytes, sigBytes);
  // TODO DEBUG TESTING
  // for (let i = 0; i < p1363Bytes.length; i += 1) {
  //   p1363Bytes[i] = 0xff;
  // }
  return p1363Bytes;
};

KeyUtils.asn1ToP1363Signature = function (asn1, p1363Signature) {
  if (asn1[0] !== 0x30) {
    throw new Error("Invalid DER signature format");
  }

  let offset = 0;
  offset += 2; // skip SEQUENCE and length bytes

  offset += 1; // skip type byte
  let rLength = asn1[offset];
  offset += 1;
  let r = asn1.slice(offset, offset + rLength);

  offset += rLength;
  offset += 1; // skip type byte
  let sLength = asn1[offset];
  offset += 1;
  let s = asn1.slice(offset, offset + sLength);

  if (!p1363Signature) {
    p1363Signature = new Uint8Array(64);
  }

  // remove ASN1 padding, or zero-pad the start of r and s, if needed
  let rStart = 32 - r.length;
  if (rStart === -1) {
    r = r.subarray(1);
    rStart = 0;
  }
  p1363Signature.set(r, rStart);

  let sStart = 64 - s.length;
  if (sStart === 31) {
    s = s.subarray(1);
    sStart = 32;
  }
  p1363Signature.set(s, sStart);

  return p1363Signature;
};

KeyUtils.getPrivateKey = async function (input) {
  if (!input.address) {
    //throw new Error('should put the address on the input there buddy...');
    console.warn("missing address:", input.txid, input.outputIndex);
    return null;
  }

  let keyInfo = keysMap[input.address];
  return keyInfo.privateKey;
};

KeyUtils.getPublicKey = async function (txInput, i) {
  let privKeyBytes = await KeyUtils.getPrivateKey(txInput, i);
  if (!privKeyBytes) {
    return null;
  }
  let pubKeyBytes = await KeyUtils.toPublicKey(privKeyBytes);

  return pubKeyBytes;
};

KeyUtils.toPublicKey = async function (privKeyBytes) {
  let isCompressed = true;
  let pubKeyBytes = Secp256k1.getPublicKey(privKeyBytes, isCompressed);

  return pubKeyBytes;
};
