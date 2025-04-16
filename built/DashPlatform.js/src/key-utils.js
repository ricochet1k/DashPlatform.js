"use strict";
// @ts-expect-error no types
import Secp256k1 from "@dashincubator/secp256k1";
import RIPEMD160 from "ripemd160";
/**
 * @typedef KeyInfo
 * @prop {String} address
 * @prop {Uint8Array} privateKey
 * @prop {Uint8Array} publicKey
 * @prop {String} pubKeyHash
 */
/** @type {Object.<String, KeyInfo>} */
const keysMap = {};
/**
 * @param {String} id - typically address
 * @param {KeyInfo} keyInfo
 */
export function set(id, keyInfo) {
    if (!id) {
        throw new Error(`key identifier is not defined)`);
    }
    keysMap[id] = keyInfo;
}
;
/**
 * @param {Uint8Array} privKeyBytes
 * @param {Uint8Array} hashBytes
 */
export async function sign(privKeyBytes, hashBytes) {
    let asn1Bytes = await signAsn1(privKeyBytes, hashBytes);
    return asn1Bytes;
}
;
/**
 * @param {Uint8Array} privKeyBytes
 * @param {Uint8Array} hashBytes
 */
export async function signAsn1(privKeyBytes, hashBytes) {
    let testing = true;
    let sigOpts = { canonical: true };
    if (!testing) {
        Object.assign({ extraEntropy: true });
    }
    let sigBytes = await Secp256k1.sign(hashBytes, privKeyBytes, sigOpts);
    return sigBytes;
}
;
/**
 * @param {Uint8Array} bytes
 */
export async function doubleSha256(bytes) {
    let firstHash = await sha256(bytes);
    let secondHash = await sha256(firstHash);
    return secondHash;
}
;
/**
 * @param {Uint8Array} bytes
 */
export async function sha256(bytes) {
    let hashBuffer = await crypto.subtle.digest("SHA-256", bytes);
    let hashBytes = new Uint8Array(hashBuffer);
    return hashBytes;
}
/**
 * Sha256 then RIPEMD-160
 * @param {Uint8Array} bytes
 */
export async function pubkeyHash(bytes) {
    let firstHash = await sha256(bytes);
    let ripemd160 = new RIPEMD160;
    ripemd160.update(Buffer.from(firstHash));
    return ripemd160.digest();
}
/**
 * This is called "Simple Sign" by the Rust SDK.
 * @param {Object} opts
 * @param {Uint8Array} opts.privKeyBytes
 * @param {Uint8Array} opts.doubleSha256Bytes
 */
export async function magicSign({ privKeyBytes, doubleSha256Bytes }) {
    if (doubleSha256Bytes?.length !== 32) {
        throw new Error(`'doubleSha256Bytes' must be a 32-byte double sha256 hash`);
    }
    let MAGIC_OFFSET = 27 + 4; // 27 because bitcoin, 4 because "compressed" key
    let testing = true;
    let sigOpts = { canonical: true, der: false, recovered: true };
    if (!testing) {
        Object.assign({ extraEntropy: true });
    }
    let recoverySig = await Secp256k1.sign(doubleSha256Bytes, privKeyBytes, sigOpts);
    let magicSig = new Uint8Array(65);
    // the magic byte is prepended (the signature is NOT reversed)
    magicSig[0] = MAGIC_OFFSET + recoverySig[1];
    magicSig.set(recoverySig[0], 1);
    return magicSig;
}
;
/**
 * @param {Uint8Array} privKeyBytes
 * @param {Uint8Array} hashBytes
 * @param {Uint8Array} [sigBytes] - preallocated 64 bytes
 */
export async function signP1363(privKeyBytes, hashBytes, sigBytes) {
    let asn1Bytes = await signAsn1(privKeyBytes, hashBytes);
    let p1363Bytes = asn1ToP1363Signature(asn1Bytes, sigBytes);
    // TODO DEBUG TESTING
    // for (let i = 0; i < p1363Bytes.length; i += 1) {
    //   p1363Bytes[i] = 0xff;
    // }
    return p1363Bytes;
}
;
/**
 * @param {Uint8Array} asn1
 * @param {Uint8Array} [p1363Signature]
 */
export function asn1ToP1363Signature(asn1, p1363Signature) {
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
}
;
/**
 * @param {{ address?: string; txid: any; outputIndex: any; }} input
 */
export async function getPrivateKey(input) {
    if (!input.address) {
        //throw new Error('should put the address on the input there buddy...');
        console.warn("missing address:", input.txid, input.outputIndex);
        return null;
    }
    let keyInfo = keysMap[input.address];
    return keyInfo.privateKey;
}
;
/**
 * @param {{ address?: string; txid: any; outputIndex: any; }} txInput
 * @param {any} i
 */
export async function getPublicKey(txInput, i) {
    let privKeyBytes = await getPrivateKey(txInput, i);
    if (!privKeyBytes) {
        return null;
    }
    let pubKeyBytes = await toPublicKey(privKeyBytes);
    return pubKeyBytes;
}
;
/**
 * @param {Uint8Array} privKeyBytes
 */
export async function toPublicKey(privKeyBytes) {
    let isCompressed = true;
    let pubKeyBytes = Secp256k1.getPublicKey(privKeyBytes, isCompressed);
    return pubKeyBytes;
}
;
