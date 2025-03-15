"use strict";

import * as secp from "@dashincubator/secp256k1"

/** @typedef {Required<import('dashtx').TxKeyUtils>} TxKeyUtils */
/**
 * @typedef KeyUtilsPartial
 * @prop {KeySet} set
 */
/** @typedef {TxKeyUtils & KeyUtilsPartial} KeyUtils */

/**
 * @typedef KeyInfo
 * @prop {String} address
 * @prop {Uint8Array} privateKey
 * @prop {Uint8Array} publicKey
 * @prop {String} pubKeyHash
 */

/** @type Object.<String, KeyInfo> */
let keysMap = {};

/**
 * @param {String} id
 * @param {KeyInfo} keyInfo
 */
function set(id, keyInfo) {
  if (!id) {
    throw new Error(`key identifier is not defined)`);
  }
  keysMap[id] = keyInfo;
};

export async function sign(privKeyBytes, hashBytes) {
  let sigOpts = { canonical: true, extraEntropy: true };
  let sigBytes = await secp.sign(hashBytes, privKeyBytes, sigOpts);
  return sigBytes;
};


export async function getPrivateKey(input) {
  if (!input.address) {
    //throw new Error('should put the address on the input there buddy...');
    console.warn("missing address:", input.txid, input.outputIndex);
    return null;
  }

  let keyInfo = keysMap[input.address];
  return keyInfo.privateKey;
};

export async function getPublicKey(txInput, i) {
  let privKeyBytes = await secp.getPrivateKey(txInput, i);
  if (!privKeyBytes) {
    return null;
  }
  let pubKeyBytes = await toPublicKey(privKeyBytes);

  return pubKeyBytes;
};

export async function toPublicKey(privKeyBytes) {
  let isCompressed = true;
  let pubKeyBytes = secp.getPublicKey(privKeyBytes, isCompressed);

  return pubKeyBytes;
};
