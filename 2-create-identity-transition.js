import Fs from "node:fs/promises";

// import DashKeys from "dashkeys";
import * as DashTx from "dashtx/dashtx.js";

import * as Bincode from "./bincode.ts";
import * as DashBincode from "./1.8.1/generated_bincode.js";
import * as KeyUtils from "./key-utils.js";
import baseX from "base-x";

const ST_CREATE_IDENTITY = 2;
const L2_VERSION_PLATFORM = 1; // actually constant "0" ??

let KEY_LEVELS = {
  0: "MASTER",
  1: "CRITICAL",
  2: "HIGH",
  3: "MEDIUM",
  MASTER: 0,
  CRITICAL: 1,
  HIGH: 2,
  MEDIUM: 3,
};

let KEY_PURPOSES = {
  0: "AUTHENTICATION",
  1: "ENCRYPTION",
  2: "DECRYPTION",
  3: "TRANSFER",
  4: "SYSTEM",
  5: "VOTING",
  AUTHENTICATION: 0,
  ENCRYPTION: 1,
  DECRYPTION: 2,
  TRANSFER: 3,
  SYSTEM: 4,
  VOTING: 5,
};

let KEY_TYPES = {
  0: "ECDSA_SECP256K1",
  ECDSA_SECP256K1: 0,
};

const BASE58 = `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`;
let base58 = baseX(BASE58);

let Thingy = {};

/**
 * @typedef AssetLockChainProof
 * @prop {Number} core_chain_locked_height
 * @prop {Object} out_point
 * @prop {String} out_point.txid
 * @prop {Number} out_point.vout
 */

/**
 * @param {import('dashhd').HDWallet} assetKey
 * @param {import('dashhd').HDWallet} masterKey
 * @param {import('dashhd').HDWallet} otherKey
 * @param {String} identityIdHex
 * @param {String} txidHex
 * @param {String} [txlocksigHex]
 * @param {import('dashtx').TxInfo} [txCore]
 */
Thingy.doStuff = async function (
  assetKey,
  masterKey,
  otherKey,
  identityIdHex,
  txidHex,
  txlocksigHex,
  txCore,
) {
  // const INSTANT_ALP = 0;
  // const CHAIN_ALP = 1;

  /** @type {DashBincode.AssetLockProof} */
  let assetLockProof;
  if (txlocksigHex) {
    assetLockProof = await getAssetLockInstantProof(txlocksigHex);
  } else {
    assetLockProof = await getAssetLockChainProof(txidHex, txCore);
  }

  if (!masterKey.privateKey) {
    throw new Error("'masterKey' is missing 'privateKey'");
  }
  if (!otherKey.privateKey) {
    throw new Error("'otherKey' is missing 'privateKey'");
  }
  let identityKeys = await getKnownIdentityKeys(
    { privateKey: masterKey.privateKey, publicKey: masterKey.publicKey },
    { privateKey: otherKey.privateKey, publicKey: otherKey.publicKey },
  );
  let stKeys = getIdentityTransitionKeys(identityKeys);

  let identityCreate = DashBincode.IdentityCreateTransitionV0({
    //protocolVersion: L2_VERSION_PLATFORM,
    // $version: L2_VERSION_PLATFORM.toString(),
    // type: ST_CREATE_IDENTITY,
    // ecdsaSig(assetLockPrivateKey, CBOR(thisStateTransition))
    // "signature":"IBTTgge+/VDa/9+n2q3pb4tAqZYI48AX8X3H/uedRLH5dN8Ekh/sxRRQQS9LaOPwZSCVED6XIYD+vravF2dhYOE=",
    asset_lock_proof: assetLockProof,
    // publicKeys: stKeys,
    public_keys: stKeys,
    // [
    //   {
    //     id: 0,
    //     type: 0,
    //     purpose: 0,
    //     securityLevel: 0,
    //     data: "AkWRfl3DJiyyy6YPUDQnNx5KERRnR8CoTiFUvfdaYSDS",
    //     readOnly: false,
    //   },
    // ],
    identity_id: DashBincode.Identifier(DashBincode.IdentifierBytes32(DashTx.utils.hexToBytes(identityIdHex))),
    user_fee_increase: 0,
    signature: DashBincode.BinaryData(new Uint8Array),
  })

  let stateTransition = DashBincode.StateTransition.IdentityCreate(
    DashBincode.IdentityCreateTransition.V0(identityCreate));
  console.log(`stKeys:`);
  console.log(stKeys);

  let nullSigTransition = new Uint8Array(Bincode.encode(
    DashBincode.StateTransition,
    stateTransition,
    {
      signable: true,
    },
  ));
  console.log();
  console.log(`nullSigTransition (ready-to-sign by identity keys):`);
  console.log('(hex)', DashTx.utils.bytesToHex(nullSigTransition));
  console.log('(base64)', bytesToBase64(nullSigTransition));

  let nullSigMagicHash = await KeyUtils.doubleSha256(nullSigTransition);

  if (!assetKey.privateKey) {
    throw new Error("'assetKey' is missing 'privateKey'");
  }
  {
    let magicSigBytes = await KeyUtils.magicSign({
      privKeyBytes: assetKey.privateKey,
      doubleSha256Bytes: nullSigMagicHash,
    });

    identityCreate.signature[0] = magicSigBytes
  }

  for (let i = 0; i < identityKeys.length; i += 1) {
    let key = identityKeys[i];
    let stPub = identityCreate.public_keys[i];
    let magicSigBytes = await KeyUtils.magicSign({
      privKeyBytes: key.privateKey,
      doubleSha256Bytes: nullSigMagicHash,
    });

    Bincode.match(stPub, {
      V0: ({0: stPub0}) => {
        stPub0.signature[0] = magicSigBytes
      }
    })
  }

  console.log();
  console.log(JSON.stringify(stateTransition, (key, val) => {
      if (val instanceof Uint8Array || val instanceof ArrayBuffer) {
        return {'@Uint8Array hex': DashTx.utils.bytesToHex(new Uint8Array(val))}
      }
      return val
    }, 2));

  let grpcTransition = "";
  let transitionHashHex = "";
  {
    let fullSigTransition = new Uint8Array(Bincode.encode(
      DashBincode.StateTransition,
      stateTransition,
      {
        signable: false,
      },
    ));
    console.log();
    console.log(`transition (fully signed):`);
    console.log(DashTx.utils.bytesToHex(fullSigTransition));
    let transitionHash = await KeyUtils.sha256(fullSigTransition);
    transitionHashHex = DashTx.utils.bytesToHex(transitionHash);
    grpcTransition = bytesToBase64(fullSigTransition);
  }

  console.log();
  console.log();
  console.log(`grpcurl -plaintext -d '{
  "stateTransition": "${grpcTransition}"
}' seed-2.testnet.networks.dash.org:1443 org.dash.platform.dapi.v0.Platform.broadcastStateTransition`);
  console.log();
  let identityIdBytes = DashTx.utils.hexToBytes(identityIdHex);
  let identity = base58.encode(identityIdBytes);
  console.log(`https://testnet.platform-explorer.com/identity/${identity}`);
  console.log(
    `https://testnet.platform-explorer.com/transaction/${transitionHashHex}`,
  );
};

export default Thingy;

/** @param {HexString} txlocksigHex */
async function getAssetLockInstantProof(txlocksigHex) {
  {
    let len = txlocksigHex.length / 2;
    console.log();
    console.log(`Tx Lock Sig Hex (${len}):`);
    console.log(txlocksigHex);
  }

  let vout = -1;
  let instantLockTxHex = "";
  let instantLockSigHex = "";
  {
    let txlocksig = DashTx.parseUnknown(txlocksigHex);
    vout = 0;
    //vout = txlocksig.extraPayload.outputs.findIndex(function (output) {
    //  //@ts-expect-error
    //  return output.script === "6a00";
    //});
    // console.log(txlocksig.extraPayload.outputs);
    //@ts-expect-error
    instantLockSigHex = txlocksig.sigHashTypeHex;
    let isLen = instantLockSigHex.length / 2;
    let len = txlocksigHex.length / 2;
    len -= isLen;
    instantLockTxHex = txlocksigHex.slice(0, len * 2);
    console.log();
    console.log(`Tx Hex (${len})`);
    console.log(instantLockTxHex);
    console.log();
    console.log(`Tx Lock Sig Instant Lock Hex (${isLen})`);
    //@ts-expect-error
    console.log(txlocksig.sigHashTypeHex);
  }

  let assetLockInstantProof = DashBincode.RawInstantLockProof({
    instant_lock: DashBincode.BinaryData(DashTx.utils.hexToBytes(instantLockSigHex)),
    transaction: DashBincode.BinaryData(DashTx.utils.hexToBytes(instantLockTxHex)), // TODO this may need the proof, not the signed tx
    output_index: vout,
  });
  return DashBincode.AssetLockProof.Instant(assetLockInstantProof);
}

/**
 * @param {HexString} txidHex
 * @param {any} txInfo - TODO CoreTx
 */
async function getAssetLockChainProof(txidHex, txInfo) {
  //@ts-expect-error
  let vout = txInfo.vout.findIndex(voutInfo =>
     voutInfo.scriptPubKey?.hex === "6a00" // TODO match the burn
  );

  let assetLockChainProof = DashBincode.ChainAssetLockProof({
    core_chain_locked_height: txInfo.height,
    out_point: {
      txid: DashBincode.Txid(DashTx.utils.hexToBytes(txidHex)),
      vout: vout,
    },
  });

  return DashBincode.AssetLockProof.Chain(assetLockChainProof);
}

/**
 * @param {Required<Pick<import('dashhd').HDXKey, "privateKey"|"publicKey">>} masterKey
 * @param {Required<Pick<import('dashhd').HDXKey, "privateKey"|"publicKey">>} otherKey
 * @returns {Promise<Array<EvoKey>>}
 */
async function getKnownIdentityKeys(masterKey, otherKey) {
  if (!masterKey.privateKey) {
    throw new Error("linter fail");
  }
  if (!otherKey.privateKey) {
    throw new Error("linter fail");
  }
  let keyDescs = [
    // {"$version":"0","id":0,"purpose":0,"securityLevel":0,"contractBounds":null,"type":0,"readOnly":false,"data":[3,58,154,139,30,76,88,26,25,135,114,76,102,151,19,93,49,192,126,231,172,130,126,106,89,206,192,34,176,77,81,5,95],"disabledAt":null}
    {
      id: 0,
      type: DashBincode.KeyType.ECDSA_SECP256K1(),
      purpose: DashBincode.Purpose.AUTHENTICATION(),
      securityLevel: DashBincode.SecurityLevel.MASTER(),
      readOnly: false,
      publicKey: masterKey.publicKey,
      privateKey: masterKey.privateKey,
      data: "",
    },
    // {"$version":"0","id":1,"purpose":0,"securityLevel":1,"contractBounds":null,"type":0,"readOnly":false,"data":[2,1,70,3,1,141,196,55,100,45,218,22,244,199,252,80,228,130,221,35,226,70,128,188,179,165,150,108,59,52,56,72,226],"disabledAt":null}
    {
      id: 1,
      type: DashBincode.KeyType.ECDSA_SECP256K1(),
      purpose: DashBincode.Purpose.AUTHENTICATION(),
      securityLevel: DashBincode.SecurityLevel.CRITICAL(),
      readOnly: false,
      privateKey: otherKey.privateKey,
      publicKey: otherKey.publicKey,
      data: "",
    },
  ];
  return keyDescs;
}

/**
 * @typedef EvoKey
 * @prop {Uint8} id
 * @prop {DashBincode.KeyType} type - TODO constrain to members of KEY_TYPES
 * @prop {DashBincode.Purpose} purpose - TODO constrain to members of KEY_PURPOSES
 * @prop {DashBincode.SecurityLevel} securityLevel - TODO constrain to members of KEY_LEVELS
 * @prop {Boolean} readOnly
 * @prop {Uint8Array} publicKey
 * @prop {Uint8Array} privateKey
 */

/**
 * @typedef STKey
 * @prop {Uint8} id
 * @prop {DashBincode.KeyType} type - TODO constrain to members of KEY_TYPES
 * @prop {DashBincode.Purpose} purpose - TODO constrain to members of KEY_PURPOSES
 * @prop {Base64} data - base64-encoded publicKey (compact)
 * @prop {DashBincode.SecurityLevel} securityLevel - TODO constrain to members of KEY_LEVELS
 * @prop {Boolean} readOnly
 */

/**
 * @param {Array<EvoKey>} identityKeys - TODO
 * @returns {Array<DashBincode.IdentityPublicKeyInCreation>}
 */
function getIdentityTransitionKeys(identityKeys) {
  let stKeys = [];
  for (let key of identityKeys) {
    let stKey = DashBincode.IdentityPublicKeyInCreation.V0(DashBincode.IdentityPublicKeyInCreationV0({
      id: key.id,
      key_type: key.type,
      purpose: key.purpose,
      security_level: key.securityLevel,
      contract_bounds: undefined,
      read_only: key.readOnly || false,
      data: DashBincode.BinaryData(key.publicKey),
      signature: DashBincode.BinaryData(new Uint8Array),
    }));
    stKeys.push(stKey);
  }
  return stKeys;
}

/**
 * @param {Uint8Array} bytes
 */
function bytesToBase64(bytes) {
  // @ts-expect-error Uint8Array is close enough to number[] for this to work
  return btoa(String.fromCharCode.apply(null, bytes));
}

/**
 * Reads a hex file as text, stripping comments (anything including and after a non-hex character), removing whitespace, and joining as a single string
 * @param {String} path
 */
async function readHex(path) {
  let text = await Fs.readFile(path, "utf8");
  let lines = text.split("\n");
  let hexes = [];
  for (let line of lines) {
    line = line.replace(/\s/g, "");
    line = line.replace(/[^0-9a-f].*/i, "");
    hexes.push(line);
  }

  let hex = hexes.join("");
  return hex;
}

/**
 * @param {String} path
 */
async function readWif(path) {
  let wif = await Fs.readFile(path, "utf8");
  wif = wif.trim();

  return wif;
}

/** @typedef {String} Base58 */
/** @typedef {String} Base64 */
/** @typedef {String} HexString */
/** @typedef {Number} Uint53 */
/** @typedef {Number} Uint32 */
/** @typedef {Number} Uint8 */
