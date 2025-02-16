"use strict";

let Fs = require("node:fs/promises");

// let DashPhrase = require("dashphrase");
let DashHd = require("dashhd");
let DashKeys = require("dashkeys");
let DashTx = require("dashtx");
let DashPlatform = require("./dashplatform.js");
let Bincode = require("./bincode.js");

let KeyUtils = require("./key-utils.js");

// let DapiGrpc = require("@dashevo/dapi-grpc");
// let WasmDpp = require("@dashevo/wasm-dpp");
// let Dpp = WasmDpp.DashPlatformProtocol;

//@ts-ignore - sssssh, yes Base58 does exist
// let b58 = DashKeys.Base58.create();

let rpcAuthUrl = "https://api:null@trpc.digitalcash.dev";

const L1_VERSION_PLATFORM = 3;
// const L1_VERSION_PLATFORM = 0;
const TYPE_ASSET_LOCK = 8;
const VERSION_ASSET_LOCK = 1;
// const L2_VERSION_PLATFORM = 1; // actually constant "0" ??
// const ST_CREATE_IDENTITY = 2;

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

let network = "testnet";
let coinType = 5; // DASH
if (network === "testnet") {
  coinType = 1; // testnet
}
//coinType = 1;

let identityEcdsaPath = "";
{
  // m/purpose'/coin_type'/feature'/subfeature'/keytype'/identityindex'/keyindex'
  // ex: m/9'/5'/5'/0'/0'/<id>/<key>
  let purposeDip13 = 9;
  let featureId = 5;
  let subfeatureKey = 0;
  let keyType = KEY_TYPES.ECDSA_SECP256K1;
  identityEcdsaPath = `m/${purposeDip13}'/${coinType}'/${featureId}'/${subfeatureKey}'/${keyType}'`;
}

async function main() {
  // void (await WasmDpp.default());

  let dashTx = DashTx.create(KeyUtils);

  let fundingWif = await readWif("./funding.wif");
  let fundingInfo = await wifToInfo(fundingWif, "testnet");

  KeyUtils.set(fundingInfo.address, {
    address: fundingInfo.address,
    privateKey: fundingInfo.privateKey,
    publicKey: fundingInfo.publicKey,
    pubKeyHash: fundingInfo.pubKeyHashHex,
  });

  let changeWif = await readWif("./change.wif");
  let changeInfo = await wifToInfo(changeWif, "testnet");

  let assetWif = await readWif("./asset.wif");
  let assetInfo = await wifToInfo(assetWif, "testnet");

  let masterWif = await readWif("./master.wif");
  let masterInfo = await wifToInfo(masterWif, "testnet");

  let otherWif = await readWif("./other.wif");
  let otherInfo = await wifToInfo(otherWif, "testnet");

  let fundingUtxos = await DashTx.utils.rpc(rpcAuthUrl, "getaddressutxos", {
    addresses: [fundingInfo.address],
  });
  fundingUtxos[0].squence = "00000000"; // ??

  let fundingTotal = DashTx.sum(fundingUtxos);
  console.log();
  console.log(`funding utxos (${fundingTotal})`);
  console.log(fundingUtxos);

  let transferSats = 100000000;
  let feeSats = 500; // enough for 1 input and 2 outputs + extrapayload
  let changeSats = fundingTotal + -transferSats + -feeSats;
  if (changeSats < 10000) {
    throw new Error(
      `too few sats for test: ${fundingTotal} (needs at least 100000000 + 250 + 10000)`,
    );
  }

  let burnOutput = { memo: "", satoshis: transferSats };
  let changeOutput = {
    satoshis: changeSats,
    pubKeyHash: changeInfo.pubKeyHashHex,
  };
  let assetExtraOutput = {
    satoshis: transferSats,
    pubKeyHash: assetInfo.pubKeyHashHex,
  };
  //@ts-expect-error - TODO add types
  let assetLockScript = DashPlatform.Tx.packAssetLock({
    version: VERSION_ASSET_LOCK,
    creditOutputs: [assetExtraOutput],
  });
  let txDraft = {
    version: L1_VERSION_PLATFORM,
    type: TYPE_ASSET_LOCK,
    inputs: fundingUtxos,
    outputs: [burnOutput, changeOutput],
    extraPayload: assetLockScript,
  };
  console.log();
  console.log(`Transaction Draft:`);
  console.log(txDraft);

  txDraft.inputs.sort(DashTx.sortInputs);
  txDraft.outputs.sort(DashTx.sortOutputs);
  let vout = txDraft.outputs.indexOf(burnOutput);

  console.log();
  let txProof = DashTx.createRaw(txDraft);
  txProof.inputs[0].script = `76a914${fundingInfo.pubKeyHashHex}88ac`;
  txProof.inputs[0].sequence = "00000000"; // Non-final DashTx.NON_FINAL = "00000000"
  console.log(`Transaction Proof:`);
  console.log(txProof);

  console.log();
  //@ts-expect-error - null sigHashType
  let txProofHex = await DashTx.serialize(txProof, null);
  console.log(`Transaction Proof Hex:`);
  console.log(txProofHex);

  console.log();
  console.log(`Ready-to-Broadcast (Signed) Transaction:`);
  console.log(
    `('sendrawtransaction' via https://rpc.digitalcash.dev or https://trpc.digitalcash.dev)`,
  );
  let txSigned = await dashTx.hashAndSignAll(txDraft);
  console.log(txSigned.transaction);

  console.log();
  console.log(`Funding Outpoint Info`);
  let outpoint = await getFundingOutPoint(txSigned.transaction, vout);
  console.log(outpoint);

  console.log();
  console.log(`Funding Outpoint Hex`);
  let fundingOutPointHex = `${outpoint.txid}${outpoint.voutHex}`;
  console.log(fundingOutPointHex);

  console.log();
  console.log(`Identity Id Hex`);
  let identityId = await createIdentityId(fundingOutPointHex);
  let identityIdHex = DashTx.utils.bytesToHex(identityId);
  console.log(identityIdHex);
}

/**
 * @param {String} path
 */
async function readWif(path) {
  let wif = await Fs.readFile(path, "utf8");
  wif = wif.trim();

  return wif;
}

/**
 * @param {String} wif
 * @param {DashKeys.VERSION_PRIVATE} version - mainnet, testnet
 */
async function wifToInfo(wif, version) {
  let privateKey = await DashKeys.wifToPrivKey(wif, { version });
  let publicKey = await KeyUtils.toPublicKey(privateKey);
  let pubKeyHash = await DashKeys.pubkeyToPkh(publicKey);
  let address = await DashKeys.pkhToAddr(pubKeyHash, {
    version,
  });

  let privateKeyHex = DashKeys.utils.bytesToHex(privateKey);
  let publicKeyHex = DashKeys.utils.bytesToHex(publicKey);
  let pubKeyHashHex = DashKeys.utils.bytesToHex(pubKeyHash);

  return {
    wif,
    privateKey,
    privateKeyHex,
    publicKey,
    publicKeyHex,
    pubKeyHash,
    pubKeyHashHex,
    address,
  };
}

/**
 * @param {Hex} txSignedHex
 * @param {Uint32} outputIndex
 */
async function getFundingOutPoint(txSignedHex, outputIndex) {
  let txBytes = DashTx.utils.hexToBytes(txSignedHex);
  let txidBytes = await DashTx.doubleSha256(txBytes);
  let txidBE = DashTx.utils.bytesToHex(txidBytes);
  let voutLE = DashTx.utils.toUint32LE(outputIndex);

  return { txid: txidBE, voutHex: voutLE, vout: outputIndex };
}

/**
 * @param {Hex} fundingOutPointHex
 */
function createIdentityId(fundingOutPointHex) {
  let fundingOutPointBytes = DashTx.utils.hexToBytes(fundingOutPointHex);
  let identityHashBytes = DashTx.doubleSha256(fundingOutPointBytes);
  // let identityId = b58.encode(identityHashBytes);
  // return identityId;
  return identityHashBytes;
}

/**
 * @param {Required<Pick<DashHd.HDXKey, "privateKey"|"publicKey">>} masterKey
 * @param {Required<Pick<DashHd.HDXKey, "privateKey"|"publicKey">>} otherKey
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
      type: KEY_TYPES.ECDSA_SECP256K1,
      purpose: KEY_PURPOSES.AUTHENTICATION,
      securityLevel: KEY_LEVELS.MASTER,
      readOnly: false,
      publicKey: masterKey.publicKey,
      privateKey: masterKey.privateKey,
      data: "",
    },
    // {"$version":"0","id":1,"purpose":0,"securityLevel":1,"contractBounds":null,"type":0,"readOnly":false,"data":[2,1,70,3,1,141,196,55,100,45,218,22,244,199,252,80,228,130,221,35,226,70,128,188,179,165,150,108,59,52,56,72,226],"disabledAt":null}
    {
      id: 1,
      type: KEY_TYPES.ECDSA_SECP256K1,
      purpose: KEY_PURPOSES.AUTHENTICATION,
      securityLevel: KEY_LEVELS.CRITICAL,
      readOnly: false,
      privateKey: otherKey.privateKey,
      publicKey: otherKey.publicKey,
      data: "",
    },
  ];
  return keyDescs;

  // let privKeyDescs = [];
  // for (let keyDesc of keyDescs) {
  //   let key = await DashHd.deriveChild(
  //     identityKey,
  //     keyDesc.id,
  //     DashHd.HARDENED,
  //   );
  //   let privKeyDesc = Object.assign(keyDesc, key);
  //   privKeyDescs.push(privKeyDesc); // for type info

  //   let dppKey = new WasmDpp.IdentityPublicKey(L2_VERSION_PLATFORM);
  //   dppKey.setId(keyDesc.id);
  //   dppKey.setData(key.publicKey);
  //   if (keyDesc.purpose) {
  //     dppKey.setPurpose(keyDesc.purpose);
  //   }
  //   dppKey.setSecurityLevel(keyDesc.securityLevel);
  //   dppKeys.push(dppKey);
  // }

  // return privKeyDescs;
}

/**
 * @typedef EvoKey
 * @prop {Uint8} id
 * @prop {Uint8} type - TODO constrain to members of KEY_TYPES
 * @prop {Uint8} purpose - TODO constrain to members of KEY_PURPOSES
 * @prop {Uint8} securityLevel - TODO constrain to members of KEY_LEVELS
 * @prop {Boolean} readOnly
 * @prop {Uint8Array} publicKey
 * @prop {Uint8Array} privateKey
 */

/**
 * @typedef STKey
 * @prop {Uint8} id
 * @prop {Uint8} type - TODO constrain to members of KEY_TYPES
 * @prop {Uint8} purpose - TODO constrain to members of KEY_PURPOSES
 * @prop {Base64} data - base64-encoded publicKey (compact)
 * @prop {Uint8} securityLevel - TODO constrain to members of KEY_LEVELS
 * @prop {Boolean} readOnly
 */

/**
 * @param {Array<EvoKey>} identityKeys - TODO
 */
function getIdentityTransitionKeys(identityKeys) {
  let stKeys = [];
  for (let key of identityKeys) {
    // let data = bytesToBase64(key.publicKey);
    let stKey = {
      $version: "0",
      id: key.id,
      type: key.type,
      purpose: key.purpose,
      security_level: key.securityLevel,
      contract_bounds: null,
      // readOnly: key.readOnly,
      read_only: key.readOnly || false,
      // data: data,
      data: key.publicKey,
      // signature: "TODO",
    };
    // if ("readOnly" in key) {
    //   Object.assign(stKey, { readOnly: key.readOnly });
    // }
    stKeys.push(stKey);
  }
  return stKeys;
}

/**
 * @param {Uint8Array} bytes
 */
function bytesToBase64(bytes) {
  let binstr = "";
  for (let i = 0; i < bytes.length; i += 1) {
    binstr += String.fromCharCode(bytes[i]);
  }

  return btoa(binstr);
}

function signTransition(identity, assetLockProof, assetLockPrivateKey) {
  // TODO is assetLockProof the same as txoutproof?

  // Create ST
  const identityCreateTransition =
    WasmDpp.identity.createIdentityCreateTransition(identity, assetLockProof);

  // Create key proofs
  const [stMasterKey, stHighAuthKey, stCriticalAuthKey, stTransferKey] =
    identityCreateTransition.getPublicKeys();

  // Sign master key

  identityCreateTransition.signByPrivateKey(
    identityMasterPrivateKey.toBuffer(),
    Dpp.IdentityPublicKey.TYPES.ECDSA_SECP256K1,
  );

  stMasterKey.setSignature(identityCreateTransition.getSignature());

  identityCreateTransition.setSignature(undefined);

  // Sign high auth key

  identityCreateTransition.signByPrivateKey(
    identityHighAuthPrivateKey.toBuffer(),
    Dpp.IdentityPublicKey.TYPES.ECDSA_SECP256K1,
  );

  stHighAuthKey.setSignature(identityCreateTransition.getSignature());

  identityCreateTransition.setSignature(undefined);

  // Sign critical auth key

  identityCreateTransition.signByPrivateKey(
    identityCriticalAuthPrivateKey.toBuffer(),
    Dpp.IdentityPublicKey.TYPES.ECDSA_SECP256K1,
  );

  stCriticalAuthKey.setSignature(identityCreateTransition.getSignature());

  identityCreateTransition.setSignature(undefined);

  // Sign transfer key

  identityCreateTransition.signByPrivateKey(
    identityTransferPrivateKey.toBuffer(),
    Dpp.IdentityPublicKey.TYPES.ECDSA_SECP256K1,
  );

  stTransferKey.setSignature(identityCreateTransition.getSignature());

  identityCreateTransition.setSignature(undefined);

  // Set public keys back after updating their signatures
  identityCreateTransition.setPublicKeys([
    stMasterKey,
    stHighAuthKey,
    stCriticalAuthKey,
    stTransferKey,
  ]);

  // Sign and validate state transition

  identityCreateTransition.signByPrivateKey(
    assetLockPrivateKey,
    Dpp.IdentityPublicKey.TYPES.ECDSA_SECP256K1,
  );

  // TODO(versioning): restore
  // @ts-ignore
  // const result = await Dpp.stateTransition.validateBasic(
  //   identityCreateTransition,
  //   // TODO(v0.24-backport): get rid of this once decided
  //   //  whether we need execution context in wasm bindings
  //   new StateTransitionExecutionContext(),
  // );

  // if (!result.isValid()) {
  //   const messages = result.getErrors().map((error) => error.message);
  //   throw new Error(`StateTransition is invalid - ${JSON.stringify(messages)}`);
  // }

  return identityCreateTransition;
}

main();

/** @typedef {String} Base58 */
/** @typedef {String} Base64 */
/** @typedef {String} Hex */
/** @typedef {Number} Uint53 */
/** @typedef {Number} Uint32 */
/** @typedef {Number} Uint8 */
