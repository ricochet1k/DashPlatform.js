"use strict";

let DashPhrase = require("dashphrase");
let DashHd = require("dashhd");
let DashKeys = require("dashkeys");
let DashTx = require("dashtx");
let DashPlatform = require("./dashplatform.js");
let CBOR = require("cbor");

let KeyUtils = require("./key-utils.js");

// let DapiGrpc = require("@dashevo/dapi-grpc");
let WasmDpp = require("@dashevo/wasm-dpp");
let Dpp = WasmDpp.DashPlatformProtocol;

//@ts-ignore - sssssh, yes Base58 does exist
let b58 = DashKeys.Base58.create();

let rpcAuthUrl = "https://api:null@trpc.digitalcash.dev";

const L1_VERSION_PLATFORM = 3;
const TYPE_ASSET_LOCK = 8;
const L2_VERSION_PLATFORM = 1;
const ST_CREATE_IDENTITY = 2;

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
  void (await WasmDpp.default());

  let dashTx = DashTx.create(KeyUtils);

  // let phrase = await DashPhrase.generate();
  let phrase =
    "wool panel expand embrace try lab rescue reason drop fog stand kangaroo";
  console.log(`Phrase:`);
  console.log(phrase);
  let salt = "";
  let seedBytes = await DashPhrase.toSeed(phrase, salt);
  console.log("Seed:");
  console.log(DashTx.utils.bytesToHex(seedBytes));
  let walletKey = await DashHd.fromSeed(seedBytes, { coinType });
  let walletId = await DashHd.toId(walletKey);
  console.log(`Wallet ID:`);
  console.log(walletId);

  let accountIndex = 0; // pick the desired account for paying the fee
  let addressIndex = 0; // pick an address with funds
  let accountKey;
  for (let a = 0; a <= accountIndex; a += 1) {
    accountKey = await walletKey.deriveAccount(a);

    for (let usage of [DashHd.RECEIVE, DashHd.CHANGE]) {
      let xprvKey = await accountKey.deriveXKey(usage);

      let addressKey;
      let addr;
      let pkh;
      let wif;
      for (let i = 0; i <= addressIndex; i += 1) {
        addressKey = await xprvKey.deriveAddress(i);
        if (!addressKey.privateKey) {
          throw new Error("not an error, just a lint hack");
        }

        addr = await DashHd.toAddr(addressKey.publicKey, { version: network });
        let pkhBytes = await DashKeys.addrToPkh(addr, {
          //@ts-ignore
          version: network,
        });
        pkh = DashKeys.utils.bytesToHex(pkhBytes);
        wif = await DashHd.toWif(addressKey.privateKey, { version: network });
        console.log();
        console.log(
          `[m/44'/${coinType}'/${a}'/${usage}/${i}] Address: ${addr}`,
        );
        // TODO is _this_ the assetLockPrivateKey??
        console.log(`[m/44'/${coinType}'/${a}/${usage}/${i}] WIF: ${wif}`);
      }
    }
  }

  process.exit(1);

  KeyUtils.set(addr, {
    address: addr,
    publicKey: addressKey.publicKey,
    privateKey: addressKey.privateKey,
    pubKeyHash: pkh,
  });

  let utxos = await DashTx.utils.rpc(rpcAuthUrl, "getaddressutxos", {
    addresses: [addr],
  });
  let total = DashTx.sum(utxos);
  console.log();
  console.log(`utxos (${total})`);
  console.log(utxos);

  // TODO which hd paths to use for which addresses?
  let creditOutputs = [{ satoshis: total - 10000, pubKeyHash: pkh }];
  let totalCredits = DashTx.sum(creditOutputs);
  let burnOutput = { satoshis: totalCredits, pubKeyHash: pkh };
  //@ts-ignore - TODO add types
  let assetLockScript = DashPlatform.Tx.packAssetLock({
    creditOutputs,
  });

  let txDraft = {
    version: L1_VERSION_PLATFORM,
    type: TYPE_ASSET_LOCK,
    inputs: utxos,
    outputs: [burnOutput],
    extraPayload: assetLockScript,
  };
  console.log();
  console.log(`txDraft:`);
  console.log(txDraft);

  txDraft.inputs.sort(DashTx.sortInputs);
  txDraft.outputs.sort(DashTx.sortOutputs);
  let vout = txDraft.outputs.indexOf(burnOutput);

  let txSigned = await dashTx.hashAndSignAll(txDraft);
  console.log();
  console.log(`txSigned:`);
  console.log(txSigned);

  // let txid = await DashTx.utils.rpc(
  //   rpcAuthUrl,
  //   "sendrawtransaction",
  //   txSigned.transaction,
  // );

  const INSTANT_ALP = 0;
  const CHAIN_ALP = 1;

  let blockchaininfo = await DashTx.utils.rpc(rpcAuthUrl, "getblockchaininfo");
  let nextBlock = blockchaininfo.blocks + 1;

  let fundingOutPointHex = await getFundingOutPointHex(
    txSigned.transaction,
    vout,
  );
  let identityId = createIdentityId(fundingOutPointHex);

  /** @param {any} magicZmqEmitter */
  async function getAssetLockInstantProof(magicZmqEmitter) {
    let assetLockInstantProof = {
      type: INSTANT_ALP,
      instantLock: await magicZmqEmitter.once(
        "zmqpubrawtxlocksig",
        /** @param {any} instantLock */
        function (instantLock) {
          return instantLock.toBase64();
        },
      ),
      transaction: txSigned.transaction,
      outputIndex: vout,
    };
    return assetLockInstantProof;
  }

  async function getAssetLockChainProof() {
    let assetLockChainProof = {
      type: CHAIN_ALP,
      coreChainLockedHeight: nextBlock,
      outPoint: fundingOutPointHex,
    };
    return assetLockChainProof;
  }

  let assetLockProof;
  let weEvenKnowHowToGetIsdlock = false;
  if (weEvenKnowHowToGetIsdlock) {
    assetLockProof = await getAssetLockInstantProof(null);
  } else {
    assetLockProof = await getAssetLockChainProof();
  }

  let idIndex = 0; // increment to first unused
  let identityKeys = await getIdentityKeys(walletKey, idIndex);
  let stKeys = await getIdentityTransitionKeys(identityKeys);

  let stateTransition = {
    protocolVersion: L2_VERSION_PLATFORM,
    type: ST_CREATE_IDENTITY,
    // ecdsaSig(assetLockPrivateKey, CBOR(thisStateTransition))
    // "signature":"IBTTgge+/VDa/9+n2q3pb4tAqZYI48AX8X3H/uedRLH5dN8Ekh/sxRRQQS9LaOPwZSCVED6XIYD+vravF2dhYOE=",
    assetLockProof: assetLockProof,
    publicKeys: stKeys,
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
  };
  console.log(`stKeys:`);
  console.log(stKeys);

  let cbor = CBOR.encodeCanonical(stateTransition);
  console.log(`cbor:`);
  console.log(DashTx.utils.bytesToHex(cbor));
  console.log(bytesToBase64(cbor));

  let sigBytes = await KeyUtils.sign(addressKey.privateKey, cbor);
  let sigHex = DashTx.utils.bytesToHex(sigBytes);
  Object.assign(stateTransition, {
    signature: sigHex,
  });
  console.log(JSON.stringify(stateTransition, null, 2));

  // let identityId = assetLockProof.createIdentifier();
  // let identity = Dpp.identity.create(identityId, dppKeys);
  // let signedTransition = signTransition(
  //   identity,
  //   assetLockProof,
  //   assetLockPrivateKeyBuffer,
  // );

  console.log("");
  console.log("TODO");
  console.log(`  - how to serialize and broadcast transition via grpc?`);
}

/**
 * @param {Hex} txSignedHex
 * @param {Uint32} outputIndex
 */
async function getFundingOutPointHex(txSignedHex, outputIndex) {
  let txBytes = DashTx.utils.hexToBytes(txSignedHex);
  let txidBytes = await DashTx.doubleSha256(txBytes);
  let txidBE = DashTx.utils.bytesToHex(txidBytes);
  let voutLE = DashTx.utils.toUint32LE(outputIndex);

  let fundingOutPointHex = `${txidBE}${voutLE}`;
  return fundingOutPointHex;
}

/**
 * @param {Hex} fundingOutPointHex
 */
function createIdentityId(fundingOutPointHex) {
  let fundingOutPointBytes = DashTx.utils.hexToBytes(fundingOutPointHex);
  let identityHashBytes = DashTx.doubleSha256(fundingOutPointBytes);
  let identityId = b58.encode(identityHashBytes);
  return identityId;
}

/**
 * @param {DashHd.HDKey} walletKey
 * @param {Uint53} idIndex
 * @returns {Promise<Array<EvoKey>>}
 */
async function getIdentityKeys(walletKey, idIndex) {
  let identityEcdsaKey = await DashHd.derivePath(walletKey, identityEcdsaPath);
  let identityKey = await DashHd.deriveChild(
    identityEcdsaKey,
    idIndex,
    DashHd.HARDENED,
  );

  let keyDescs = [
    {
      id: 0,
      type: KEY_TYPES.ECDSA_SECP256K1,
      purpose: KEY_PURPOSES.AUTHENTICATION,
      data: "",
      securityLevel: KEY_LEVELS.MASTER,
      // readOnly: false,
    },
    {
      id: 1,
      type: KEY_TYPES.ECDSA_SECP256K1,
      purpose: KEY_PURPOSES.AUTHENTICATION,
      data: "",
      securityLevel: KEY_LEVELS.HIGH,
      // readOnly: false,
    },
    {
      id: 2,
      type: KEY_TYPES.ECDSA_SECP256K1,
      purpose: KEY_PURPOSES.AUTHENTICATION,
      data: "",
      securityLevel: KEY_LEVELS.CRITICAL,
      // readOnly: false,
    },
    {
      id: 3,
      type: KEY_TYPES.ECDSA_SECP256K1,
      purpose: KEY_PURPOSES.TRANSFER,
      data: "",
      securityLevel: KEY_LEVELS.CRITICAL,
      // readOnly: false,
    },
  ];

  for (let keyDesc of keyDescs) {
    let key = await DashHd.deriveChild(
      identityKey,
      keyDesc.id,
      DashHd.HARDENED,
    );
    Object.assign(keyDesc, key);

    // let dppKey = new WasmDpp.IdentityPublicKey(L2_VERSION_PLATFORM);
    // dppKey.setId(keyDesc.id);
    // dppKey.setData(key.publicKey);
    // if (keyDesc.purpose) {
    //   dppKey.setPurpose(keyDesc.purpose);
    // }
    // dppKey.setSecurityLevel(keyDesc.securityLevel);
    // dppKeys.push(dppKey);
  }

  return keyDescs;
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
    let data = bytesToBase64(key.publicKey);
    let stKey = {
      id: key.id,
      type: key.type,
      purpose: key.purpose,
      securityLevel: key.securityLevel,
      data: data,
      // readOnly: key.readOnly,
    };
    if ("readOnly" in key) {
      Object.assign(stKey, { readOnly: key.readOnly });
    }
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
