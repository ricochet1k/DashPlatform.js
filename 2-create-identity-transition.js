let Fs = require("node:fs/promises");

let DashKeys = require("dashkeys");
let DashTx = require("dashtx");
let Bincode = require("./bincode.js");

let KeyUtils = require("./key-utils.js");

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

async function main() {
  // let fundingWif = await readWif("./funding.wif");
  // let fundingInfo = await wifToInfo(fundingWif, "testnet");

  // KeyUtils.set(fundingInfo.address, {
  //   address: fundingInfo.address,
  //   privateKey: fundingInfo.privateKey,
  //   publicKey: fundingInfo.publicKey,
  //   pubKeyHash: fundingInfo.pubKeyHashHex,
  // });

  // let changeWif = await readWif("./change.wif");
  // let changeInfo = await wifToInfo(changeWif, "testnet");

  let assetWif = await readWif("./asset.wif");
  let assetInfo = await wifToInfo(assetWif, "testnet");

  let masterWif = await readWif("./master.wif");
  let masterInfo = await wifToInfo(masterWif, "testnet");

  let otherWif = await readWif("./other.wif");
  let otherInfo = await wifToInfo(otherWif, "testnet");

  let identityIdHex = await readHex("./identity-id.hex");

  let txlocksigHex = await readHex("./rawtxlocksig.hex");
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
    vout = txlocksig.outputs.findIndex(function (output) {
      //@ts-expect-error
      return output.script === "6a00"; // TODO match the burn
    });
    console.log(txlocksig.outputs);
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

  // let txid = await DashTx.utils.rpc(
  //   rpcAuthUrl,
  //   "sendrawtransaction",
  //   txSigned.transaction,
  // );

  // const INSTANT_ALP = 0;
  // const CHAIN_ALP = 1;

  // let blockchaininfo = await DashTx.utils.rpc(rpcAuthUrl, "getblockchaininfo");
  // let nextBlock = blockchaininfo.blocks + 1;

  // TODO - AJ is here

  /** @param {any} magicZmqEmitter */
  async function getAssetLockInstantProof(magicZmqEmitter) {
    let assetLockInstantProof = {
      // type: INSTANT_ALP,
      instant_lock: DashTx.utils.hexToBytes(instantLockSigHex),
      transaction: DashTx.utils.hexToBytes(instantLockTxHex), // TODO this may need the proof, not the signed tx
      // output_index: DashTx.utils.hexToBytes(vout),
      output_index: vout,
    };
    return assetLockInstantProof;
  }

  async function getAssetLockChainProof() {
    let assetLockChainProof = {
      // type: CHAIN_ALP,
      core_chain_locked_height: nextBlock,
      // out_point: fundingOutPointHex,
      out_point: {
        txid: outpoint.txid,
        vout: vout,
      },
    };
    return assetLockChainProof;
  }

  let assetLockProof;
  let weEvenKnowHowToGetIsdlock = true;
  if (weEvenKnowHowToGetIsdlock) {
    assetLockProof = await getAssetLockInstantProof(null);
  } else {
    assetLockProof = await getAssetLockChainProof();
  }

  let identityKeys = await getKnownIdentityKeys(
    { privateKey: masterInfo.privateKey, publicKey: masterInfo.publicKey },
    { privateKey: otherInfo.privateKey, publicKey: otherInfo.publicKey },
  );
  let stKeys = await getIdentityTransitionKeys(identityKeys);

  let stateTransition = {
    //protocolVersion: L2_VERSION_PLATFORM,
    $version: L2_VERSION_PLATFORM.toString(),
    type: ST_CREATE_IDENTITY,
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
    user_fee_increase: 0,
  };
  console.log(`stKeys:`);
  console.log(stKeys);

  let bcAb = Bincode.encode(Bincode.StateTransition, stateTransition, {
    signable: true,
  });
  console.log(`bc (ready-to-sign) AB:`, bcAb);
  let bc = new Uint8Array(bcAb);
  console.log(`bc (ready-to-sign):`);
  console.log(DashTx.utils.bytesToHex(bc));
  console.log(bytesToBase64(bc));

  let ethBytes = await KeyUtils.signEth(assetInfo.privateKey, bc);
  // let sigHex = DashTx.utils.bytesToHex(sigBytes);
  Object.assign(stateTransition, {
    identity_id: DashTx.utils.hexToBytes(identityIdHex),
    // signature: sigHex,
    signature: ethBytes,
  });
  for (let i = 0; i < identityKeys.length; i += 1) {
    let key = identityKeys[i];
    let stPub = stateTransition.public_keys[i];
    let ethBytes = await KeyUtils.signEth(key.privateKey, bc);
    // let sigHex = DashTx.utils.bytesToHex(sigBytes);
    Object.assign(stPub, {
      // signature: sigHex,
      signature: ethBytes,
    });
  }

  console.log(JSON.stringify(stateTransition, null, 2));

  {
    let bcAb = Bincode.encode(Bincode.StateTransition, stateTransition, {
      signable: false,
    });
    let bc = new Uint8Array(bcAb);
    console.log(`bc (signed):`);
    console.log(DashTx.utils.bytesToHex(bc));
    console.log(bytesToBase64(bc));
  }

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

main();

/** @typedef {String} Base58 */
/** @typedef {String} Base64 */
/** @typedef {String} Hex */
/** @typedef {Number} Uint53 */
/** @typedef {Number} Uint32 */
/** @typedef {Number} Uint8 */
