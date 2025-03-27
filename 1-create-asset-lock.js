import Fs from "node:fs/promises";

import Dotenv from "dotenv";
import DashPhrase from "dashphrase";
import DashHd from "dashhd";
import * as DashHdUtils from "./dashhd-utils.js";
import DashKeys from "dashkeys";
import * as DashTx from "dashtx/dashtx.js";
import * as DashPlatform from "./dashplatform.js";
import * as Bincode from "./bincode.ts";
import * as DashBincode from "./1.8.1/generated_bincode.js";
import * as QRCode from "./_qr.js";
import * as KeyUtils from "./key-utils.js";
import { OP } from "./opcodes.ts";
import * as Scripts from "./scripts.ts";

import Thingy from "./2-create-identity-transition.js";

import EventSourcePackage from "launchdarkly-eventsource";
import { toHex } from "./hex.js"

Dotenv.config({ path: ".env" });

let EventSourceShim = EventSourcePackage.EventSource;

// let DapiGrpc = require("@dashevo/dapi-grpc");
// let WasmDpp = require("@dashevo/wasm-dpp");
// let Dpp = WasmDpp.DashPlatformProtocol;

//@ts-ignore - sssssh, yes Base58 does exist
// let b58 = DashKeys.Base58.create();

let rpcAuthUrl = "https://api:null@trpc.digitalcash.dev";
let zmqUuid = crypto.randomUUID();
let zmqAuthUrl = `https://tzmq.digitalcash.dev/api/zmq/eventsource/${zmqUuid}`;

const L1_VERSION_PLATFORM = 3;
// const L1_VERSION_PLATFORM = 0;
const TYPE_ASSET_LOCK = 8;
const VERSION_ASSET_LOCK = 1;
// const L2_VERSION_PLATFORM = 1; // actually constant "0" ??
// const ST_CREATE_IDENTITY = 2;

let VERSIONS_TESTNET = ["8c", "ef"];

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
  let coinType = 5;
  let testnet = true; // TODO
  if (testnet) {
    coinType = 1;
  }

  // void (await WasmDpp.default());

  let walletPhrase = process.env.DASH_WALLET_PHRASE;
  let walletSalt = process.env.DASH_WALLET_SALT ?? "";
  if (!walletPhrase) {
    console.error("");
    console.error("ERROR");
    console.error("   'DASH_WALLET_PHRASE' is not set");
    console.error("");
    console.error("SOLUTION");
    let newPhrase = await DashPhrase.generate();
    console.error(`   echo 'DASH_WALLET_PHRASE="${newPhrase}"' >> .env`);
    console.error(`   echo 'DASH_WALLET_SALT=""' >> .env`);
    console.error("");
    process.exit(1);
    return;
  }

  let identityIndexStr = process.argv[2];
  let identityIndex = parseInt(identityIndexStr, 10);
  if (isNaN(identityIndex)) {
    console.error("");
    console.error("USAGE");
    console.error("   ./demo.js <identity-index>");
    console.error("");
    console.error("EXAMPLE");
    console.error("   ./demo.js 0");
    console.error("");
    process.exit(1);
    return;
  }

  let seed = await DashPhrase.toSeed(walletPhrase, walletSalt);
  let walletKey = await DashHd.fromSeed(seed);

  let hdOpts = { version: "testnet" }; // TODO

  let regFundAddressPath = `m/9'/${coinType}'/5'/1'/${identityIndex}`;
  let regFundKey = await DashHdUtils.deriveIdentRegFundKeyPath(
    walletKey,
    regFundAddressPath,
  );

  let assetKey = await DashHd.deriveChild(regFundKey, 0, DashHd.HARDENED);
  let assetWif = await DashHd.toWif(assetKey.privateKey, hdOpts);
  let assetInfo = await wifToInfo(assetWif, "testnet");
  console.log("Asset WIF", assetWif, "(would be ephemeral, non-hd)");
  // TODO the asset wif isn't used that way...
  // {
  //   let assetDeltas = await DashTx.utils.rpc(rpcAuthUrl, "getaddressdeltas", {
  //     addresses: [assetInfo.address],
  //   });
  //   let memDeltas = await DashTx.utils.rpc(rpcAuthUrl, "getaddressmempool", {
  //     addresses: [assetInfo.address],
  //   });
  //   let isUsed = assetDeltas.length > 0 || memDeltas.length;
  //   if (isUsed) {
  //     throw new Error(`asset key has been used`);
  //   }
  // }

  let topupAddressPath = `m/9'/${coinType}'/5'/2'/0`;
  let topupKey = await DashHdUtils.deriveIdentTopupKeyPath(
    walletKey,
    topupAddressPath,
  );

  let { identityIdHex, txidHex, assetProof } = await createPlatformAssetLock(
    hdOpts,
    regFundKey,
    topupKey, // TODO next change key from wallet
    assetInfo,
  );

  let txlocksigHex;
  let txCore;
  if (assetProof.data.raw) {
    txlocksigHex = assetProof.data.raw;
  } else if (assetProof.data.vin) {
    txCore = assetProof.data;
  } else {
    console.log(`DEBUG assetProof`);
    console.log(assetProof);
    throw new Error("internal error: no acceptable asset proof");
  }

  console.log();
  console.log(`txidHex: `, txidHex);
  console.log(`identityIdHex:`, identityIdHex);
  console.log(`txlocksigHex:`, txlocksigHex);
  console.log(`txCore:`, txCore);

  let authWalletPath = `m/9'/${coinType}'/5'/0'/0'/${identityIndex}'`;
  let authWallet = await DashHdUtils.deriveIdentAuthWalletPath(
    walletKey,
    authWalletPath,
  );
  let masterKey = await authWallet.deriveAuthKey(0);
  let otherKey = await authWallet.deriveAuthKey(1);

  await Fs.writeFile('ready-to-thingy-dostuff.json', JSON.stringify({
    assetKey,
    masterKey,
    otherKey,
    identityIdHex,
    txidHex,
    txlocksigHex,
    txCore,
  }, (key, val) => {
    if (val instanceof Uint8Array || val instanceof ArrayBuffer) {
      return {'@Uint8Array hex': DashTx.utils.bytesToHex(new Uint8Array(val))}
    }
    return val
  }, 2));

  await Thingy.doStuff(
    assetKey,
    masterKey,
    otherKey,
    identityIdHex,
    txidHex,
    txlocksigHex,
    txCore,
  );
  // walletKey, coinType, identityIndex
}

/**
 * @param {import('dashhd').HDToAddressOpts} hdOpts
 * @param {import('dashhd').HDKey} regFundKey
 * @param {import('dashhd').HDKey} changeKey
 * @param {{publicKey: Uint8Array}} assetInfo
 */
async function createPlatformAssetLock(
  hdOpts,
  regFundKey,
  changeKey,
  assetInfo,
) {
  let dashTx = DashTx.create(KeyUtils);

  if (!regFundKey.privateKey) {
    throw new Error("'regFundKey' is missing 'privateKey'");
  }
  let fundingWif = await DashHd.toWif(regFundKey.privateKey, hdOpts);
  let fundingInfo = await wifToInfo(fundingWif, "testnet");
  {
    let fundingDeltas = await DashTx.utils.rpc(rpcAuthUrl, "getaddressdeltas", {
      addresses: [fundingInfo.address],
    });
    let memDeltas = await DashTx.utils.rpc(rpcAuthUrl, "getaddressmempool", {
      addresses: [fundingInfo.address],
    });
    let totalUses = fundingDeltas.length + memDeltas.length;
    if (totalUses >= 2) {
      throw new Error(`funding key has been used 2+ times`);
    }
  }

  KeyUtils.set(fundingInfo.address, {
    address: fundingInfo.address,
    privateKey: fundingInfo.privateKey,
    publicKey: fundingInfo.publicKey,
    pubKeyHash: fundingInfo.pubKeyHashHex,
  });

  if (!changeKey.privateKey) {
    throw new Error("'topupKey' is missing 'privateKey'");
  }
  let changeWif = await DashHd.toWif(changeKey.privateKey, hdOpts);
  let changeInfo = await wifToInfo(changeWif, "testnet");

  let fundingUtxos = await TODOgetUtxos([fundingInfo.address]);
  for (let utxo of fundingUtxos) {
    utxo.squence = "00000000"; // ??
  }

  // TODO list transactions from funding address and check for
  //      - check the funding address for transactions
  let fundingTotal = DashTx.sum(fundingUtxos);
  console.log();
  console.log(`funding utxos (${fundingTotal})`);
  console.log(fundingUtxos);

  let transferSats = 100000000;
  let feeSats = 500; // enough for 1 input and 2 outputs + extrapayload
  let changeSats = fundingTotal + -transferSats + -feeSats;

  let burnOutput = { memo: "", satoshis: transferSats };

  /** @type {Array<import('dashtx').TxOutput>} */
  let outputs = [burnOutput];
  if (changeSats >= 10000) {
    outputs.push({
      satoshis: changeSats,
      pubKeyHash: changeInfo.pubKeyHashHex,
    });
  } else if (changeSats < 250) {
    let needSats = 250 - changeSats;
    promptQr(fundingInfo.address, needSats);
    process.exit(1);
    // throw new Error(
    //   `too few sats for test: ${fundingTotal} (needs at least 100000000 + 250 + 10000)`,
    // );
  }

  // Comes from new_p2pkh
  // TODO: hash160?!
  let pubkeyhash = await KeyUtils.pubkeyHash(assetInfo.publicKey);
  // let script = Scripts.makeP2PKH(pubkeyhash)
  // console.log('assetInfo.publicKey', toHex(assetInfo.publicKey));
  // console.log('pubkeyhash', toHex(pubkeyhash));
  // console.log('p2pkh script', toHex(script));
  // let assetLockPayload = DashBincode.AssetLockPayload({
  //   version: VERSION_ASSET_LOCK,
  //   credit_outputs: [DashBincode.TxOut({
  //     value: BigInt(transferSats),
  //     script_pubkey: DashBincode.ScriptBuf(script),
  //   })]
  // })
  // let assetLockPayloadBytes = Bincode.encode(DashBincode.AssetLockPayload, assetLockPayload);
  // let assetLockPayloadHex = DashTx.utils.bytesToHex(new Uint8Array(assetLockPayloadBytes));

  /** @type {DashTx.TxOutput} */
  let assetExtraOutput = {
    satoshis: transferSats,
    pubKeyHash: DashTx.utils.bytesToHex(pubkeyhash),
  };
  let assetLockScript = DashPlatform.packAssetLock({
    version: VERSION_ASSET_LOCK,
    creditOutputs: [assetExtraOutput],
  });

  console.log('assetLockScript      ', assetLockScript);
  // console.log('assetLockPayloadBytes', assetLockPayloadHex);

  let txDraft = {
    version: L1_VERSION_PLATFORM,
    type: TYPE_ASSET_LOCK,
    inputs: fundingUtxos,
    outputs: outputs, // burnOutput, changeOutput
    extraPayload: assetLockScript,
  };
  console.log();
  console.log(`Transaction Draft:`);
  console.log(txDraft);

  // to guarantee order
  // txDraft.inputs.sort(DashTx.sortInputs);
  // txDraft.outputs.sort(DashTx.sortOutputs);
  let vout = txDraft.outputs.indexOf(burnOutput);

  console.log(`DEBUG fundingInfo`, fundingInfo);

  console.log();
  let txProof = DashTx.createRaw(txDraft);
  // // @ts-expect-error - TxInputRaw is returned, transform to TxInputForSig?
  // txProof.inputs[0].script = DashTx.utils.bytesToHex(new Uint8Array([OP.OP_RETURN])); //`76a914${fundingInfo.pubKeyHashHex}88ac`;
  txProof.inputs[0].sequence = "00000000"; // Non-final DashTx.NON_FINAL = "00000000"
  console.log(`Transaction Proof:`);
  console.log(txProof);

  console.log();
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

  // process.exit(1);
  console.log();
  console.log(
    `IMPORTANT: before broadcast, listen to 'rawtxlocksig' on https://tzmq.digitalcash.dev`,
  );

  console.log();
  console.log(`Funding Outpoint Info (BE, internal)`);
  let outpoint = await getFundingOutPoint(txSigned.transaction, vout);
  console.log(outpoint);

  let txidHex = await DashTx.utils.rpc(
    rpcAuthUrl,
    "sendrawtransaction",
    txSigned.transaction,
  );
  console.log("DEBUG send result (txidHex) (LE, for RPC)", txidHex);

  let assetProof;
  {
    // let assetInstantEvent = startEventSource(
    //   zmqAuthUrl,
    //   "rawtxlocksig",
    //   createCheckDataIsProof(txSigned),
    // );
    let assetChainPoll = pollAssetLockChainProof(txidHex);
    assetProof = await Promise.race([
      // assetInstantEvent.promise,
      assetChainPoll.promise,
    ]);
    // assetInstantEvent.source.close();
    assetChainPoll.source.close();
  }

  console.log();
  console.log(`Funding Outpoint Hex`);
  let fundingOutPointHex = `${outpoint.txid}${outpoint.voutHex}`;
  console.log(fundingOutPointHex);

  let identityId = await createIdentityId(fundingOutPointHex);
  let identityIdHex = DashTx.utils.bytesToHex(identityId);

  return {
    txidHex,
    identityIdHex,
    assetProof,
  };
}

/**
 * @param {String} fundingAddress
 * @param {Number} needSats
 */
function promptQr(fundingAddress, needSats) {
  let dashAmount = DashTx.toDash(needSats);
  let content = `dash:${fundingAddress}?amount=${dashAmount}`;
  let ascii = QRCode.ascii(content, {
    indent: 3,
    padding: 4,
    width: 256,
    height: 256,
    color: "#000000",
    background: "#ffffff",
    ecl: "M",
  });
  console.error();
  console.error(`ERROR`);
  console.error(
    `   not enough DASH at funding address (including instant send)`,
  );
  console.error();
  console.error(`SOLUTION`);
  console.error(`   send ${dashAmount} to ${fundingAddress}`);
  console.error(``);
  console.error(ascii);
  console.error();
}

/**
 * @param {import('dashtx').TxInfoSigned} txProofSigned
 * @returns {CheckData}
 */
function createCheckDataIsProof(txProofSigned) {
  /**
   * @param {Object.<String, any>} txlocksig
   */
  async function checkDataIsProof(txlocksig) {
    if (!txlocksig?.raw) {
      console.warn(`unknown data:`, txlocksig);
      return false;
    }

    return txlocksig.raw.startsWith(txProofSigned.transaction);
  }

  return checkDataIsProof;
}

/**
 * @param {String} txidHex
 */
function pollAssetLockChainProof(txidHex) {
  let isActive = true;
  /** @type {any} */
  let timeoutToken;

  /**
   * @param {any} token
   */
  function setTimeoutToken(token) {
    timeoutToken = token;
  }

  let promise = new Promise(async function (resolve) {
    for (;;) {
      console.log("Fetch (rawtransaction): sleeping for 15s...");
      await sleep(15000, setTimeoutToken);

      if (!isActive) {
        resolve(null);
        return;
      }
      // TODO DashTx.TxCoreInfo
      let txCore = await getTransactionJson(txidHex);
      if (txCore) {
        resolve({
          source: "rawtransaction",
          data: txCore,
        });
        return;
      }
    }
  });

  let source = {
    close: function () {
      isActive = false;
      clearTimeout(timeoutToken);
    },
  };

  return {
    promise,
    source,
  };
}

/**
 * @param {HexString} txidHex
 */
async function getTransactionJson(txidHex) {
  const E_NO_TX = -5;
  let getJson = true;

  let txInfo = await DashTx.utils
    .rpc(rpcAuthUrl, "getrawtransaction", txidHex, getJson)
    .catch(
      /** @param {Error} err */
      function (err) {
        //@ts-expect-error - it may have .code
        if (err.code === E_NO_TX) {
          return null;
        }
        throw err;
      },
    );
  if (!txInfo?.vout) {
    return null;
  }

  return txInfo;
}

/**
 * @param {Uint32} ms
 * @param {Function} setTimeoutToken
 */
async function sleep(ms, setTimeoutToken) {
  return await new Promise(function (resolve) {
    let token = setTimeout(resolve, ms);
    if (token.unref) {
      token.unref();
    }
    if (setTimeoutToken) {
      setTimeoutToken(token);
    }
  });
}

/**
 * @callback CheckData
 * @param {String} message
 * @returns {Promise<Boolean>}
 */

/**
 * @param {String} url
 * @param {String} eventName
 * @param {CheckData} checkData
 */
function startEventSource(url, eventName, checkData) {
  let isActive = true;

  let tickerHeartbeatMs = 5 * 1000;
  // in case of a network hiccup lasting several seconds
  let tickerHeartbeatTimeout = 3 * tickerHeartbeatMs;
  let source = new EventSourceShim(url, {
    readTimeoutMillis: tickerHeartbeatTimeout,
  });
  let promise = new Promise(async function (resolve, reject) {
    let basicAuth = btoa(`api:null`);
    let resp = await fetch(zmqAuthUrl, {
      method: "PUT",
      headers: {
        Authorization: `Basic ${basicAuth}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ topics: ["debug:ticker", eventName] }),
    }).catch(reject);
    if (!resp) {
      // rejected;
      return null;
    }

    let result = await resp.text();
    console.log(`[DEBUG] status: ${result}`);

    /** @param {MessageEvent} event */
    async function onMessage(event) {
      if (!isActive) {
        console.log("EventSource: received message after close");
        source.close();
        return;
      }

      console.log(`DEBUG MessageEvent`, event);
      let data = JSON.parse(event.data);

      let isValidData = await checkData(data).catch(function (err) {
        console.error(`error checking event source data`);
        console.error(err);
        return false;
      });
      if (!isValidData) {
        return;
      }

      resolve({
        source: "txlocksig",
        data: data,
      });
      source.close();
    }

    console.log(`EventSource: listening for debug:ticker`);
    source.addEventListener("debug:ticker", function (/** @type {any} */ event) {
      console.log("EventSource: ticker", event);
    });
    if (eventName) {
      console.log(`EventSource: listening for ${eventName}`);
      source.addEventListener(eventName, onMessage);
    } else {
      console.log(`EventSource: listening for all messages`);
      source.addEventListener("message", onMessage);
    }

    source.addEventListener("error", function (/** @type {any} */ err) {
      if (!isActive) {
        console.log("EventSource: received error after close (probably okay)");
        source.close();
        return;
      }

      console.error("error: disconnected from EventSource", err);
      // TODO reconnect?
    });

    source.addEventListener("close", function () {
      console.log("DEBUG: closed EventSource");
    });
  });

  return {
    promise: promise,
    source: {
      close: function () {
        isActive = false;
        source.close();
      },
    },
  };
}

/**
 * @typedef Delta
 * @prop {String} txid
 * @prop {Uint32} index
 * @prop {String} pubKeyHash
 * @prop {String} address
 * @prop {Uint32} satoshis
 */

/**
 * THIS IS PROBABLY WRONG
 * We'd actually need to do getaddresstxids, getrawtransaction, getaddressutxos, getaddressmempool to get all of the data to pair the coins properly
 * @param {Array<String>} addresses
 */
export const TODOgetUtxos = async function (addresses) {
  // let oldDeltas = await DashTx.utils.rpc(rpcAuthUrl, "getaddressdeltas", {
  let utxos = await DashTx.utils.rpc(rpcAuthUrl, "getaddressutxos", {
    addresses: addresses,
  });
  console.log(`DEBUG utxos`);
  console.log(utxos);

  let memDeltas = await DashTx.utils.rpc(rpcAuthUrl, "getaddressmempool", {
    addresses: addresses,
  });

  let oldTotal = DashTx.sum(utxos);
  let newTotal = DashTx.sum(memDeltas);
  let total = newTotal + oldTotal;
  if (total === 0) {
    return [];
  } else if (total < 0) {
    throw new Error("sanity fail: double spend detected");
  }

  for (let delta of memDeltas) {
    if (delta.satoshis < 0) {
      throw new Error(
        "dev error: reconciling instant-send debits is not yet supported",
      );
    }

    // TODO expose decodeUnchecked(), rename 'pubKeyHash' (data) to 'hex'
    let pubKeyHashCheck = DashKeys._dash58check.decode(delta.address, {
      //@ts-expect-error
      versions: VERSIONS_TESTNET,
    });
    let utxo = {
      address: delta.address,
      //@ts-expect-error - needs better abstraction
      pubKeyHash: pubKeyHashCheck.pubKeyHash,
      txid: delta.txid,
      outputIndex: delta.index,
      satoshis: delta.satoshis,
      //@ts-expect-error - needs better abstraction
      script: `76a914${pubKeyHashCheck.pubKeyHash}88ac`,
    };
    utxos.push(utxo);
  }

  return utxos;
};

// /**
//  * @param {String} path
//  */
// async function readWif(path) {
//   let wif = await Fs.readFile(path, "utf8");
//   wif = wif.trim();

//   return wif;
// }

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

  let info = {
    wif,
    privateKey,
    privateKeyHex,
    publicKey,
    publicKeyHex,
    pubKeyHash,
    pubKeyHashHex,
    address,
  };
  // console.log(info);
  // process.exit(1);
  return info;
}

/**
 * @param {HexString} txSignedHex
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
 * @param {HexString} fundingOutPointHex
 */
function createIdentityId(fundingOutPointHex) {
  let fundingOutPointBytes = DashTx.utils.hexToBytes(fundingOutPointHex);
  let identityHashBytes = DashTx.doubleSha256(fundingOutPointBytes);
  // let identityId = b58.encode(identityHashBytes);
  // return identityId;
  return identityHashBytes;
}

main();

/** @typedef {String} Base58 */
/** @typedef {String} Base64 */
/** @typedef {String} HexString */
/** @typedef {Number} Uint53 */
/** @typedef {Number} Uint32 */
/** @typedef {Number} Uint8 */
