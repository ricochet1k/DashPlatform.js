import Fs from "node:fs/promises";

import DashHd from "dashhd";
import * as DashHdUtils from "./dashhd-utils.js";
import DashKeys from "dashkeys";
import * as DashTx from "dashtx/dashtx.js";
import * as DashPlatform from "./dashplatform.js";
import * as QRCode from "./_qr.js";
import * as KeyUtils from "./key-utils.js";

import { createIdentityFromAssetLock } from "./2-create-identity-transition.js";

import { loadWallet } from "./cli.js"
import { deriveAllCreateIdentityKeys } from "./asset_lock.js"
import { createPlatformAssetLock } from "./asset_lock.js"
// let DapiGrpc = require("@dashevo/dapi-grpc");
// let WasmDpp = require("@dashevo/wasm-dpp");
// let Dpp = WasmDpp.DashPlatformProtocol;

//@ts-ignore - sssssh, yes Base58 does exist
// let b58 = DashKeys.Base58.create();

async function main() {
  const walletKey = await loadWallet();

  let identityIndex = parseInt(process.argv[2], 10);
  if (isNaN(identityIndex)) {
    console.error("");
    console.error("USAGE");
    console.error(`   ${process.argv[0]} ${process.argv[1]} <identity-index>`);
    console.error("");
    console.error("EXAMPLE");
    console.error(`   ${process.argv[0]} ${process.argv[1]} 0`);
    console.error("");
    process.exit(1);
  }

  let hdOpts = { version: "testnet" }; // TODO

  let {
    regFundKey,
    topupKey, // TODO next change key from wallet
    assetWif,
    assetInfo,

    assetKey,
    masterKey,
    otherKey,
  } = await deriveAllCreateIdentityKeys(hdOpts, walletKey, identityIndex);
  
  console.log("Asset WIF", assetWif, "(would be ephemeral, non-hd)");

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

  await createIdentityFromAssetLock(
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

main();
