import Fs from "node:fs/promises";

import DashHd from "dashhd";
import * as DashHdUtils from "./src/dashhd-utils.js";
import DashKeys from "dashkeys";
import * as DashTx from "dashtx";
import * as DashPlatform from "./src/dashplatform.js";
import * as QRCode from "./src/_qr.js";
import * as KeyUtils from "./src/key-utils.js";

import { createIdentityFromAssetLock } from "./2-create-identity-transition.js";

import { loadWallet } from "./src/cli.js"
import { deriveAllCreateIdentityKeys } from "./src/asset_lock.js"
import { createPlatformAssetLock } from "./src/asset_lock.js"
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

  console.log('regFundKey', await DashHd.toAddr(regFundKey.publicKey, {version: 'testnet'}));
  console.log('topupKey', await DashHd.toAddr(topupKey.publicKey, {version: 'testnet'}));
  console.log('assetKey', await DashHd.toAddr(assetKey.publicKey, {version: 'testnet'}));
  console.log('masterKey', await DashHd.toAddr(masterKey.publicKey, {version: 'testnet'}));
  console.log('otherKey', await DashHd.toAddr(otherKey.publicKey, {version: 'testnet'}));
  console.log();

  let { identityIdHex, txidHex, assetProof } = await createPlatformAssetLock(
    hdOpts,
    regFundKey,
    topupKey, // TODO next change key from wallet
    assetInfo,
  );

  console.log();
  console.log(`txidHex: `, txidHex);
  console.log(`identityIdHex:`, identityIdHex);
  console.log(`assetProof:`, assetProof);

  await Fs.writeFile('ready-to-create-identity.json', JSON.stringify({
    assetKey,
    masterKey,
    otherKey,
    identityIdHex,
    txidHex,
    assetProof,
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
    assetProof,
  );
  // walletKey, coinType, identityIndex
}

main();
