import Fs from "node:fs/promises";

import DashHd from "dashhd";
import * as DashHdUtils from "./src/dashhd-utils.ts";
import * as Bincode from "./src/bincode.ts";
import DashKeys from "dashkeys";
import * as DashTx from "dashtx";
import * as DashPlatform from "./src/dashplatform.js";
import * as QRCode from "./src/_qr.js";
import * as KeyUtils from "./src/key-utils.js";

import {
  createIdentityFromAssetLock,
} from "./2-create-identity-transition.ts";

import { loadWallet } from "./src/cli.ts";
import { deriveAllCreateIdentityKeys } from "./src/asset_lock.ts";
import { createPlatformAssetLock } from "./src/asset_lock.ts";
import { connectToNode, TRPC } from "./src/rpc.ts"
import { NODE_ADDRESS, RPC_AUTH_URL } from "./src/constants.ts"
import { fromHex, toHex } from "./src/hex.js"
import * as BinCode from "./src/bincode.ts"
import * as DashBincode from "./2.0.0/generated_bincode.js"
import { base58 } from "./src/util/base58.ts"
import { findExistingIdentity } from "./src/identity.ts"

async function main(): Promise<void> {
  const rpc = new TRPC(RPC_AUTH_URL);
  const nodeRpc = connectToNode(NODE_ADDRESS)

  const walletKey = await loadWallet();

  const identityIndex = parseInt(process.argv[2], 10);
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

  const hdOpts = { version: "testnet" as const }; // TODO

  const {
    regFundKey,
    changeKey,
    assetKey,
    masterKey,
    otherKey,
  } = await deriveAllCreateIdentityKeys(
    hdOpts,
    walletKey,
    identityIndex,
  );

  // console.log("Asset WIF", assetWif, "(would be ephemeral, non-hd)");

  console.log(
    "regFundKey",
    await DashHd.toAddr(regFundKey.publicKey, { version: "testnet" }),
  );
  console.log(
    "changeKey",
    await DashHd.toAddr(changeKey.publicKey, { version: "testnet" }),
  );
  console.log(
    "assetKey",
    await DashHd.toAddr(assetKey.publicKey, { version: "testnet" }),
  );
  console.log(
    "masterKey",
    await DashHd.toAddr(masterKey.publicKey, { version: "testnet" }),
  );
  console.log(
    "masterKey priv wif",
    await DashHd.toWif(masterKey.privateKey!, { version: "testnet" }),
  );
  console.log(
    "otherKey",
    await DashHd.toAddr(otherKey.publicKey, { version: "testnet" }),
  );
  console.log();

  const pkh = await DashKeys.pubkeyToPkh(masterKey.publicKey)
  console.log('masterKey pkh', toHex(pkh))
  const existingIdentity = await findExistingIdentity(nodeRpc, pkh)
  if (existingIdentity) {
    const existingIdentityV0: DashBincode.IdentityV0 = Bincode.match(existingIdentity, {
      V0: i => i[0]
    });
    const existingIdentityId = existingIdentityV0.id[0][0];
    console.log('Identity Already Created!', base58.encode(existingIdentityId))
    process.exit(1);
  }

  const {
    identityId,
    txidHex,
    assetProof,
  } = await createPlatformAssetLock(hdOpts, regFundKey, changeKey, assetKey, rpc);

  console.log();
  console.log(`txidHex: `, txidHex);
  console.log(`identityId:`, base58.encode(identityId));
  console.log(`assetProof:`, assetProof);

  await Fs.writeFile(
    "ready-to-create-identity.json",
    JSON.stringify(
      {
        assetKey,
        masterKey,
        otherKey,
        identityId: toHex(identityId),
        txidHex,
        assetProof,
      },
      (key, val) => {
        if (val instanceof Uint8Array || val instanceof ArrayBuffer) {
          return {
            "@Uint8Array hex": DashTx.utils.bytesToHex(new Uint8Array(val)),
          };
        }
        return val;
      },
      2,
    ),
  );

  await createIdentityFromAssetLock(
    assetKey,
    masterKey,
    otherKey,
    identityId,
    assetProof,
  );
}

main();
