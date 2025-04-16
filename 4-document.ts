import Fs from "node:fs/promises";

// import DashHd from "dashhd";
// import * as DashHdUtils from "./dashhd-utils.js";
// import DashKeys from "dashkeys";
// import * as DashTx from "dashtx";
// import * as DashPlatform from "./dashplatform.js";
import * as Bincode from "./src/bincode.ts";
import * as DashBincode from "./1.8.1/generated_bincode.js";
import * as QRCode from "./src/_qr.js";
import * as KeyUtils from "./src/key-utils.js";

import { createIdentityFromAssetLock } from "./2-create-identity-transition.js";

import { loadWallet } from "./src/cli.js"
import { deriveAllCreateIdentityKeys } from "./src/asset_lock.js"
import { toHex } from "./src/hex.js"

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

  const data: Map<string, DashBincode.Value> = new Map();

  const documentCreate = DashBincode.DocumentCreateTransitionV0({
    base: DashBincode.DocumentBaseTransition.V0(
      DashBincode.DocumentBaseTransitionV0({
        id: DashBincode.Identifier(DashBincode.IdentifierBytes32(new Uint8Array)), // TODO
        identity_contract_nonce: 0n,
        document_type_name: "",
        data_contract_id: DashBincode.Identifier(DashBincode.IdentifierBytes32(new Uint8Array)), // TODO
      })
    ),
    entropy: new Uint8Array, // TODO
    data: data,
  })

  const documentsBatch = DashBincode.DocumentsBatchTransitionV0({
    owner_id: DashBincode.Identifier(DashBincode.IdentifierBytes32(new Uint8Array)), // TODO
    transitions: [
      DashBincode.DocumentTransition.Create(
        DashBincode.DocumentCreateTransition.V0(documentCreate)
      )
    ],
    user_fee_increase: 0,
    signature_public_key_id: 0,
    signature: DashBincode.BinaryData(new Uint8Array), // TODO
  })

  const stateTransition = DashBincode.StateTransition.DocumentsBatch(
    DashBincode.DocumentsBatchTransition.V0(documentsBatch));

  {
    const signableBytes = new Uint8Array(Bincode.encode(DashBincode.StateTransition, stateTransition, {signable: true}));

    const signableHash = await KeyUtils.doubleSha256(signableBytes);

    const signatureBytes = await KeyUtils.magicSign({
      privKeyBytes: assetKey.privateKey,
      doubleSha256Bytes: signableHash,
    });

    documentsBatch.signature[0] = signatureBytes
  }

  const signedBytes = new Uint8Array(Bincode.encode(DashBincode.StateTransition, stateTransition));

  console.log("Signed")
  console.log(toHex(signedBytes))
}

main();
