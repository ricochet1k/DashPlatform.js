import Fs from "node:fs/promises";

import DashHd from "dashhd";
import * as DashHdUtils from "./dashhd-utils.js";
import DashKeys from "dashkeys";
import * as DashTx from "dashtx/dashtx.js";
import * as DashPlatform from "./dashplatform.js";
import * as Bincode from "./bincode.ts";
import * as DashBincode from "./1.8.1/generated_bincode.js";
import * as QRCode from "./_qr.js";
import * as KeyUtils from "./key-utils.js";

import { createIdentityFromAssetLock } from "./2-create-identity-transition.js";

import { loadWallet } from "./cli.js"
import { deriveAllCreateIdentityKeys } from "./asset_lock.js"

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

  /** @type {Map<string, DashBincode.Value} */
  const documentSchemas = new Map();
  documentSchemas.set("x", DashBincode.Value.Map([
    // [DashBincode.Value.Text("key"), DashBincode.Value.Text("value")],
  ]))

  const dataContract = DashBincode.DataContractInSerializationFormatV0({
      id: DashBincode.Identifier(DashBincode.IdentifierBytes32(new Uint8Array)), // TODO
      config: DashBincode.DataContractConfig.V0(
        DashBincode.DataContractConfigV0({
            can_be_deleted: false,
            readonly: false,
            keeps_history: false,
            documents_keep_history_contract_default: false,
            documents_mutable_contract_default: false,
            documents_can_be_deleted_contract_default: false
        })
      ),
      version: 0,
      owner_id: DashBincode.Identifier(DashBincode.IdentifierBytes32(new Uint8Array)), // TODO
      document_schemas: documentSchemas,
      // schema_defs: ,
  })

  const createDataContract = DashBincode.DataContractCreateTransitionV0({
      data_contract: DashBincode.DataContractInSerializationFormat.V0(dataContract),
      identity_nonce: 0n,
      user_fee_increase: 0,
      signature_public_key_id: 0,
      signature: DashBincode.BinaryData(new Uint8Array),
  })

  const stateTransition = DashBincode.StateTransition.DataContractCreate(
    DashBincode.DataContractCreateTransition.V0(createDataContract));

  const signableBytes = Bincode.encode(DashBincode.StateTransition, stateTransition, {signable: true});
  

}

main();
