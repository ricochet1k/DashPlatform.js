import Fs from "node:fs/promises";

import { doubleSha256 } from "dashtx"
import DashKeys from "dashkeys"
import * as Bincode from "./src/bincode.ts";
import * as DashBincode from "./2.0.0/generated_bincode.js";
import * as KeyUtils from "./src/key-utils.js";

import { loadWallet } from "./src/cli.ts"
import { deriveAllCreateIdentityKeys } from "./src/asset_lock.ts"
import { toHex } from "./src/hex.js"
import { connectToNode } from "./src/rpc.ts"
import { NODE_ADDRESS } from "./src/constants.ts"
import { findExistingIdentity } from "./src/identity.ts"
import { base58 } from "./src/util/base58.ts"

const nodeRpc = connectToNode(NODE_ADDRESS);

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

let hdOpts = { version: "testnet" } as const; // TODO

let {
  regFundKey,
  changeKey, // TODO next change key from wallet
  assetKey,

  masterKey,
  otherKey,
} = await deriveAllCreateIdentityKeys(hdOpts, walletKey, identityIndex);

console.log('masterKey hex', toHex(masterKey.publicKey))
console.log('otherKey hex', toHex(otherKey.publicKey))

console.log('masterKey pkh', toHex(await DashKeys.pubkeyToPkh(masterKey.publicKey)))
console.log('otherKey pkh', toHex(await DashKeys.pubkeyToPkh(otherKey.publicKey)))

const pkh = await DashKeys.pubkeyToPkh(masterKey.publicKey)
const existingIdentity = await findExistingIdentity(nodeRpc, pkh)
if (!existingIdentity) {
  console.log('Identity Not Yet Created!')
  process.exit(1);
}

const existingIdentityV0: DashBincode.IdentityV0 = Bincode.match(existingIdentity, {
  V0: i => i[0]
});

const existingIdentityId = existingIdentityV0.id[0][0];

const identityNonceResponse = await nodeRpc.platform.getIdentityNonce({version: {
  oneofKind: "v0",
  v0: {
    identityId: existingIdentityId,
    prove: false,
  }
}})
// console.log('identityNonceResponse', identityNonceResponse)
// console.log('identityNonceResponse', identityNonceResponse.response.version.v0.result)

let current_identity_nonce = 0n;
if (identityNonceResponse.response.version.oneofKind === 'v0') {
  const v0 = identityNonceResponse.response.version.v0;
  if (v0.result.oneofKind === 'identityNonce') {
    current_identity_nonce = BigInt(v0.result.identityNonce)
  } else {
    throw new Error("Cannot handle identityNonceResponse")
  }
} else {
  throw new Error("Cannot handle identityNonceResponse")
}
console.log('current_identity_nonce', current_identity_nonce)

console.log('Identity:', base58.encode(existingIdentityV0.id[0][0]))
console.log(existingIdentityV0)

const owner_id = existingIdentityId;
const identity_nonce = current_identity_nonce + 1n;

// TODO: check to see if a data contract has already been created

const documentSchemas = new Map<string, DashBincode.Value>();
documentSchemas.set("note", DashBincode.Value.Map([
  [DashBincode.Value.Text("type"), DashBincode.Value.Text("object")], // required
  [DashBincode.Value.Text("properties"), DashBincode.Value.Map([
    [DashBincode.Value.Text("message"), DashBincode.Value.Map([
      [DashBincode.Value.Text("type"), DashBincode.Value.Text("string")],
      [DashBincode.Value.Text("position"), DashBincode.Value.U32(0)],
    ])],
  ])],
  [DashBincode.Value.Text("additionalProperties"), DashBincode.Value.Bool(false)],
]))

const newContractIdBuffer = new Uint8Array(owner_id.length + 8);
newContractIdBuffer.set(owner_id, 0);
new DataView(newContractIdBuffer.buffer).setBigUint64(owner_id.length, identity_nonce);
console.log('owner_id', toHex(owner_id))
console.log('newContractIdBuffer', toHex(newContractIdBuffer))
const newContractID = await doubleSha256(newContractIdBuffer)
const newContractIDStr = base58.encode(newContractID)
console.log('newContractID', newContractIDStr)


const dataContract = DashBincode.DataContractInSerializationFormatV0({
    version: 1,
    owner_id: DashBincode.Identifier(DashBincode.IdentifierBytes32(owner_id)),
    id: DashBincode.Identifier(DashBincode.IdentifierBytes32(newContractID)),
    document_schemas: documentSchemas,
    config: DashBincode.DataContractConfig.V0({
      can_be_deleted: false,
      readonly: false,
      keeps_history: false,
      documents_keep_history_contract_default: false,
      documents_mutable_contract_default: false,
      documents_can_be_deleted_contract_default: false
    }),
    // schema_defs: ,
})

const createDataContract = DashBincode.DataContractCreateTransitionV0({
    data_contract: DashBincode.DataContractInSerializationFormat.V0(dataContract),
    identity_nonce, // TODO: https://docs.dash.org/en/latest/docs/core/dips/dip-0030.html#identity-contract-nonce
    user_fee_increase: 0, // extra fee to process this transition faster, leave 0
    signature_public_key_id: 1, // TODO: set to which identity public key are we signing with
    signature: DashBincode.BinaryData(new Uint8Array),
})

const stateTransition = DashBincode.StateTransition.DataContractCreate(
  DashBincode.DataContractCreateTransition.V0(createDataContract));

{
  const signableBytes = new Uint8Array(Bincode.encode(DashBincode.StateTransition, stateTransition, {signable: true}));

  const signableHash = await KeyUtils.doubleSha256(signableBytes);

  const signatureBytes = await KeyUtils.magicSign({
    privKeyBytes: otherKey.privateKey!,
    doubleSha256Bytes: signableHash,
  });

  createDataContract.signature[0] = signatureBytes
}

const signedBytes = new Uint8Array(Bincode.encode(DashBincode.StateTransition, stateTransition));

console.log("Signed")
console.log(toHex(signedBytes))

console.log("Broadcasting Data Contract Create Transition...")
try {
  const response = await nodeRpc.platform.broadcastStateTransition({
    stateTransition: signedBytes,
  })
  console.log('response', response);
  await Fs.writeFile('data-contract-' + newContractIDStr.slice(0, 6) + '.json', JSON.stringify({id: newContractIDStr}));

} catch (e) {
  console.error("Error: ", decodeURIComponent((e as any).message))
}

console.log();
console.log('New Contract ID:', newContractIDStr)
console.log("https://testnet.platform-explorer.com/document/" + newContractIDStr)
