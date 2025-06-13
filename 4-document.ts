import Fs from "node:fs/promises";

// import DashHd from "dashhd";
// import * as DashHdUtils from "./dashhd-utils.ts";
import DashKeys from "dashkeys";
// import * as DashTx from "dashtx";
// import * as DashPlatform from "./dashplatform.js";
import * as Bincode from "./src/bincode.ts";
import * as DashBincode from "./2.0.0/generated_bincode.js";
import * as QRCode from "./src/_qr.js";
import * as KeyUtils from "./src/key-utils.js";
import { connectToNode } from "./src/rpc.ts"
import { NODE_ADDRESS } from "./src/constants.ts"
import { findExistingIdentity } from "./src/identity.ts"

import { loadWallet } from "./src/cli.ts"
import { deriveAllCreateIdentityKeys } from "./src/asset_lock.ts"
import { toHex } from "./src/hex.js"
import { base58 } from "./src/util/base58.ts"

const nodeRpc = connectToNode(NODE_ADDRESS);

const walletKey = await loadWallet();

function printUsage() {
  console.error("");
  console.error("USAGE");
  console.error(`   ${process.argv[0]} ${process.argv[1]} <identity-index> <data-contract-id>`);
  console.error("");
  console.error("EXAMPLE");
  console.error(`   ${process.argv[0]} ${process.argv[1]} 0 JEJjgpGiLqeH8yaUeAwbCzuhTeL3xBMUAvyRCiGBXkEn`);
  console.error("");
}

const identityIndex = parseInt(process.argv[2], 10);
if (isNaN(identityIndex)) {
  printUsage();
  process.exit(1);
}

const dataContractId = process.argv[3]; // "JEJjgpGiLqeH8yaUeAwbCzuhTeL3xBMUAvyRCiGBXkEn"
console.log('dataContractId', dataContractId, dataContractId.length);
const dataContractIdBytes = base58.decode(dataContractId);
if (dataContractIdBytes.length != 32) {
  printUsage();
  process.exit(1);
}


const hdOpts = { version: "testnet" } as const; // TODO

const {
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

const identityContractNonceResponse = await nodeRpc.platform.getIdentityContractNonce({version: {
  oneofKind: "v0",
  v0: {
    identityId: existingIdentityId,
    contractId: dataContractIdBytes,
    prove: false,
  }
}})
// console.log('identityContractNonceResponse', identityContractNonceResponse)
// console.log('identityContractNonceResponse', identityContractNonceResponse.response.version.v0.result)

let current_identity_contract_nonce = 0n;
if (identityContractNonceResponse.response.version.oneofKind === 'v0') {
  const v0 = identityContractNonceResponse.response.version.v0;
  if (v0.result.oneofKind === 'identityContractNonce') {
    current_identity_contract_nonce = BigInt(v0.result.identityContractNonce)
  } else {
    throw new Error("Cannot handle identityContractNonceResponse")
  }
} else {
  throw new Error("Cannot handle identityContractNonceResponse")
}
console.log('current_identity_contract_nonce', current_identity_contract_nonce)

const owner_id = existingIdentityId;
const identity_contract_nonce = current_identity_contract_nonce + 1n;
const document_type_name = "note";
const document_type_name_bytes = new TextEncoder().encode(document_type_name)
const entropy = crypto.getRandomValues(new Uint8Array(32))
// generate the document id

// TODO: This is a terribly stupid way of concatting these arrays
const buf = new Uint8Array([
  ...dataContractIdBytes,
  ...owner_id,
  ...document_type_name_bytes,
  ...entropy,
])
const document_id = await KeyUtils.doubleSha256(buf)



const data: Map<string, DashBincode.Value> = new Map();
data.set("message", DashBincode.Value.Text("It's working!"))


const documentCreate = DashBincode.DocumentCreateTransitionV0({
  base: DashBincode.DocumentBaseTransition.V0(
    DashBincode.DocumentBaseTransitionV0({
      id: DashBincode.Identifier(DashBincode.IdentifierBytes32(document_id)),
      data_contract_id: DashBincode.Identifier(DashBincode.IdentifierBytes32(dataContractIdBytes)),
      identity_contract_nonce,
      document_type_name,
    })
  ),
  entropy,
  data,
})

const documentsBatch = DashBincode.BatchTransitionV0({
  owner_id: DashBincode.Identifier(DashBincode.IdentifierBytes32(owner_id)),
  transitions: [
    DashBincode.DocumentTransition.Create(DashBincode.DocumentCreateTransition.V0(documentCreate)),
  ],
  user_fee_increase: 0,
  signature_public_key_id: 1,
  signature: DashBincode.BinaryData(new Uint8Array), // filled in later
})

const stateTransition = DashBincode.StateTransition.Batch(
  DashBincode.BatchTransition.V0(documentsBatch));

{
  const signableBytes = new Uint8Array(Bincode.encode(DashBincode.StateTransition, stateTransition, {signable: true}));

  const signableHash = await KeyUtils.doubleSha256(signableBytes);

  const signatureBytes = await KeyUtils.magicSign({
    privKeyBytes: otherKey.privateKey!,
    doubleSha256Bytes: signableHash,
  });

  documentsBatch.signature[0] = signatureBytes
}

const signedBytes = new Uint8Array(Bincode.encode(DashBincode.StateTransition, stateTransition));

console.log("Signed")
console.log(toHex(signedBytes))

console.log("Broadcasting Batch Transition for Document Create...")
try {
  const response = await nodeRpc.platform.broadcastStateTransition({
    stateTransition: signedBytes,
  })
  console.log('response', response);
  // await Fs.writeFile('data-contract-' + newContractIDStr.slice(0, 6) + '.json', JSON.stringify({id: newContractIDStr}));

} catch (e) {
  console.error("Error: ", decodeURIComponent((e as any).message))
}

console.log("Document ID:" + base58.encode(document_id))
console.log("https://testnet.platform-explorer.com/document/" + base58.encode(document_id))
