import * as Bincode from "./src/bincode.js";
import * as DashBincode from "./1.8.1/generated_bincode.js";
import * as KeyUtils from "./src/key-utils.js";
import { loadWallet } from "./src/cli.js";
import { deriveAllCreateIdentityKeys } from "./src/asset_lock.js";
import { toHex } from "./src/hex.js";
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
let { regFundKey, topupKey, // TODO next change key from wallet
assetWif, assetInfo, assetKey, masterKey, otherKey, } = await deriveAllCreateIdentityKeys(hdOpts, walletKey, identityIndex);
// TODO: GetIdentityByPublicKeyHashRequestV0
// get the identity id
const owner_id = "TODO";
const documentSchemas = new Map();
documentSchemas.set("x", DashBincode.Value.Map([
// [DashBincode.Value.Text("key"), DashBincode.Value.Text("value")],
]));
const dataContract = DashBincode.DataContractInSerializationFormatV0({
    id: DashBincode.Identifier(DashBincode.IdentifierBytes32(new Uint8Array)), // TODO
    config: DashBincode.DataContractConfig.V0({
        can_be_deleted: false,
        readonly: false,
        keeps_history: false,
        documents_keep_history_contract_default: false,
        documents_mutable_contract_default: false,
        documents_can_be_deleted_contract_default: false
    }),
    version: 0,
    owner_id: DashBincode.Identifier(DashBincode.IdentifierBytes32(new Uint8Array)),
    document_schemas: documentSchemas,
    // schema_defs: ,
});
const createDataContract = DashBincode.DataContractCreateTransitionV0({
    data_contract: DashBincode.DataContractInSerializationFormat.V0(dataContract),
    identity_nonce: 0n, // TODO: https://docs.dash.org/en/latest/docs/core/dips/dip-0030.html#identity-contract-nonce
    user_fee_increase: 0,
    signature_public_key_id: 0,
    signature: DashBincode.BinaryData(new Uint8Array),
});
const stateTransition = DashBincode.StateTransition.DataContractCreate(DashBincode.DataContractCreateTransition.V0(createDataContract));
{
    const signableBytes = new Uint8Array(Bincode.encode(DashBincode.StateTransition, stateTransition, { signable: true }));
    const signableHash = await KeyUtils.doubleSha256(signableBytes);
    const signatureBytes = await KeyUtils.magicSign({
        privKeyBytes: assetKey.privateKey,
        doubleSha256Bytes: signableHash,
    });
    createDataContract.signature[0] = signatureBytes;
}
const signedBytes = new Uint8Array(Bincode.encode(DashBincode.StateTransition, stateTransition));
console.log("Signed");
console.log(toHex(signedBytes));
