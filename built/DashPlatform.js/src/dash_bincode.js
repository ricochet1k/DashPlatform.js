import { Bool, Bytes, Enum, FixedBytes, Lazy, Struct, Uint16, Uint32, Uint64, Uint8, VarUint, Vec, Option, String, NotSignable } from "./src/bincode";
/** @import {BinCodeable} from './src/bincode' */
// export const IdentityCreateTransitionV0 = Lazy(() =>
//     Struct("IdentityCreateTransitionV0", {
//         // $version: Constant("0"),
//         // // When signing, we don't sign the signatures for keys
//         // #[platform_signable(into = "Vec<IdentityPublicKeyInCreationSignable>")]
//         public_keys: Vec(IdentityPublicKeyInCreation),
//         asset_lock_proof: RawAssetLockProof,
//         user_fee_increase: UserFeeIncrease,
//         // #[platform_signable(exclude_from_sig_hash)]
//         signature: NotSignable(BinaryData),
//         // #[cfg_attr(feature = "state-transition-serde-conversion", serde(skip))]
//         // #[platform_signable(exclude_from_sig_hash)]
//         identity_id: NotSignable(Identifier),
//     })
// )
// export const IdentityCreateTransition = Enum("IdentityCreateTransition", {
//     0: IdentityCreateTransitionV0,
// })
// export const KeyID = VarUint
// export const Identifier = FixedBytes(32)
// export const BinaryData = Bytes
// export const UserFeeIncrease = VarUint //Uint16;
// export const TimestampMillis = VarUint //Uint64;
// export const KeyType = VarUint // enum
// export const KeyType_values = [
//     "ECDSA_SECP256K1",
//     "BLS12_381",
//     "ECDSA_HASH160",
//     "BIP13_SCRIPT_HASH",
//     "EDDSA_25519_HASH160",
// ]
// export const Purpose = VarUint // enum
// export const Purpose_values = [
//     "AUTHENTICATION",
//     "ENCRYPTION",
//     "DECRYPTION",
//     "TRANSFER",
//     "SYSTEM",
//     "VOTING",
// ]
// export const SecurityLevel = VarUint // enum
// export const SecurityLevel_values = ["MASTER", "CRITICAL", "HIGH", "MEDIUM"]
// export const ContractBounds0 = Struct("ContractBounds0", {
//     id: Identifier,
// })
// export const ContractBounds1 = Struct("ContractBounds1", {
//     id: Identifier,
//     document_type_name: String,
// })
// export const ContractBounds = Enum("ContractBounds", {
//     0: ContractBounds0,
//     1: ContractBounds1,
// })
// export const IdentityPublicKeyInCreationV0 = Struct("IdentityPublicKeyInCreationV0", {
//     id: KeyID,
//     type: KeyType,
//     purpose: Purpose,
//     security_level: SecurityLevel,
//     contract_bounds: Option(ContractBounds),
//     read_only: Bool,
//     data: BinaryData,
//     // /// The signature is needed for ECDSA_SECP256K1 Key type and BLS12_381 Key type
//     // #[platform_signable(exclude_from_sig_hash)]
//     signature: NotSignable(BinaryData),
// })
// export const IdentityPublicKeyInCreation = Enum("IdentityPublicKeyInCreation", {
//     0: IdentityPublicKeyInCreationV0,
// })
// export const Txid = FixedBytes(32)
// export const CycleHash = FixedBytes(32)
// export const BLSSignature = FixedBytes(96)
// export const ScriptBuf = Bytes
// export const OutPoint = Struct("OutPoint", {
//     txid: Txid,
//     vout: Uint32,
// })
// export const InstantLock = Struct("InstantLock", {
//     version: Uint8,
//     inputs: Vec(OutPoint),
//     txid: Txid,
//     cyclehash: CycleHash,
//     signature: BLSSignature,
// })
// export const Witness = Struct("Witness", {
//     content: Bytes,
//     witness_elements: Uint64,
//     indices_start: Uint64,
// })
// export const TxIn = Struct("TxIn", {
//     previous_output: OutPoint,
//     script_sig: ScriptBuf,
//     sequence: Uint32,
//     witness: Witness,
// })
// export const TxOut = Struct("TxOut", {
//     value: Uint64,
//     script_pubkey: ScriptBuf,
// })
// export const TransactionPayload = Enum("TransactionPayload", {
//     // TODO - we have the normal layer 1 payload already
// })
// export const Transaction = Struct("Transaction", {
//     version: Uint16,
//     lock_time: Uint32,
//     input: Vec(TxIn),
//     output: Vec(TxOut),
//     special_transaction_payload: Option(TransactionPayload),
// })
// export const InstantAssetLockProof = Struct("InstantAssetLockProof", {
//     instant_lock: InstantLock,
//     transaction: Transaction,
//     output_index: Uint32,
// })
// export const RawInstantLockProof = Struct("RawInstantLockProof", {
//     instant_lock: BinaryData,
//     transaction: BinaryData,
//     output_index: VarUint, //Uint32,
// })
// export const ChainAssetLockProof = Struct("ChainAssetLockProof", {
//     core_chain_locked_height: Uint32,
//     out_point: OutPoint,
// })
// export const AssetLockProof = Enum("AssetLockProof", {
//     0: InstantAssetLockProof,
//     1: ChainAssetLockProof,
// })
// export const RawAssetLockProof = Enum("RawAssetLockProof", {
//     0: RawInstantLockProof,
//     1: ChainAssetLockProof,
// })
// export const IdentityPublicKeyV0 = Struct("IdentityPublicKeyV0", {
//     id: KeyID,
//     purpose: Purpose,
//     security_level: SecurityLevel,
//     contract_bounds: Option(ContractBounds),
//     type: KeyType,
//     read_only: Bool,
//     data: BinaryData,
//     disabled_at: Option(TimestampMillis),
// })
// export const IdentityPublicKey = Enum("IdentityPublicKey", {
//     0: IdentityPublicKeyV0,
// })
/**
 * This is a JSON.stringify replacer that converts keys to camelCase
 * and Uint8Array to regular Array to match what to_json* does.
 * @param {string} key
 * @param {any} value
 */
function jsonCamelCaseReplacer(key, value) {
    if (value instanceof Uint8Array) {
        return Array.from(value);
    }
    if (value && typeof value === "object") {
        /** @type {any} */
        let replacement = {};
        for (let k of Object.keys(value)) {
            let newkey = k.replace(/_[a-z]/g, (val) => val[1].toUpperCase());
            replacement[newkey] = value[k];
        }
        return replacement;
    }
    return value;
}
/**
 * @param {any} value
 */
export function toJsonCamelCase(value) {
    return JSON.stringify(value, jsonCamelCaseReplacer);
}
// // TODO: Implement all the other transitions
// export const StateTransition = Enum("StateTransition", {
//     0: DataContractCreateTransition, //DataContractCreate(DataContractCreateTransition),
//     // 1: DataContractUpdateTransition, //DataContractUpdate(DataContractUpdateTransition),
//     // 2: DocumentsBatchTransition, //DocumentsBatch(DocumentsBatchTransition),
//     3: IdentityCreateTransition, //IdentityCreate(IdentityCreateTransition),
//     // 4: IdentityTopUpTransition, //IdentityTopUp(IdentityTopUpTransition),
//     // 5: IdentityCreditWithdrawalTransition, //IdentityCreditWithdrawal(IdentityCreditWithdrawalTransition),
//     // 6: IdentityUpdateTransition, //IdentityUpdate(IdentityUpdateTransition),
//     // 7: IdentityCreditTransferTransition, //IdentityCreditTransfer(IdentityCreditTransferTransition),
//     // 8: MasternodeVoteTransition, //MasternodeVote(MasternodeVoteTransition),
// })
