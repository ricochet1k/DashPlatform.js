import { doubleSha256 } from "../../DashTx.js/dashtx.js"
import * as Bincode from "./bincode.js"
import { BinaryData, Identifier, IdentifierBytes32, IdentityPublicKey, StateTransition } from "../2.0.0/generated_bincode.js"
import * as secp from "@noble/secp256k1"

/**
 * Signs a StateTransition in-place.
 * TODO: owner_id?
 * @param st StateTransition to sign
 * @param identity Public key to sign with
 * @param private_key Cooresponding Private key
 */
export async function signTransitionWithRawKey(st: StateTransition, pubkey: IdentityPublicKey, private_key: Uint8Array) {
    await Bincode.match(st, {
        DataContractCreate: ({ 0: dcct }) => Bincode.match(dcct, {
            V0: async ({ 0: dcct0 }) => {
                await Bincode.match(dcct0.data_contract, {
                    V0: async ({ 0: dc }) => {
                        // dc.owner_id = owner_id
                        dc.id = await makeContractId(dc.owner_id, dcct0.identity_nonce)
                    },
                    V1: async ({ 0: dc }) => {
                        // dc.owner_id = owner_id
                        dc.id = await makeContractId(dc.owner_id, dcct0.identity_nonce)
                    },
                })

                const new_signable_bytes = Bincode.encode(StateTransition, st, { signable: true })
                const hash = await doubleSha256(new Uint8Array(new_signable_bytes))

                // TODO: switch to magicSign
                const signature = (await secp.signAsync(hash, private_key, { extraEntropy: false }))
                const signature_bytes = new Uint8Array(1 + 64)
                signature_bytes[0] = signature.recovery + 27 + 4 // These magic numbers come from rust-dashcore/dash/src/signer.rs RecoverableSignature::to_compact_signature
                signature_bytes.set(signature.toCompactRawBytes(), 1)

                dcct0.signature_public_key_id = Bincode.match(pubkey, {
                    V0: ({0: pk}) => pk.id,
                })
                dcct0.signature = BinaryData(signature_bytes)
            }
        }),
        DataContractUpdate: x => { throw new Error("Not implemented") },
        Batch: x => { throw new Error("Function not implemented.") },
        IdentityCreate: x => { throw new Error("Not implemented") },
        IdentityTopUp: x => { throw new Error("Not implemented") },
        IdentityCreditWithdrawal: x => { throw new Error("Not implemented") },
        IdentityUpdate: x => { throw new Error("Not implemented") },
        IdentityCreditTransfer: x => { throw new Error("Not implemented") },
        MasternodeVote: x => { throw new Error("Not implemented") },
    })
}

async function makeContractId(owner_id: Identifier, identity_nonce: bigint) {
    const contract_id_bytes = new Uint8Array(32 + 8);
    contract_id_bytes.set(owner_id[0][0], 0);
    new DataView(contract_id_bytes.buffer).setBigUint64(32, BigInt(identity_nonce), false);
    const contract_id = await doubleSha256(contract_id_bytes)

    return Identifier(IdentifierBytes32(contract_id))
}
