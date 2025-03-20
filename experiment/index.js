
const identity_create = db.StateTransition.IdentityCreate(
    db.IdentityCreateTransition.V0(
        db.IdentityCreateTransitionV0({
            public_keys: [],
            // asset_lock_proof: db.AssetLockProof.Instant(db.InstantAssetLockProof({
            //     instant_lock: "",
            //     transaction: asset_lock,
            // })),
            asset_lock_proof: db.AssetLockProof.Chain(db.ChainAssetLockProof({
                core_chain_locked_height: 1,
                out_point: db.OutPoint({
                    txid: db.Txid(fromHex("0000000000000000000000000000000000000000000000000000000000000000")),
                    vout: 1,
                }),
            })),
            output_index: 0,
            user_fee_increase: 0,
            identity_id: db.Identifier(db.IdentifierBytes32(fromHex("0000000000000000000000000000000000000000000000000000000000000000"))),
            signature: db.BinaryData(fromHex("0000000000000000000000000000000000000000000000000000000000000000"))
        })
    )
);

const identity_create_bytes = Bincode.encode(db.StateTransition, identity_create)
console.log('identity_create_bytes', identity_create_bytes)


const data_contract_create = db.StateTransition.DataContractCreate(db.DataContractCreateTransition.V0(db.DataContractCreateTransitionV0({
    data_contract: db.DataContractInSerializationFormat.V1(db.DataContractInSerializationFormatV1({
      
    })),
    identity_nonce: 43,
    user_fee_increase: 4,
    signature_public_key_id: 42,
    signature: db.BinaryData(fromHex("0000000000000000000000000000000000000000000000000000000000000000")),
})))

const data_contract_create_bytes = Bincode.encode(db.StateTransition, data_contract_create)
console.log('data_contract_create_bytes', data_contract_create_bytes)

