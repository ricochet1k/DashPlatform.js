import * as Bincode from '../bincode.ts';
import * as db from '../generated_bincode.js';

const data_contract_create = db.StateTransition.DataContractCreate(
    db.DataContractCreateTransition.V0(
        db.DataContractCreateTransitionV0({
            data_contract: db.DataContractInSerializationFormat.V1({
                id: db.Identifier(db.IdentifierBytes32(new Uint8Array(32))),
                config: db.DataContractConfig.V0({
                    can_be_deleted: false,
                    readonly: false,
                    keeps_history: false,
                    documents_keep_history_contract_default: false,
                    documents_mutable_contract_default: false,
                    documents_can_be_deleted_contract_default: false,
                    requires_identity_decryption_bounded_key: undefined,
                    requires_identity_encryption_bounded_key: undefined,
                }),
                version: 4,
                owner_id: db.Identifier(db.IdentifierBytes32(new Uint8Array(32))),
                schema_defs: undefined,
                document_schemas: new Map,
                groups: new Map,
                tokens: new Map,
            }),
            identity_nonce: 43,
            user_fee_increase: 4,
            signature_public_key_id: 42,
            signature: db.BinaryData(new Uint8Array(32)),
        })
    )
)

const foo : db.AssetLockPayload = db.AssetLockPayload({
    version: 1,
    credit_outputs: [],
});
const fooInstanceof = foo instanceof db.AssetLockPayload;
const x = Bincode.encode(db.AssetLockPayload, foo)

function expectError(fn: () => any) {
    let failed = false;
    try {
        fn();
    } catch (_) {
        failed = true;
    }
    if (!failed) {
        throw new Error("expected an error and got none from " + fn)
    }
}

// @ts-expect-error
const bad : db.AssetLockProof = db.AssetLockProof({} as any);

const bar = db.AssetLockProof.Instant({
    instant_lock: db.BinaryData(new Uint8Array),
    transaction: db.BinaryData(new Uint8Array),
    output_index: 1,
});

// @ts-expect-error
const badbar : db.AssetLockProof.Chain = bar;

const bar2 : db.AssetLockProof = bar;
const barInstanceof = bar instanceof db.AssetLockProof;
const bar2Instanceof = bar instanceof db.AssetLockProof.Instant;

expectError(() => {
    // @ts-expect-error
    const bady = Bincode.encode(db.AssetLockProof, foo)
})

const y = Bincode.encode(db.AssetLockProof, bar)

console.assert(data_contract_create instanceof db.StateTransition)
console.assert(data_contract_create instanceof db.StateTransition.DataContractCreate)

const data_contract_create_bytes = Bincode.encode(db.StateTransition, data_contract_create)
console.log('data_contract_create_bytes', data_contract_create_bytes)
