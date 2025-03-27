use std::{
    collections::{BTreeMap, BTreeSet},
    num::ParseIntError,
    str::FromStr,
};

use dashcore::{
    PubkeyHash, PublicKey, Script, ScriptBuf, TxIn, TxOut, Witness,
    consensus::{Decodable, Encodable},
    transaction::special_transaction::{TransactionPayload, asset_lock::AssetLockPayload},
};
use dpp::{
    bincode,
    dashcore::{
        BlockHash, InstantLock, OutPoint, Transaction, Txid,
        bls_sig_utils::BLSSignature,
        hashes::{Hash, hex::FromHex, sha256d},
    },
    data_contract::{
        TokenConfiguration,
        associated_token::{
            token_configuration::v0::TokenConfigurationV0,
            token_configuration_convention::{
                TokenConfigurationConvention, v0::TokenConfigurationConventionV0,
            },
            token_configuration_localization::{
                TokenConfigurationLocalization, v0::TokenConfigurationLocalizationV0,
            },
            token_distribution_rules::{TokenDistributionRules, v0::TokenDistributionRulesV0},
            token_keeps_history_rules::{TokenKeepsHistoryRules, v0::TokenKeepsHistoryRulesV0},
            token_perpetual_distribution::{
                TokenPerpetualDistribution, distribution_function::DistributionFunction,
                distribution_recipient::TokenDistributionRecipient,
                reward_distribution_type::RewardDistributionType, v0::TokenPerpetualDistributionV0,
            },
            token_pre_programmed_distribution::{
                TokenPreProgrammedDistribution, v0::TokenPreProgrammedDistributionV0,
            },
        },
        change_control_rules::{
            ChangeControlRules, authorized_action_takers::AuthorizedActionTakers,
            v0::ChangeControlRulesV0,
        },
        config::{DataContractConfig, v0::DataContractConfigV0, v1::DataContractConfigV1},
        document_type::{DocumentType, v1::DocumentTypeV1},
        group::{Group, v0::GroupV0},
        v1::DataContractV1,
    },
    identity::{
        KeyID, KeyType, PartialIdentity, Purpose, SecurityLevel,
        core_script::CoreScript,
        identity_public_key::v0::IdentityPublicKeyV0,
        state_transition::asset_lock_proof::{InstantAssetLockProof, chain::ChainAssetLockProof},
    },
    platform_value::{BinaryData, Value, string_encoding::Encoding},
    prelude::{AssetLockProof, DataContract, Identifier, IdentityPublicKey},
    serialization::{PlatformSerializable, PlatformSerializableWithPlatformVersion, Signable},
    state_transition::{
        JsonStateTransitionSerializationOptions, StateTransition, StateTransitionJsonConvert,
        StateTransitionValueConvert,
        data_contract_create_transition::{
            DataContractCreateTransition, DataContractCreateTransitionV0,
            methods::DataContractCreateTransitionMethodsV0,
        },
        identity_create_transition::{IdentityCreateTransition, v0::IdentityCreateTransitionV0},
    },
    version::{PlatformVersion, TryIntoPlatformVersioned},
};
use simple_signer::signer::SimpleSigner;

fn main() {
    let platform_version = PlatformVersion::get(9).unwrap();
    let config = DataContractConfig::V0(DataContractConfigV0 {
        can_be_deleted: true,
        readonly: false,
        keeps_history: true,
        documents_keep_history_contract_default: false,
        documents_mutable_contract_default: false,
        documents_can_be_deleted_contract_default: false,
        requires_identity_encryption_bounded_key: None,
        requires_identity_decryption_bounded_key: None,
    });

    let owner_id = Identifier::new([5; 32]);

    let data_contract_v1 = DataContractV1 {
        id: Identifier::new([1; 32]),
        version: 2,
        owner_id,
        document_types: BTreeMap::from([(
            "asdf".to_string(),
            DocumentType::try_from_schema(
                Identifier::new([1; 32]),
                "valid_name-a-b-123",
                Value::Map(vec![
                    (
                        Value::Text("type".to_string()),
                        Value::Text("object".to_string()),
                    ),
                    (
                        Value::Text("properties".to_string()),
                        Value::Map(vec![(
                            Value::Text("test".to_string()),
                            Value::Map(vec![
                                (
                                    Value::Text("type".to_string()),
                                    Value::Text("string".to_string()),
                                ),
                                (Value::Text("position".to_string()), Value::U32(0)),
                            ]),
                        )]),
                    ),
                    (
                        Value::Text("additionalProperties".to_string()),
                        Value::Bool(false),
                    ),
                ]),
                None,
                &config,
                true,
                &mut vec![],
                platform_version,
            )
            .unwrap(),
        )]),
        config,
        schema_defs: Some(BTreeMap::from([])),
        created_at: Some(100000),
        updated_at: Some(100001),
        created_at_block_height: Some(100002),
        updated_at_block_height: Some(100003),
        created_at_epoch: Some(10004),
        updated_at_epoch: Some(10005),
        groups: BTreeMap::from([(
            12,
            Group::V0(GroupV0 {
                members: BTreeMap::from([(Identifier::new([15; 32]), 1)]),
                required_power: 1,
            }),
        )]),
        tokens: BTreeMap::from([(
            0,
            TokenConfiguration::V0(TokenConfigurationV0 {
                conventions: TokenConfigurationConvention::V0(TokenConfigurationConventionV0 {
                    localizations: BTreeMap::from([(
                        "US".to_string(),
                        TokenConfigurationLocalization::V0(TokenConfigurationLocalizationV0 {
                            should_capitalize: true,
                            singular_form: "x".to_string(),
                            plural_form: "xs".to_string(),
                        }),
                    )]),
                    decimals: 2,
                }),
                conventions_change_rules: ChangeControlRules::V0(ChangeControlRulesV0 {
                    authorized_to_make_change: AuthorizedActionTakers::MainGroup,
                    admin_action_takers: AuthorizedActionTakers::ContractOwner,
                    changing_authorized_action_takers_to_no_one_allowed: false,
                    changing_admin_action_takers_to_no_one_allowed: false,
                    self_changing_admin_action_takers_allowed: true,
                }),
                base_supply: 12345678901234567890,
                max_supply: Some(18446744073709551615),
                keeps_history: TokenKeepsHistoryRules::V0(TokenKeepsHistoryRulesV0 {
                    keeps_transfer_history: false,
                    keeps_freezing_history: false,
                    keeps_minting_history: true,
                    keeps_burning_history: true,
                }),
                start_as_paused: false,
                max_supply_change_rules: ChangeControlRules::V0(ChangeControlRulesV0 {
                    authorized_to_make_change: AuthorizedActionTakers::MainGroup,
                    admin_action_takers: AuthorizedActionTakers::ContractOwner,
                    changing_authorized_action_takers_to_no_one_allowed: false,
                    changing_admin_action_takers_to_no_one_allowed: false,
                    self_changing_admin_action_takers_allowed: true,
                }),
                distribution_rules: TokenDistributionRules::V0(TokenDistributionRulesV0 {
                    perpetual_distribution: Some(TokenPerpetualDistribution::V0(
                        TokenPerpetualDistributionV0 {
                            distribution_type: RewardDistributionType::EpochBasedDistribution {
                                interval: 16,
                                function: DistributionFunction::InvertedLogarithmic {
                                    a: 1,
                                    d: 2,
                                    m: 3,
                                    n: 4,
                                    o: 5,
                                    start_moment: Some(1235678),
                                    b: 0,
                                    min_value: None,
                                    max_value: Some(112233445566),
                                },
                            },
                            distribution_recipient:
                                TokenDistributionRecipient::EvonodesByParticipation,
                        },
                    )),
                    perpetual_distribution_rules: ChangeControlRules::V0(ChangeControlRulesV0 {
                        authorized_to_make_change: AuthorizedActionTakers::MainGroup,
                        admin_action_takers: AuthorizedActionTakers::ContractOwner,
                        changing_authorized_action_takers_to_no_one_allowed: false,
                        changing_admin_action_takers_to_no_one_allowed: false,
                        self_changing_admin_action_takers_allowed: true,
                    }),
                    pre_programmed_distribution: Some(TokenPreProgrammedDistribution::V0(
                        TokenPreProgrammedDistributionV0 {
                            distributions: BTreeMap::from([]),
                        },
                    )),
                    new_tokens_destination_identity: Some(Identifier::new([18; 32])),
                    new_tokens_destination_identity_rules: ChangeControlRules::V0(
                        ChangeControlRulesV0 {
                            authorized_to_make_change: AuthorizedActionTakers::MainGroup,
                            admin_action_takers: AuthorizedActionTakers::ContractOwner,
                            changing_authorized_action_takers_to_no_one_allowed: false,
                            changing_admin_action_takers_to_no_one_allowed: false,
                            self_changing_admin_action_takers_allowed: true,
                        },
                    ),
                    minting_allow_choosing_destination: true,
                    minting_allow_choosing_destination_rules: ChangeControlRules::V0(
                        ChangeControlRulesV0 {
                            authorized_to_make_change: AuthorizedActionTakers::MainGroup,
                            admin_action_takers: AuthorizedActionTakers::ContractOwner,
                            changing_authorized_action_takers_to_no_one_allowed: false,
                            changing_admin_action_takers_to_no_one_allowed: false,
                            self_changing_admin_action_takers_allowed: true,
                        },
                    ),
                }),
                manual_minting_rules: ChangeControlRules::V0(ChangeControlRulesV0 {
                    authorized_to_make_change: AuthorizedActionTakers::MainGroup,
                    admin_action_takers: AuthorizedActionTakers::ContractOwner,
                    changing_authorized_action_takers_to_no_one_allowed: false,
                    changing_admin_action_takers_to_no_one_allowed: false,
                    self_changing_admin_action_takers_allowed: true,
                }),
                manual_burning_rules: ChangeControlRules::V0(ChangeControlRulesV0 {
                    authorized_to_make_change: AuthorizedActionTakers::MainGroup,
                    admin_action_takers: AuthorizedActionTakers::ContractOwner,
                    changing_authorized_action_takers_to_no_one_allowed: false,
                    changing_admin_action_takers_to_no_one_allowed: false,
                    self_changing_admin_action_takers_allowed: true,
                }),
                freeze_rules: ChangeControlRules::V0(ChangeControlRulesV0 {
                    authorized_to_make_change: AuthorizedActionTakers::MainGroup,
                    admin_action_takers: AuthorizedActionTakers::ContractOwner,
                    changing_authorized_action_takers_to_no_one_allowed: false,
                    changing_admin_action_takers_to_no_one_allowed: false,
                    self_changing_admin_action_takers_allowed: true,
                }),
                unfreeze_rules: ChangeControlRules::V0(ChangeControlRulesV0 {
                    authorized_to_make_change: AuthorizedActionTakers::MainGroup,
                    admin_action_takers: AuthorizedActionTakers::ContractOwner,
                    changing_authorized_action_takers_to_no_one_allowed: false,
                    changing_admin_action_takers_to_no_one_allowed: false,
                    self_changing_admin_action_takers_allowed: true,
                }),
                destroy_frozen_funds_rules: ChangeControlRules::V0(ChangeControlRulesV0 {
                    authorized_to_make_change: AuthorizedActionTakers::MainGroup,
                    admin_action_takers: AuthorizedActionTakers::ContractOwner,
                    changing_authorized_action_takers_to_no_one_allowed: false,
                    changing_admin_action_takers_to_no_one_allowed: false,
                    self_changing_admin_action_takers_allowed: true,
                }),
                emergency_action_rules: ChangeControlRules::V0(ChangeControlRulesV0 {
                    authorized_to_make_change: AuthorizedActionTakers::MainGroup,
                    admin_action_takers: AuthorizedActionTakers::ContractOwner,
                    changing_authorized_action_takers_to_no_one_allowed: false,
                    changing_admin_action_takers_to_no_one_allowed: false,
                    self_changing_admin_action_takers_allowed: true,
                }),
                main_control_group: Some(2),
                main_control_group_can_be_modified: AuthorizedActionTakers::NoOne,
            }),
        )]),
    };

    let data_contract_create = DataContractCreateTransition::V0(DataContractCreateTransitionV0 {
        data_contract: data_contract_v1
            .clone()
            .try_into_platform_versioned(&platform_version)
            .unwrap(),
        identity_nonce: 83838,
        user_fee_increase: 0,
        signature_public_key_id: 0,
        signature: BinaryData::new(vec![42; 32]),
    });

    let data_contract_create_bytes = data_contract_create.serialize_to_bytes().unwrap();
    println!(
        "data_contract_create_bytes: {}",
        to_hex(&data_contract_create_bytes)
    );

    let data_contract_create_signable_bytes = data_contract_create.signable_bytes().unwrap();
    println!(
        "data_contract_create_signable_bytes: {}",
        to_hex(&data_contract_create_signable_bytes)
    );

    let value = data_contract_create
        .to_json(JsonStateTransitionSerializationOptions {
            skip_signature: false,
            into_validating_json: true,
        })
        .unwrap();
    println!("data_contract_create JSON: {}", value.to_string());

    let identity_public_key = IdentityPublicKey::V0(IdentityPublicKeyV0 {
        id: 0,
        purpose: Purpose::AUTHENTICATION,
        security_level: SecurityLevel::CRITICAL,
        contract_bounds: None,
        key_type: KeyType::ECDSA_SECP256K1,
        read_only: true,
        data: BinaryData::from_string(
            "033a9a8b1e4c581a1987724c6697135d31c07ee7ac827e6a59cec022b04d51055f",
            Encoding::Hex,
        )
        .unwrap(),
        disabled_at: None,
    });

    let mut signer = SimpleSigner::default();
    signer.add_key(
        identity_public_key.clone(),
        BinaryData::from_string(
            "6c554775029f960891e3edf2d36b26a30d9a4b10034bb49f3a6c4617f557f7bc",
            Encoding::Hex,
        )
        .unwrap()
        .0
        .try_into()
        .unwrap(),
    );

    let identity = PartialIdentity {
        id: owner_id,
        loaded_public_keys: BTreeMap::from([(0, identity_public_key)]),
        balance: None,
        revision: None,
        not_found_public_keys: BTreeSet::new(),
    };

    let state_transition = DataContractCreateTransition::new_from_data_contract(
        DataContract::V1(data_contract_v1),
        83838,
        &identity,
        0,
        &signer,
        platform_version,
        None,
    )
    .unwrap();

    let state_transition_bytes = state_transition.serialize_to_bytes().unwrap();
    println!(
        "state_transition_bytes bytes: {}",
        to_hex(&state_transition_bytes)
    );

    let signable_bytes = state_transition.signable_bytes().unwrap();
    println!(
        "state_transition signable_bytes: {}",
        to_hex(&signable_bytes)
    );

    let hash_bytes = [
        1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32,
    ];
    let txid = Txid::from_raw_hash(sha256d::Hash::from_byte_array(hash_bytes));

    let op = OutPoint::new(txid, 12345);
    println!("OutPoint to_string: {}", op.to_string());
    let op_bytes: Vec<u8> =
        bincode::serde::encode_to_vec(op, bincode::config::standard().with_big_endian()).unwrap(); //op.try_into().unwrap();
    println!("OutPoint bincode: {}", to_hex(&op_bytes));

    let idc_chain = IdentityCreateTransition::V0(IdentityCreateTransitionV0 {
        public_keys: Vec::new(),
        asset_lock_proof: AssetLockProof::Chain(ChainAssetLockProof {
            core_chain_locked_height: 1234567,
            out_point: op,
        }),
        user_fee_increase: 0x42,
        signature: BinaryData::new(Vec::new()),
        identity_id: Identifier::new([0x12; 32]),
    });

    println!(
        "IdentityCreate with AssetLockProof.Chain: {}",
        to_hex(
            &StateTransition::IdentityCreate(idc_chain)
                .serialize_to_bytes()
                .unwrap()
        )
    );

    let idc_instant = IdentityCreateTransition::V0(IdentityCreateTransitionV0 {
        public_keys: Vec::new(),
        asset_lock_proof: AssetLockProof::Instant(InstantAssetLockProof {
            instant_lock: InstantLock {
                version: 0,
                inputs: Vec::new(),
                txid,
                cyclehash: BlockHash::from_raw_hash(sha256d::Hash::from_byte_array([0x12; 32])),
                signature: BLSSignature::from_byte_iter([0x48u8; 96].into_iter().map(Ok)).unwrap(),
            },
            transaction: Transaction {
                version: 2,
                lock_time: 0,
                input: Vec::new(),
                output: Vec::new(),
                special_transaction_payload: None,
            },
            output_index: 0,
        }),
        user_fee_increase: 0x42,
        signature: BinaryData::new(Vec::new()),
        identity_id: Identifier::new([0x12; 32]),
    });

    println!(
        "IdentityCreate with AssetLockProof.Instant: {}",
        to_hex(
            &StateTransition::IdentityCreate(idc_instant)
                .serialize_to_bytes()
                .unwrap()
        )
    );

    let pubkeyhash =
        PublicKey::from_str("02b1f2f08d44538b32938a0ad232c8217f8a328e0df115067ee6e5f48c50286c49")
            .unwrap()
            .pubkey_hash();

    let asset_lock_payload = AssetLockPayload {
        version: 1,
        credit_outputs: vec![TxOut {
            value: 100000000,
            script_pubkey: ScriptBuf::new_p2pkh(&pubkeyhash),
        }],
    };

    let tx = Transaction {
        version: 3,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_hex(
                    "10dfb70f669d7c067001ffae6f03edb7d6ed04476dbd9b02ff372c698815f4de",
                )
                .unwrap(),
                vout: 0,
            },
            script_sig: ScriptBuf::from_hex("").unwrap(),
            sequence: 0,
            witness: Witness::default(),
        }],
        output: vec![TxOut {
            value: 100000000,
            script_pubkey: ScriptBuf::new_op_return(&[]),
        }],
        special_transaction_payload: Some(TransactionPayload::AssetLockPayloadType(
            asset_lock_payload.clone(),
        )),
    };
    {
        let mut encoded = Vec::new();
        pubkeyhash.consensus_encode(&mut encoded).unwrap();
        println!("encoded pubkeyhash: {}", to_hex(&encoded));
    }
    {
        let mut encoded = Vec::new();
        tx.input.consensus_encode(&mut encoded).unwrap();
        println!("encoded tx inputs: {}", to_hex(&encoded));
    }
    {
        let mut encoded = Vec::new();
        tx.output.consensus_encode(&mut encoded).unwrap();
        println!("encoded tx outputs: {}", to_hex(&encoded));
    }
    {
        let mut encoded = Vec::new();
        tx.special_transaction_payload
            .as_ref()
            .unwrap()
            .consensus_encode(&mut encoded)
            .unwrap();

        let mut encoded_again = Vec::new();
        encoded.consensus_encode(&mut encoded_again).unwrap();
        println!("encoded tx payload: {}", to_hex(&encoded_again));
    }
    let mut tx_encoded = Vec::new();
    tx.consensus_encode(&mut tx_encoded).unwrap();
    println!("encoded tx: {}", to_hex(&tx_encoded));

    /*
    encoded pubkeyhash: 82ca6828fa0341ad712ee5fda71daf9ec67e430a
    encoded tx inputs: 01def41588692c37ff029bbd6d4704edd6b7ed036faeff0170067c9d660fb7df10000000000000000000
    encoded tx outputs: 0100e1f50500000000026a00
    encoded tx payload: 24010100e1f505000000001976a91482ca6828fa0341ad712ee5fda71daf9ec67e430a88ac
    encoded tx: 0300080001def41588692c37ff029bbd6d4704edd6b7ed036faeff0170067c9d660fb7df100000000000000000000100e1f50500000000026a000000000024010100e1f505000000001976a91482ca6828fa0341ad712ee5fda71daf9ec67e430a88ac
    */

    /*
    assetInfo.publicKey 02b1f2f08d44538b32938a0ad232c8217f8a328e0df115067ee6e5f48c50286c49
    pubkeyhash 82ca6828fa0341ad712ee5fda71daf9ec67e430a
    p2pkh script 76a91482ca6828fa0341ad712ee5fda71daf9ec67e430a88ac
    assetLockScript       010100e1f505000000001976a91482ca6828fa0341ad712ee5fda71daf9ec67e430a88ac
    assetLockPayloadBytes 0101fc05f5e1001976a91482ca6828fa0341ad712ee5fda71daf9ec67e430a88ac

    Transaction Proof Hex:
    0300080001def41588692c37ff029bbd6d4704edd6b7ed036faeff0170067c9d660fb7df100000000000000000000100e1f50500000000026a0000000000210101fc05f5e1001976a91482ca6828fa0341ad712ee5fda71daf9ec67e430a88ac
    */

    let signed_tx_bytes = from_hex(
        "0300080001def41588692c37ff029bbd6d4704edd6b7ed036faeff0170067c9d660fb7df10000000006b483045022100c29115f386139b54a8786c2ca2585841b7c88daebab6898943354de2c3164bc00220447285ba52077cf67f711a4c9f9f27230e943ea71ad004adbba9abe6d35fc4cb8121034b5d935eca4909b986637dc655422b255c803817124b16b5159577cc12474572ffffffff0100e1f50500000000026a00000000002e0101fc05f5e1002676a92102b1f2f08d44538b32938a0ad232c8217f8a328e0df115067ee6e5f48c50286c4988ac"
    ).unwrap();

    let mut cursor = std::io::Cursor::new(&signed_tx_bytes);
    let tx = Transaction::consensus_decode(&mut cursor).unwrap();

    println!("tx: {:#?}", tx);
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn from_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}
