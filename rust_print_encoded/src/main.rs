use std::collections::{BTreeMap, BTreeSet};

use dpp::{
    dashcore::{
        OutPoint, Txid,
        hashes::{Hash, sha256d},
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
        identity_public_key::v0::IdentityPublicKeyV0,
    },
    platform_value::{BinaryData, Value, string_encoding::Encoding},
    prelude::{DataContract, Identifier, IdentityPublicKey},
    serialization::{PlatformSerializable, PlatformSerializableWithPlatformVersion, Signable},
    state_transition::{
        JsonStateTransitionSerializationOptions, StateTransition, StateTransitionJsonConvert,
        StateTransitionValueConvert,
        data_contract_create_transition::{
            DataContractCreateTransition, DataContractCreateTransitionV0,
            methods::DataContractCreateTransitionMethodsV0,
        },
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
                // let schema = platform_value!({
                //     "type": "object",
                //     "properties": {
                //         "test": {
                //             "type": "string",
                //             "position": 0,
                //         }
                //     },
                //     "creationRestrictionMode": 1,
                //     "additionalProperties": false,
                // });
                Value::Map(vec![
                    (
                        Value::Text("type".to_string()),
                        Value::Text("object".to_string()),
                    ),
                    // (
                    //     Value::Text("$schema".to_string()),
                    //     Value::Text("https://github.com/dashpay/platform/blob/master/packages/rs-dpp/schema/meta_schemas/document/v0/document-meta.json".to_string()),
                    // ),
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
    let op_bytes: Vec<u8> = op.try_into().unwrap();
    println!("OutPoint bincode: {}", to_hex(&op_bytes));
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
