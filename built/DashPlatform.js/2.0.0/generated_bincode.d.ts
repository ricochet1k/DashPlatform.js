export const Hash: any;
/** @type {*} */
export const Value: any;
export const BinaryData: any;
export const BlockHeight: any;
export const BlockHeightInterval: any;
export const Credits: any;
export const DefinitionName: any;
export const DerivationEncryptionKeyIndex: any;
export const DocumentName: any;
export const EpochIndex: any;
export const EpochInterval: any;
export const GroupContractPosition: any;
export const GroupMemberPower: any;
export const GroupRequiredPower: any;
export const Hash256: any;
export const IdentifierBytes32: any;
export const IdentityNonce: any;
export const KeyID: any;
/**
 * allow non_camel_case_types
 * repr u8
 */
export const KeyType: any;
/** repr u8 */
export const Pooling: any;
/** repr u8 */
export const Purpose: any;
/** "Raw" instant lock for serialization */
export const RawInstantLockProof: any;
export const RecipientKeyIndex: any;
export const Revision: any;
export const RootEncryptionKeyIndex: any;
/**
 * An owned, growable script.
 *
 *  `ScriptBuf` is the most common script type that has the ownership over the contents of the
 *  script. It has a close relationship with its borrowed counterpart, [`Script`].
 *
 *  Just as other similar types, this implements [`Deref`], so [deref coercions] apply. Also note
 *  that all the safety/validity restrictions that apply to [`Script`] apply to `ScriptBuf` as well.
 *
 *  [deref coercions]: https://doc.rust-lang.org/std/ops/trait.Deref.html#more-on-deref-coercion
 */
export const ScriptBuf: any;
/** repr u8 */
export const SecurityLevel: any;
export const SenderKeyIndex: any;
export const SharedEncryptedNote: any;
/**
 * The Storage Key requirements
 * repr u8
 */
export const StorageKeyRequirements: any;
export const TimestampMillis: any;
export const TimestampMillisInterval: any;
export const TokenAmount: any;
export const TokenConfigurationLocalizationV0: any;
export const TokenContractPosition: any;
/**
 * Represents the type of token distribution.
 *
 *  - `PreProgrammed`: A scheduled distribution with predefined rules.
 *  - `Perpetual`: A continuous or recurring distribution.
 */
export const TokenDistributionType: any;
export const TokenEmergencyAction: any;
/**
 * The rules for keeping a ledger as documents of token events.
 *  Config update, Destroying Frozen Funds, Emergency Action,
 *  Pre Programmed Token Release always require an entry to the ledger
 */
export const TokenKeepsHistoryRulesV0: any;
/** A transaction output, which defines new coins to be created from old ones. */
export const TxOut: any;
/** A dash transaction hash/transaction ID. */
export const Txid: any;
export const UserFeeIncrease: any;
export const ValueMap: any;
/**
 * An Asset Lock payload. This is contained as the payload of an asset lock special transaction.
 *  The Asset Lock Special transaction and this payload is described in the Asset Lock DIP2X
 *  (todo:update this).
 *  An Asset Lock can fund multiple Identity registrations or top ups.
 *  The Asset Lock payload credit outputs field contains a vector of TxOuts.
 *  Each TxOut refers to a funding of an Identity.
 */
export const AssetLockPayload: any;
export const DashcoreScript: any;
export const DataContractConfigV0: any;
export const DataContractConfigV1: any;
export const DistributionFunction: any;
export const Identifier: any;
/** platform_serialize unversioned */
export const IdentityCreditTransferTransitionV0: any;
export const InstantAssetLockProof: any;
/** A reference to a transaction output. */
export const OutPoint: any;
export const PrivateEncryptedNote: any;
/**
 * A representation of a dynamic value that can handled dynamically
 * non_exhaustive
 */
export const REAL_Value: any;
/**
 * A resource votes is a votes determining what we should do with a contested resource.
 *  For example Alice and Bob both want the username "Malaka"
 *  Some would vote for Alice to get it by putting in her Identifier.
 *  Some would vote for Bob to get it by putting in Bob's Identifier.
 *  Let's say someone voted, but is now not quite sure of their votes, they can abstain.
 *  Lock is there to signal that the shared resource should be given to no one.
 *  In this case Malaka might have a bad connotation in Greek, hence some might votes to Lock
 *  the name.
 */
export const ResourceVoteChoice: any;
export const RewardDistributionType: any;
export const TokenConfigurationLocalization: any;
/** platform_serialize unversioned */
export const TokenDistributionRecipient: any;
export const TokenKeepsHistoryRules: any;
export const TokenPerpetualDistributionV0: any;
export const TokenPreProgrammedDistributionV0: any;
export const AuthorizedActionTakers: any;
/**
 * Instant Asset Lock Proof is a part of Identity Create and Identity Topup
 *  transitions. It is a proof that specific output of dash is locked in credits
 *  pull and the transitions can mint credits and populate identity's balance.
 *  To prove that the output is locked, a height where transaction was chain locked is provided.
 */
export const ChainAssetLockProof: any;
export const ChangeControlRulesV0: any;
/**
 * platform_serialize unversioned
 * platform_serialize limit = 100000
 */
export const ContestedDocumentResourceVotePoll: any;
/**
 * A contract bounds is the bounds that the key has influence on.
 *  For authentication keys the bounds mean that the keys can only be used to sign
 *  within the specified contract.
 *  For encryption decryption this tells clients to only use these keys for specific
 *  contracts.
 *
 * repr u8
 */
export const ContractBounds: any;
export const CoreScript: any;
export const DataContractConfig: any;
export const DataContractInSerializationFormatV0: any;
export const DocumentBaseTransitionV0: any;
export const GroupStateTransitionInfo: any;
/** platform_serialize unversioned */
export const GroupV0: any;
/**
 * platform_serialize unversioned
 * platform_version_path_bounds "dpp.state_transition_serialization_versions.identity_credit_transfer_state_transition"
 */
export const IdentityCreditTransferTransition: any;
export const IdentityCreditWithdrawalTransitionV0: any;
export const IdentityCreditWithdrawalTransitionV1: any;
export const IdentityPublicKeyInCreationV0: any;
export const IdentityPublicKeyV0: any;
export const TokenBaseTransitionV0: any;
export const TokenConfigurationConventionV0: any;
/** platform_serialize unversioned */
export const TokenPerpetualDistribution: any;
export const TokenPreProgrammedDistribution: any;
/**
 * platform_serialize unversioned
 * platform_serialize limit = 100000
 */
export const VotePoll: any;
export const AssetLockProof: any;
export const ChangeControlRules: any;
export const DocumentBaseTransition: any;
export const DocumentCreateTransitionV0: any;
export const DocumentDeleteTransitionV0: any;
export const DocumentPurchaseTransitionV0: any;
export const DocumentReplaceTransitionV0: any;
export const DocumentTransferTransitionV0: any;
export const DocumentUpdatePriceTransitionV0: any;
/** platform_serialize unversioned */
export const Group: any;
/**
 * platform_serialize unversioned
 * platform_version_path "dpp.state_transition_serialization_versions.identity_credit_withdrawal_state_transition"
 */
export const IdentityCreditWithdrawalTransition: any;
/** platform_serialize limit = 2000 , unversioned */
export const IdentityPublicKey: any;
export const IdentityPublicKeyInCreation: any;
export const IdentityTopUpTransitionV0: any;
export const IdentityUpdateTransitionV0: any;
/** platform_serialize unversioned */
export const ResourceVoteV0: any;
export const TokenBaseTransition: any;
export const TokenBurnTransitionV0: any;
export const TokenClaimTransitionV0: any;
export const TokenConfigurationConvention: any;
export const TokenDestroyFrozenFundsTransitionV0: any;
export const TokenDistributionRulesV0: any;
export const TokenEmergencyActionTransitionV0: any;
export const TokenFreezeTransitionV0: any;
export const TokenMintTransitionV0: any;
export const TokenTransferTransitionV0: any;
export const TokenUnfreezeTransitionV0: any;
export const DocumentCreateTransition: any;
export const DocumentDeleteTransition: any;
export const DocumentPurchaseTransition: any;
export const DocumentReplaceTransition: any;
export const DocumentTransferTransition: any;
export const DocumentUpdatePriceTransition: any;
export const IdentityCreateTransitionV0: any;
/**
 * platform_serialize unversioned
 * platform_version_path_bounds "dpp.state_transition_serialization_versions.identity_top_up_state_transition"
 */
export const IdentityTopUpTransition: any;
/**
 * platform_serialize unversioned
 * platform_version_path_bounds "dpp.state_transition_serialization_versions.identity_update_state_transition"
 */
export const IdentityUpdateTransition: any;
/** platform_serialize limit = 15000 , unversioned */
export const ResourceVote: any;
export const TokenBurnTransition: any;
export const TokenClaimTransition: any;
export const TokenConfigurationChangeItem: any;
export const TokenDestroyFrozenFundsTransition: any;
export const TokenDistributionRules: any;
export const TokenEmergencyActionTransition: any;
export const TokenFreezeTransition: any;
export const TokenMintTransition: any;
export const TokenTransferTransition: any;
export const TokenUnfreezeTransition: any;
/** platform_serialize limit = 15000 , unversioned */
export const Vote: any;
export const DocumentTransition: any;
/**
 * platform_serialize unversioned
 * platform_version_path_bounds "dpp.state_transition_serialization_versions.identity_create_state_transition"
 */
export const IdentityCreateTransition: any;
/** platform_serialize unversioned */
export const MasternodeVoteTransitionV0: any;
export const TokenConfigUpdateTransitionV0: any;
export const TokenConfigurationV0: any;
export const BatchTransitionV0: any;
/**
 * platform_serialize unversioned
 * platform_version_path_bounds "dpp.state_transition_serialization_versions.masternode_vote_state_transition"
 */
export const MasternodeVoteTransition: any;
export const TokenConfigUpdateTransition: any;
export const TokenConfiguration: any;
export const TokenTransition: any;
export const BatchedTransition: any;
export const DataContractInSerializationFormatV1: any;
export const BatchTransitionV1: any;
export const DataContractInSerializationFormat: any;
export const DataContractUpdateTransitionV0: any;
/**
 * platform_serialize unversioned
 * platform_version_path_bounds "dpp.state_transition_serialization_versions.batch_state_transition"
 */
export const BatchTransition: any;
/** DataContractCreateTransitionV0 has the same encoding structure */
export const DataContractCreateTransitionV0: any;
/**
 * platform_serialize unversioned
 * platform_version_path_bounds "dpp.state_transition_serialization_versions.contract_update_state_transition"
 */
export const DataContractUpdateTransition: any;
/**
 * platform_serialize unversioned
 * platform_version_path_bounds "dpp.state_transition_serialization_versions.contract_create_state_transition"
 */
export const DataContractCreateTransition: any;
/**
 * platform_serialize unversioned
 * platform_serialize limit = 100000
 */
export const StateTransition: any;
