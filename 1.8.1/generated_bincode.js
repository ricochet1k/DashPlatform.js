import {
  Bool, Bytes, Enum, VariantDiscriminant, FixedBytes, Lazy, Struct, StructTuple,
  Int128, Int16, Int32, Int64, Int8, Uint128, Uint16, Uint32, Uint64, Uint8, Float64,
  VarInt, VarUint, Vec, Tuple, Map, Option, String, Nothing, Range, NotSignable,
  SocketAddr,
} from "../bincode.ts"
import { Transaction } from "../bincode_types.ts";
export const Hash = Bytes; //FixedBytes(32)

/** @type {*} */
export const Value = Lazy("Value", () => REAL_Value);

export const BinaryData = StructTuple("BinaryData",
  Bytes,
);

export const Credits = VarUint

export const DefinitionName = String

export const DocumentName = String

export const Hash256 = FixedBytes(32)

export const IdentifierBytes32 = StructTuple("IdentifierBytes32",
  FixedBytes(32),
);

export const IdentityNonce = VarUint

export const KeyID = VarUint

/**
 * allow non_camel_case_types
 * repr u8
 */
export const KeyType = Enum("KeyType", /** @type {const} */ ({
  /** default */
  ECDSA_SECP256K1: [],
  BLS12_381: [],
  ECDSA_HASH160: [],
  BIP13_SCRIPT_HASH: [],
  EDDSA_25519_HASH160: [],
}))

/** repr u8 */
export const Pooling = Enum("Pooling", /** @type {const} */ ({
  /** default */
  Never: [],
  IfAvailable: [],
  Standard: [],
}))

/** repr u8 */
export const Purpose = Enum("Purpose", /** @type {const} */ ({
  /**
   * at least one authentication key must be registered for all security levels
   * default
   */
  AUTHENTICATION: [],
  /** this key cannot be used for signing documents */
  ENCRYPTION: [],
  /** this key cannot be used for signing documents */
  DECRYPTION: [],
  /** this key is used to sign credit transfer and withdrawal state transitions */
  TRANSFER: [],
  /** this key cannot be used for signing documents */
  SYSTEM: [],
  /** this key cannot be used for signing documents */
  VOTING: [],
  /** this key is used to prove ownership of a masternode or evonode */
  OWNER: [],
}))

// !ENCODE
/** "Raw" instant lock for serialization */
export const RawInstantLockProof = Struct("RawInstantLockProof", {
  instant_lock: BinaryData,
  transaction: BinaryData,
  output_index: VarUint,
});

export const Revision = VarUint

// !ENCODE
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
export const ScriptBuf = StructTuple("ScriptBuf",
  Bytes,
);

/** repr u8 */
export const SecurityLevel = Enum("SecurityLevel", /** @type {const} */ ({
  MASTER: [],
  CRITICAL: [],
  /** default */
  HIGH: [],
  MEDIUM: [],
}))

/**
 * The Storage Key requirements
 * repr u8
 */
export const StorageKeyRequirements = Enum("StorageKeyRequirements", /** @type {const} */ ({
  Unique: [],
  Multiple: [],
  MultipleReferenceToLatest: [],
}))

export const TimestampMillis = VarUint

// !ENCODE
/** A transaction output, which defines new coins to be created from old ones. */
export const TxOut = Struct("TxOut", {
  /** The value of the output, in satoshis. */
  value: VarUint,
  /** The script which must be satisfied for the output to be spent. */
  script_pubkey: ScriptBuf,
});

// !ENCODE
/** A dash transaction hash/transaction ID. */
export const Txid = StructTuple("Txid",
  Hash,
);

export const UserFeeIncrease = VarUint

export const ValueMap = Vec(Tuple(Value, Value))

// !ENCODE
/**
 * An Asset Lock payload. This is contained as the payload of an asset lock special transaction.
 *  The Asset Lock Special transaction and this payload is described in the Asset Lock DIP2X
 *  (todo:update this).
 *  An Asset Lock can fund multiple Identity registrations or top ups.
 *  The Asset Lock payload credit outputs field contains a vector of TxOuts.
 *  Each TxOut refers to a funding of an Identity.
 */
export const AssetLockPayload = Struct("AssetLockPayload", {
  version: Uint8,
  credit_outputs: Vec(TxOut),
});

export const DashcoreScript = ScriptBuf

export const DataContractConfigV0 = Struct("DataContractConfigV0", {
  /**
   * Can the contract ever be deleted. If the contract is deleted, so should be all
   *  documents associated with it. TODO: There should also be a way to "stop" the contract -
   *  contract and documents are kept in the system, but no new documents can be added to it
   */
  can_be_deleted: Bool,
  /**
   * Is the contract mutable. Means that the document definitions can be changed or new
   *  document definitions can be added to the contract
   */
  readonly: Bool,
  /** Does the contract keep history when the contract itself changes */
  keeps_history: Bool,
  /**
   * Do documents in the contract keep history. This is a default for all documents in
   *  the contract, but can be overridden by the document itself
   */
  documents_keep_history_contract_default: Bool,
  /**
   * Are documents in the contract mutable? This specifies whether the documents can be
   *  changed. This is a default for all document types in the contract, but can be
   *  overridden by the document type config.
   */
  documents_mutable_contract_default: Bool,
  /**
   * Can documents in the contract be deleted? This specifies whether the documents can be
   *  deleted. This is a default for all document types in the contract, but can be
   *  overridden by the document types itself.
   */
  documents_can_be_deleted_contract_default: Bool,
  /** Encryption key storage requirements */
  requires_identity_encryption_bounded_key: Option(StorageKeyRequirements),
  /** Decryption key storage requirements */
  requires_identity_decryption_bounded_key: Option(StorageKeyRequirements),
});

export const Identifier = StructTuple("Identifier",
  IdentifierBytes32,
);

/** platform_serialize unversioned */
export const IdentityCreditTransferTransitionV0 = Struct("IdentityCreditTransferTransitionV0", {
  identity_id: Identifier,
  recipient_id: Identifier,
  amount: VarUint,
  nonce: IdentityNonce,
  user_fee_increase: UserFeeIncrease,
  signature_public_key_id: NotSignable(KeyID),
  signature: NotSignable(BinaryData),
});

export const InstantAssetLockProof = RawInstantLockProof

// !ENCODE
/** A reference to a transaction output. */
export const OutPoint = Struct("OutPoint", {
  /** The referenced transaction's txid. */
  txid: Txid,
  /** The index of the referenced output in its transaction's vout. */
  vout: VarUint,
});

/**
 * A representation of a dynamic value that can handled dynamically
 * non_exhaustive
 */
export const REAL_Value = Enum("Value", /** @type {const} */ ({
  /** A u128 integer */
  U128: [VarUint],
  /** A i128 integer */
  I128: [VarInt],
  /** A u64 integer */
  U64: [VarUint],
  /** A i64 integer */
  I64: [VarInt],
  /** A u32 integer */
  U32: [VarUint],
  /** A i32 integer */
  I32: [VarInt],
  /** A u16 integer */
  U16: [VarUint],
  /** A i16 integer */
  I16: [VarInt],
  /** A u8 integer */
  U8: [Uint8],
  /** A i8 integer */
  I8: [Int8],
  /** Bytes */
  Bytes: [Bytes],
  /** Bytes 20 */
  Bytes20: [FixedBytes(20)],
  /** Bytes 32 */
  Bytes32: [FixedBytes(32)],
  /** Bytes 36 : Useful for outpoints */
  Bytes36: [FixedBytes(36)],
  /** An enumeration of u8 */
  EnumU8: [Bytes],
  /** An enumeration of strings */
  EnumString: [Vec(String)],
  /**
   * Identifier
   *  The identifier is very similar to bytes, however it is serialized to Base58 when converted
   *  to a JSON Value
   */
  Identifier: [Hash256],
  /** A float */
  Float: [Float64],
  /** A string */
  Text: [String],
  /** A boolean */
  Bool: [Bool],
  /** Null */
  Null: [],
  /** An array */
  Array: [Vec(Value)],
  /** A map */
  Map: [ValueMap],
}))

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
export const ResourceVoteChoice = Enum("ResourceVoteChoice", /** @type {const} */ ({
  TowardsIdentity: [Identifier],
  /** default */
  Abstain: [],
  Lock: [],
}))

// !ENCODE
/**
 * Instant Asset Lock Proof is a part of Identity Create and Identity Topup
 *  transitions. It is a proof that specific output of dash is locked in credits
 *  pull and the transitions can mint credits and populate identity's balance.
 *  To prove that the output is locked, a height where transaction was chain locked is provided.
 */
export const ChainAssetLockProof = Struct("ChainAssetLockProof", {
  /** Core height on which the asset lock transaction was chain locked or higher */
  core_chain_locked_height: VarUint,
  /** A reference to Asset Lock Special Transaction ID and output index in the payload */
  out_point: OutPoint,
});

/**
 * platform_serialize unversioned
 * platform_serialize limit = 100000
 */
export const ContestedDocumentResourceVotePoll = Struct("ContestedDocumentResourceVotePoll", {
  contract_id: Identifier,
  document_type_name: String,
  index_name: String,
  index_values: Vec(Value),
});

/**
 * A contract bounds is the bounds that the key has influence on.
 *  For authentication keys the bounds mean that the keys can only be used to sign
 *  within the specified contract.
 *  For encryption decryption this tells clients to only use these keys for specific
 *  contracts.
 * 
 * repr u8
 */
export const ContractBounds = Enum("ContractBounds", /** @type {const} */ ({
  /** this key can only be used within a specific contract */
  SingleContract: {
    id: Identifier,
  },
  /** this key can only be used within a specific contract and for a specific document type */
  SingleContractDocumentType: {
    id: Identifier,
    document_type_name: String,
  },
}))

// !ENCODE
export const CoreScript = StructTuple("CoreScript",
  DashcoreScript,
);

export const DataContractConfig = Enum("DataContractConfig", /** @type {const} */ ({
  V0: [DataContractConfigV0],
}))

export const DataContractInSerializationFormatV0 = Struct("DataContractInSerializationFormatV0", {
  /** A unique identifier for the data contract. */
  id: Identifier,
  /** Internal configuration for the contract. */
  config: DataContractConfig,
  /** The version of this data contract. */
  version: VarUint,
  /** The identifier of the contract owner. */
  owner_id: Identifier,
  /** Shared subschemas to reuse across documents as $defs object */
  schema_defs: Option(Map(DefinitionName, Value)),
  /** Document JSON Schemas per type */
  document_schemas: Map(DocumentName, Value),
});

export const DocumentBaseTransitionV0 = Struct("DocumentBaseTransitionV0", {
  /** The document ID */
  id: Identifier,
  identity_contract_nonce: IdentityNonce,
  /** Name of document type found int the data contract associated with the `data_contract_id` */
  document_type_name: String,
  /** Data contract ID generated from the data contract's `owner_id` and `entropy` */
  data_contract_id: Identifier,
});

/**
 * platform_serialize unversioned
 * platform_version_path_bounds "dpp.state_transition_serialization_versions.identity_credit_transfer_state_transition"
 */
export const IdentityCreditTransferTransition = Enum("IdentityCreditTransferTransition", /** @type {const} */ ({
  V0: [IdentityCreditTransferTransitionV0],
}))

export const IdentityCreditWithdrawalTransitionV0 = Struct("IdentityCreditWithdrawalTransitionV0", {
  identity_id: Identifier,
  amount: VarUint,
  core_fee_per_byte: VarUint,
  pooling: Pooling,
  output_script: CoreScript,
  nonce: IdentityNonce,
  user_fee_increase: UserFeeIncrease,
  signature_public_key_id: NotSignable(KeyID),
  signature: NotSignable(BinaryData),
});

export const IdentityCreditWithdrawalTransitionV1 = Struct("IdentityCreditWithdrawalTransitionV1", {
  identity_id: Identifier,
  amount: VarUint,
  core_fee_per_byte: VarUint,
  pooling: Pooling,
  /** If the send to output script is None, then we send the withdrawal to the address set by core */
  output_script: Option(CoreScript),
  nonce: IdentityNonce,
  user_fee_increase: UserFeeIncrease,
  signature_public_key_id: NotSignable(KeyID),
  signature: NotSignable(BinaryData),
});

export const IdentityPublicKeyInCreationV0 = Struct("IdentityPublicKeyInCreationV0", {
  id: KeyID,
  key_type: KeyType,
  purpose: Purpose,
  security_level: SecurityLevel,
  contract_bounds: Option(ContractBounds),
  read_only: Bool,
  data: BinaryData,
  /** The signature is needed for ECDSA_SECP256K1 Key type and BLS12_381 Key type */
  signature: NotSignable(BinaryData),
});

export const IdentityPublicKeyV0 = Struct("IdentityPublicKeyV0", {
  id: KeyID,
  purpose: Purpose,
  security_level: SecurityLevel,
  contract_bounds: Option(ContractBounds),
  key_type: KeyType,
  read_only: Bool,
  data: BinaryData,
  disabled_at: Option(TimestampMillis),
});

/**
 * platform_serialize unversioned
 * platform_serialize limit = 100000
 */
export const VotePoll = Enum("VotePoll", /** @type {const} */ ({
  ContestedDocumentResourceVotePoll: [ContestedDocumentResourceVotePoll],
}))

export const AssetLockProof = Enum("AssetLockProof", /** @type {const} */ ({
  Instant: [InstantAssetLockProof],
  Chain: [ChainAssetLockProof],
}))

export const DataContractInSerializationFormat = Enum("DataContractInSerializationFormat", /** @type {const} */ ({
  V0: [DataContractInSerializationFormatV0],
}))

export const DataContractUpdateTransitionV0 = Struct("DataContractUpdateTransitionV0", {
  identity_contract_nonce: IdentityNonce,
  data_contract: DataContractInSerializationFormat,
  user_fee_increase: UserFeeIncrease,
  signature_public_key_id: NotSignable(KeyID),
  signature: NotSignable(BinaryData),
});

export const DocumentBaseTransition = Enum("DocumentBaseTransition", /** @type {const} */ ({
  V0: [DocumentBaseTransitionV0],
}))

export const DocumentCreateTransitionV0 = Struct("DocumentCreateTransitionV0", {
  /** Document Base Transition */
  base: DocumentBaseTransition,
  /** Entropy used to create a Document ID. */
  entropy: FixedBytes(32),
  data: Map(String, Value),
  /**
   * Pre funded balance (for unique index conflict resolution voting - the identity will put money
   *  aside that will be used by voters to vote)
   *  This is a map of index names to the amount we want to prefund them for
   *  Since index conflict resolution is not a common feature most often nothing should be added here.
   */
  prefunded_voting_balance: Option(Tuple(String, Credits)),
});

export const DocumentDeleteTransitionV0 = Struct("DocumentDeleteTransitionV0", {
  base: DocumentBaseTransition,
});

export const DocumentPurchaseTransitionV0 = Struct("DocumentPurchaseTransitionV0", {
  base: DocumentBaseTransition,
  revision: Revision,
  price: Credits,
});

export const DocumentReplaceTransitionV0 = Struct("DocumentReplaceTransitionV0", {
  base: DocumentBaseTransition,
  revision: Revision,
  data: Map(String, Value),
});

export const DocumentTransferTransitionV0 = Struct("DocumentTransferTransitionV0", {
  base: DocumentBaseTransition,
  revision: Revision,
  recipient_owner_id: Identifier,
});

export const DocumentUpdatePriceTransitionV0 = Struct("DocumentUpdatePriceTransitionV0", {
  base: DocumentBaseTransition,
  revision: Revision,
  price: Credits,
});

/**
 * platform_serialize unversioned
 * platform_version_path "dpp.state_transition_serialization_versions.identity_credit_withdrawal_state_transition"
 */
export const IdentityCreditWithdrawalTransition = Enum("IdentityCreditWithdrawalTransition", /** @type {const} */ ({
  V0: [IdentityCreditWithdrawalTransitionV0],
  V1: [IdentityCreditWithdrawalTransitionV1],
}))

/** platform_serialize limit = 2000 , unversioned */
export const IdentityPublicKey = Enum("IdentityPublicKey", /** @type {const} */ ({
  V0: [IdentityPublicKeyV0],
}))

export const IdentityPublicKeyInCreation = Enum("IdentityPublicKeyInCreation", /** @type {const} */ ({
  V0: [IdentityPublicKeyInCreationV0],
}))

export const IdentityTopUpTransitionV0 = Struct("IdentityTopUpTransitionV0", {
  asset_lock_proof: AssetLockProof,
  identity_id: Identifier,
  user_fee_increase: UserFeeIncrease,
  signature: NotSignable(BinaryData),
});

export const IdentityUpdateTransitionV0 = Struct("IdentityUpdateTransitionV0", {
  /** Unique identifier of the identity to be updated */
  identity_id: Identifier,
  /** The revision of the identity after update */
  revision: Revision,
  /** Identity nonce for this transition to prevent replay attacks */
  nonce: IdentityNonce,
  /**
   * Public Keys to add to the Identity
   *  we want to skip serialization of transitions, as we does it manually in `to_object()`  and `to_json()`
   */
  add_public_keys: Vec(IdentityPublicKeyInCreation),
  /** Identity Public Keys ID's to disable for the Identity */
  disable_public_keys: Vec(KeyID),
  /** The fee multiplier */
  user_fee_increase: UserFeeIncrease,
  /** The ID of the public key used to sing the State Transition */
  signature_public_key_id: NotSignable(KeyID),
  /** Cryptographic signature of the State Transition */
  signature: NotSignable(BinaryData),
});

/** platform_serialize unversioned */
export const ResourceVoteV0 = Struct("ResourceVoteV0", {
  vote_poll: VotePoll,
  resource_vote_choice: ResourceVoteChoice,
});

/** DataContractCreateTransitionV0 has the same encoding structure */
export const DataContractCreateTransitionV0 = Struct("DataContractCreateTransitionV0", {
  data_contract: DataContractInSerializationFormat,
  identity_nonce: IdentityNonce,
  user_fee_increase: UserFeeIncrease,
  signature_public_key_id: NotSignable(KeyID),
  signature: NotSignable(BinaryData),
});

/**
 * platform_serialize unversioned
 * platform_version_path_bounds "dpp.state_transition_serialization_versions.contract_update_state_transition"
 */
export const DataContractUpdateTransition = Enum("DataContractUpdateTransition", /** @type {const} */ ({
  V0: [DataContractUpdateTransitionV0],
}))

export const DocumentCreateTransition = Enum("DocumentCreateTransition", /** @type {const} */ ({
  V0: [DocumentCreateTransitionV0],
}))

export const DocumentDeleteTransition = Enum("DocumentDeleteTransition", /** @type {const} */ ({
  V0: [DocumentDeleteTransitionV0],
}))

export const DocumentPurchaseTransition = Enum("DocumentPurchaseTransition", /** @type {const} */ ({
  V0: [DocumentPurchaseTransitionV0],
}))

export const DocumentReplaceTransition = Enum("DocumentReplaceTransition", /** @type {const} */ ({
  V0: [DocumentReplaceTransitionV0],
}))

export const DocumentTransferTransition = Enum("DocumentTransferTransition", /** @type {const} */ ({
  V0: [DocumentTransferTransitionV0],
}))

export const DocumentUpdatePriceTransition = Enum("DocumentUpdatePriceTransition", /** @type {const} */ ({
  V0: [DocumentUpdatePriceTransitionV0],
}))

export const IdentityCreateTransitionV0 = Struct("IdentityCreateTransitionV0", {
  public_keys: Vec(IdentityPublicKeyInCreation),
  asset_lock_proof: AssetLockProof,
  user_fee_increase: UserFeeIncrease,
  signature: NotSignable(BinaryData),
  identity_id: NotSignable(Identifier),
});

/**
 * platform_serialize unversioned
 * platform_version_path_bounds "dpp.state_transition_serialization_versions.identity_top_up_state_transition"
 */
export const IdentityTopUpTransition = Enum("IdentityTopUpTransition", /** @type {const} */ ({
  V0: [IdentityTopUpTransitionV0],
}))

/**
 * platform_serialize unversioned
 * platform_version_path_bounds "dpp.state_transition_serialization_versions.identity_update_state_transition"
 */
export const IdentityUpdateTransition = Enum("IdentityUpdateTransition", /** @type {const} */ ({
  V0: [IdentityUpdateTransitionV0],
}))

/** platform_serialize limit = 15000 , unversioned */
export const ResourceVote = Enum("ResourceVote", /** @type {const} */ ({
  V0: [ResourceVoteV0],
}))

/** platform_serialize limit = 15000 , unversioned */
export const Vote = Enum("Vote", /** @type {const} */ ({
  ResourceVote: [ResourceVote],
}))

/**
 * platform_serialize unversioned
 * platform_version_path_bounds "dpp.state_transition_serialization_versions.contract_create_state_transition"
 */
export const DataContractCreateTransition = Enum("DataContractCreateTransition", /** @type {const} */ ({
  V0: [DataContractCreateTransitionV0],
}))

export const DocumentTransition = Enum("DocumentTransition", /** @type {const} */ ({
  Create: [DocumentCreateTransition],
  Replace: [DocumentReplaceTransition],
  Delete: [DocumentDeleteTransition],
  Transfer: [DocumentTransferTransition],
  UpdatePrice: [DocumentUpdatePriceTransition],
  Purchase: [DocumentPurchaseTransition],
}))

export const DocumentsBatchTransitionV0 = Struct("DocumentsBatchTransitionV0", {
  owner_id: Identifier,
  transitions: Vec(DocumentTransition),
  user_fee_increase: UserFeeIncrease,
  signature_public_key_id: NotSignable(KeyID),
  signature: NotSignable(BinaryData),
});

/**
 * platform_serialize unversioned
 * platform_version_path_bounds "dpp.state_transition_serialization_versions.identity_create_state_transition"
 */
export const IdentityCreateTransition = Enum("IdentityCreateTransition", /** @type {const} */ ({
  V0: [IdentityCreateTransitionV0],
}))

/** platform_serialize unversioned */
export const MasternodeVoteTransitionV0 = Struct("MasternodeVoteTransitionV0", {
  pro_tx_hash: Identifier,
  voter_identity_id: Identifier,
  vote: Vote,
  nonce: IdentityNonce,
  signature_public_key_id: NotSignable(KeyID),
  signature: NotSignable(BinaryData),
});

/**
 * platform_serialize unversioned
 * platform_version_path_bounds "dpp.state_transition_serialization_versions.documents_batch_state_transition"
 */
export const DocumentsBatchTransition = Enum("DocumentsBatchTransition", /** @type {const} */ ({
  V0: [DocumentsBatchTransitionV0],
}))

/**
 * platform_serialize unversioned
 * platform_version_path_bounds "dpp.state_transition_serialization_versions.masternode_vote_state_transition"
 */
export const MasternodeVoteTransition = Enum("MasternodeVoteTransition", /** @type {const} */ ({
  V0: [MasternodeVoteTransitionV0],
}))

/**
 * platform_serialize unversioned
 * platform_serialize limit = 100000
 */
export const StateTransition = Enum("StateTransition", /** @type {const} */ ({
  DataContractCreate: [DataContractCreateTransition],
  DataContractUpdate: [DataContractUpdateTransition],
  DocumentsBatch: [DocumentsBatchTransition],
  IdentityCreate: [IdentityCreateTransition],
  IdentityTopUp: [IdentityTopUpTransition],
  IdentityCreditWithdrawal: [IdentityCreditWithdrawalTransition],
  IdentityUpdate: [IdentityUpdateTransition],
  IdentityCreditTransfer: [IdentityCreditTransferTransition],
  MasternodeVote: [MasternodeVoteTransition],
}))

// NOT NEEDED: AddOperation
// NOT NEEDED: AddrV2
// NOT NEEDED: AddrV2Message
// NOT NEEDED: DUPLICATE_Address
// NOT NEEDED: AddressEncoding
// NOT NEEDED: AddressInner
// NOT NEEDED: AddressType
// NOT NEEDED: All
// NOT NEEDED: Amount
// NOT NEEDED: Annex
// NOT NEEDED: ArrayDeserializer
// NOT NEEDED: ArrayItemType
// NOT NEEDED: AssetLockOutputNotFoundError
// NOT NEEDED: AssetLockProofType
// NOT NEEDED: AssetLockTransactionIsNotFoundError
// NOT NEEDED: AssetLockValue
// NOT NEEDED: AssetLockValueV0
// NOT NEEDED: AssetUnlockBasePayload
// NOT NEEDED: AssetUnlockBaseTransactionInfo
// NOT NEEDED: AssetUnlockPayload
// NOT NEEDED: AssetUnlockRequestInfo
// NOT NEEDED: BLSPublicKey
// NOT NEEDED: BLSSignature
// NOT NEEDED: BalanceChange
// NOT NEEDED: BalanceChangeForIdentity
// NOT NEEDED: BalanceIsNotEnoughError
// NOT NEEDED: BasicBLSError
// NOT NEEDED: BasicECDSAError
// NOT NEEDED: BasicError
// NOT NEEDED: BinVisitor
// NOT NEEDED: BinWriter
// NOT NEEDED: Bip34Error
// NOT NEEDED: BitStreamReader
// NOT NEEDED: BitStreamWriter
// NOT NEEDED: Block
// NOT NEEDED: BlockFilter
// NOT NEEDED: BlockFilterReader
// NOT NEEDED: BlockFilterWriter
// NOT NEEDED: DUPLICATE_BlockHash
// NOT NEEDED: BlockHeight
// NOT NEEDED: BlockInfo
// NOT NEEDED: BlockTransactions
// NOT NEEDED: BlockTransactionsRequest
// NOT NEEDED: BlockTxn
// NOT NEEDED: BloomFlags
// NOT NEEDED: BorrowedPair
// NOT NEEDED: Builder
// NOT NEEDED: ByteArrayKeyword
// NOT NEEDED: ByteArrayPropertySizes
// NOT NEEDED: Bytes
// NOT NEEDED: Bytes20
// NOT NEEDED: Bytes32
// NOT NEEDED: Bytes36
// NOT NEEDED: BytesPerEpoch
// NOT NEEDED: BytesPerEpochByIdentifier
// NOT NEEDED: CFCheckpt
// NOT NEEDED: CFHeaders
// NOT NEEDED: CFilter
// NOT NEEDED: CachedEpochIndexFeeVersions
// NOT NEEDED: CachedEpochIndexFeeVersionsFieldsBeforeVersion4
// NOT NEEDED: CborCanonicalMap
// NOT NEEDED: ChainCode
// NOT NEEDED: ChainHash
// NOT NEEDED: ChainLock
// NOT NEEDED: CheckedData
// NOT NEEDED: ChildNumber
// NOT NEEDED: Class
// NOT NEEDED: ClassifyContext
// NOT NEEDED: ClientDataRetrievalError
// NOT NEEDED: CmpctBlock
// NOT NEEDED: CoinbasePayload
// NOT NEEDED: CommandString
// NOT NEEDED: CommandStringError
// NOT NEEDED: CommonCache
// NOT NEEDED: CompactTarget
// NOT NEEDED: CompatibleProtocolVersionIsNotDefinedError
// NOT NEEDED: ConfirmedHash
// NOT NEEDED: ConfirmedHashHashedWithProRegTx
// NOT NEEDED: ConsensusError
// NOT NEEDED: ConsensusValidationResult
// NOT NEEDED: Contender
// NOT NEEDED: ContenderV0
// NOT NEEDED: ContenderWithSerializedDocument
// NOT NEEDED: ContenderWithSerializedDocumentV0
// NOT NEEDED: ContestedDocumentVotePollStatus
// NOT NEEDED: ContestedDocumentVotePollStoredInfo
// NOT NEEDED: ContestedDocumentVotePollStoredInfoV0
// NOT NEEDED: ContestedDocumentVotePollStoredInfoVoteEventV0
// NOT NEEDED: ContestedDocumentVotePollWinnerInfo
// NOT NEEDED: ContestedDocumentsTemporarilyNotAllowedError
// NOT NEEDED: ContestedIndexFieldMatch
// NOT NEEDED: ContestedIndexInformation
// NOT NEEDED: ContestedIndexResolution
// NOT NEEDED: ContestedUniqueIndexOnMutableDocumentTypeError
// NOT NEEDED: ContestedUniqueIndexWithUniqueIndexError
// NOT NEEDED: ContractBoundsType
// NOT NEEDED: ControlBlock
// NOT NEEDED: ConversionError
// NOT NEEDED: CopyOperation
// NOT NEEDED: DUPLICATE_CoreBlockHeight
// NOT NEEDED: CreatedDataContract
// NOT NEEDED: CreatedDataContractInSerializationFormat
// NOT NEEDED: CreatedDataContractInSerializationFormatV0
// NOT NEEDED: CreatedDataContractV0
// NOT NEEDED: CreationRestrictionMode
// NOT NEEDED: CreditsPerEpoch
// NOT NEEDED: CreditsPerEpochByIdentifier
// NOT NEEDED: CycleHash
// NOT NEEDED: DKGParams
// NOT NEEDED: DPPError
// NOT NEEDED: DUPLICATE_DashPlatformProtocol
// NOT NEEDED: DashPlatformProtocolInitError
// NOT NEEDED: DataBuilder
// NOT NEEDED: DataContract
// NOT NEEDED: DataContractAlreadyPresentError
// NOT NEEDED: DataContractBoundsNotPresentError
// NOT NEEDED: DataContractConfigUpdateError
// NOT NEEDED: DataContractCreateTransitionLatest
// NOT NEEDED: DataContractError
// NOT NEEDED: DataContractFacade
// NOT NEEDED: DataContractFactory
// NOT NEEDED: DataContractFactoryV0
// NOT NEEDED: DataContractHaveNewUniqueIndexError
// NOT NEEDED: DataContractImmutablePropertiesUpdateError
// NOT NEEDED: DataContractInvalidIndexDefinitionUpdateError
// NOT NEEDED: DataContractIsReadonlyError
// NOT NEEDED: DataContractMaxDepthExceedError
// NOT NEEDED: DUPLICATE_DataContractNotPresentError
// NOT NEEDED: DataContractUniqueIndicesChangedError
// NOT NEEDED: DataContractUpdatePermissionError
// NOT NEEDED: DataContractUpdateTransitionLatest
// NOT NEEDED: DataContractV0
// NOT NEEDED: DataTriggerConditionError
// NOT NEEDED: DataTriggerError
// NOT NEEDED: DataTriggerExecutionError
// NOT NEEDED: DataTriggerInvalidResultError
// NOT NEEDED: DUPLICATE_DecodeError
// NOT NEEDED: DecodeInitError
// NOT NEEDED: DecodeProtocolIdentity
// NOT NEEDED: Decoder
// NOT NEEDED: DecodingError
// NOT NEEDED: DefaultEntropyGenerator
// NOT NEEDED: DeletedQuorum
// NOT NEEDED: Denomination
// NOT NEEDED: DerivationPath
// NOT NEEDED: DerivationPathIterator
// NOT NEEDED: DerivationPathReference
// NOT NEEDED: Deserializer
// NOT NEEDED: DisablingKeyIdAlsoBeingAddedInSameTransitionError
// NOT NEEDED: Display
// NOT NEEDED: DisplayExpected
// NOT NEEDED: DisplayStyle
// NOT NEEDED: DisplayUnchecked
// NOT NEEDED: DisplayWrapper
// NOT NEEDED: DistributionAmount
// NOT NEEDED: DistributionLeftovers
// NOT NEEDED: Document
// NOT NEEDED: DocumentAlreadyPresentError
// NOT NEEDED: DocumentContestCurrentlyLockedError
// NOT NEEDED: DocumentContestDocumentWithSameIdAlreadyPresentError
// NOT NEEDED: DocumentContestIdentityAlreadyContestantError
// NOT NEEDED: DocumentContestNotJoinableError
// NOT NEEDED: DocumentContestNotPaidForError
// NOT NEEDED: DocumentCreationNotAllowedError
// NOT NEEDED: DocumentError
// NOT NEEDED: DocumentFacade
// NOT NEEDED: DocumentFactory
// NOT NEEDED: DocumentFactoryV0
// NOT NEEDED: DocumentFieldFillSize
// NOT NEEDED: DocumentFieldFillType
// NOT NEEDED: DocumentFieldMaxSizeExceededError
// NOT NEEDED: DocumentForCbor
// NOT NEEDED: DocumentIncorrectPurchasePriceError
// NOT NEEDED: DocumentNotForSaleError
// NOT NEEDED: DocumentNotFoundError
// NOT NEEDED: DocumentOwnerIdMismatchError
// NOT NEEDED: DocumentPatch
// NOT NEEDED: DocumentProperty
// NOT NEEDED: DocumentPropertyType
// NOT NEEDED: DocumentTimestampWindowViolationError
// NOT NEEDED: DocumentTimestampsAreEqualError
// NOT NEEDED: DocumentTimestampsMismatchError
// NOT NEEDED: DocumentTransitionActionType
// NOT NEEDED: DocumentTransitionsAreAbsentError
// NOT NEEDED: DocumentType
// NOT NEEDED: DocumentTypeMutRef
// NOT NEEDED: DocumentTypeRef
// NOT NEEDED: DocumentTypeUpdateError
// NOT NEEDED: DocumentTypeV0
// NOT NEEDED: DocumentTypesAreMissingError
// NOT NEEDED: DocumentV0
// NOT NEEDED: Duffs
// NOT NEEDED: DuplicateDocumentTransitionsWithIdsError
// NOT NEEDED: DuplicateDocumentTransitionsWithIndicesError
// NOT NEEDED: DuplicateIndexError
// NOT NEEDED: DuplicateIndexNameError
// NOT NEEDED: DuplicateUniqueIndexError
// NOT NEEDED: DuplicatedIdentityPublicKeyBasicError
// NOT NEEDED: DuplicatedIdentityPublicKeyIdBasicError
// NOT NEEDED: DuplicatedIdentityPublicKeyIdStateError
// NOT NEEDED: DuplicatedIdentityPublicKeyStateError
// NOT NEEDED: DUPLICATE_EcdsaSighashType
// NOT NEEDED: EmptyWrite
// NOT NEEDED: EncodeSigningDataResult
// NOT NEEDED: Encoder
// NOT NEEDED: Encoding
// NOT NEEDED: EntryMasternodeType
// NOT NEEDED: Epoch
// NOT NEEDED: EpochIndex
// NOT NEEDED: EpochIndexFeeVersionsForStorage
// NOT NEEDED: DUPLICATE_Error
// NOT NEEDED: ErrorTrackingWriter
// NOT NEEDED: ExpectedDocumentsData
// NOT NEEDED: ExtendedBlockInfo
// NOT NEEDED: ExtendedBlockInfoV0
// NOT NEEDED: ExtendedDocument
// NOT NEEDED: ExtendedDocumentV0
// NOT NEEDED: ExtendedDocumentVisitor
// NOT NEEDED: ExtendedEpochInfo
// NOT NEEDED: ExtendedEpochInfoV0
// NOT NEEDED: ExtendedPrivKey
// NOT NEEDED: ExtendedPubKey
// NOT NEEDED: FeeError
// NOT NEEDED: FeeRate
// NOT NEEDED: FeeRefunds
// NOT NEEDED: FeeResult
// NOT NEEDED: FetchAndValidateDataContract
// NOT NEEDED: FieldMinMaxBounds
// NOT NEEDED: FieldType
// NOT NEEDED: FieldTypeWeights
// NOT NEEDED: FilterAdd
// NOT NEEDED: FilterHash
// NOT NEEDED: FilterHeader
// NOT NEEDED: FilterLoad
// NOT NEEDED: FinalizedContender
// NOT NEEDED: FinalizedContenderWithSerializedDocument
// NOT NEEDED: FinalizedResourceVoteChoicesWithVoterInfo
// NOT NEEDED: Fingerprint
// NOT NEEDED: FormatOptions
// NOT NEEDED: FromHexError
// NOT NEEDED: FutureLeafVersion
// NOT NEEDED: GcsFilter
// NOT NEEDED: GcsFilterReader
// NOT NEEDED: GcsFilterWriter
// NOT NEEDED: GetBlockTxn
// NOT NEEDED: GetBlocksMessage
// NOT NEEDED: GetCFCheckpt
// NOT NEEDED: GetCFHeaders
// NOT NEEDED: GetCFilters
// NOT NEEDED: GetDataContractSecurityLevelRequirementFn
// NOT NEEDED: GetHeadersMessage
// NOT NEEDED: GetKeyError
// NOT NEEDED: GetMnListDiff
// NOT NEEDED: GetQRInfo
// NOT NEEDED: HRVisitor
// NOT NEEDED: Header
// NOT NEEDED: HeaderAndShortIds
// NOT NEEDED: HeaderDeserializationWrapper
// NOT NEEDED: HeaderSerializationWrapper
// NOT NEEDED: DUPLICATE_Height
// NOT NEEDED: Hex
// NOT NEEDED: HiddenNodes
// NOT NEEDED: IHeader
// NOT NEEDED: IdentitiesContractKeys
// NOT NEEDED: Identity
// NOT NEEDED: IdentityAlreadyExistsError
// NOT NEEDED: IdentityAssetLockProofLockedTransactionMismatchError
// NOT NEEDED: IdentityAssetLockStateTransitionReplayError
// NOT NEEDED: IdentityAssetLockTransactionIsNotFoundError
// NOT NEEDED: IdentityAssetLockTransactionOutPointAlreadyConsumedError
// NOT NEEDED: IdentityAssetLockTransactionOutPointNotEnoughBalanceError
// NOT NEEDED: IdentityAssetLockTransactionOutputNotFoundError
// NOT NEEDED: IdentityCreateTransitionLatest
// NOT NEEDED: IdentityCreateTransitionV0Inner
// NOT NEEDED: IdentityCreditTransferToSelfError
// NOT NEEDED: IdentityCreditTransferTransitionLatest
// NOT NEEDED: IdentityCreditWithdrawalTransitionLatest
// NOT NEEDED: IdentityCreditWithdrawalTransitionV01
// NOT NEEDED: IdentityCreditWithdrawalTransitionV010
// NOT NEEDED: IdentityCreditWithdrawalTransitionV02
// NOT NEEDED: IdentityCreditWithdrawalTransitionV03
// NOT NEEDED: IdentityCreditWithdrawalTransitionV04
// NOT NEEDED: IdentityCreditWithdrawalTransitionV05
// NOT NEEDED: IdentityCreditWithdrawalTransitionV06
// NOT NEEDED: IdentityCreditWithdrawalTransitionV07
// NOT NEEDED: IdentityCreditWithdrawalTransitionV08
// NOT NEEDED: IdentityCreditWithdrawalTransitionV09
// NOT NEEDED: IdentityFacade
// NOT NEEDED: IdentityFactory
// NOT NEEDED: IdentityInsufficientBalanceError
// NOT NEEDED: IdentityNotFoundError
// NOT NEEDED: IdentityNotPresentError
// NOT NEEDED: IdentityPublicKeyAlreadyExistsForUniqueContractBoundsError
// NOT NEEDED: IdentityPublicKeyIsDisabledError
// NOT NEEDED: IdentityPublicKeyIsReadOnlyError
// NOT NEEDED: IdentityV0
// NOT NEEDED: IncompatibleDataContractSchemaError
// NOT NEEDED: IncompatibleDocumentTypeSchemaError
// NOT NEEDED: IncompatibleJsonSchemaOperation
// NOT NEEDED: IncompatibleProtocolVersionError
// NOT NEEDED: IncompatibleRe2PatternError
// NOT NEEDED: IncompleteBuilder
// NOT NEEDED: InconsistentCompoundIndexDataError
// NOT NEEDED: Index
// NOT NEEDED: IndexConstPath
// NOT NEEDED: IndexLevel
// NOT NEEDED: IndexLevelTypeInfo
// NOT NEEDED: IndexName
// NOT NEEDED: IndexOrderDirection
// NOT NEEDED: IndexProperties
// NOT NEEDED: IndexProperty
// NOT NEEDED: IndexPropertyName
// NOT NEEDED: IndexType
// NOT NEEDED: Input
// NOT NEEDED: InputWeightPrediction
// NOT NEEDED: InputsHash
// NOT NEEDED: DUPLICATE_InstantLock
// NOT NEEDED: Instruction
// NOT NEEDED: InstructionIndices
// NOT NEEDED: Instructions
// NOT NEEDED: IntegerReplacementType
// NOT NEEDED: InvalidAssetLockProofCoreChainHeightError
// NOT NEEDED: InvalidAssetLockProofTransactionHeightError
// NOT NEEDED: InvalidAssetLockTransactionOutputReturnSizeError
// NOT NEEDED: InvalidCompoundIndexError
// NOT NEEDED: InvalidDataContractIdError
// NOT NEEDED: InvalidDataContractVersionError
// NOT NEEDED: InvalidDocumentRevisionError
// NOT NEEDED: InvalidDocumentTransitionActionError
// NOT NEEDED: InvalidDocumentTransitionIdError
// NOT NEEDED: DUPLICATE_InvalidDocumentTypeError
// NOT NEEDED: InvalidDocumentTypeNameError
// NOT NEEDED: InvalidDocumentTypeRequiredSecurityLevelError
// NOT NEEDED: InvalidIdentifierError
// NOT NEEDED: InvalidIdentityAssetLockProofChainLockValidationError
// NOT NEEDED: InvalidIdentityAssetLockTransactionError
// NOT NEEDED: InvalidIdentityAssetLockTransactionOutputError
// NOT NEEDED: InvalidIdentityCreditTransferAmountError
// NOT NEEDED: InvalidIdentityCreditWithdrawalTransitionAmountError
// NOT NEEDED: InvalidIdentityCreditWithdrawalTransitionCoreFeeError
// NOT NEEDED: InvalidIdentityCreditWithdrawalTransitionOutputScriptError
// NOT NEEDED: InvalidIdentityKeySignatureError
// NOT NEEDED: InvalidIdentityNonceError
// NOT NEEDED: InvalidIdentityPublicKeyDataError
// NOT NEEDED: InvalidIdentityPublicKeyIdError
// NOT NEEDED: InvalidIdentityPublicKeySecurityLevelError
// NOT NEEDED: DUPLICATE_InvalidIdentityPublicKeyTypeError
// NOT NEEDED: InvalidIdentityRevisionError
// NOT NEEDED: InvalidIdentityUpdateTransitionDisableKeysError
// NOT NEEDED: InvalidIdentityUpdateTransitionEmptyError
// NOT NEEDED: InvalidIndexPropertyTypeError
// NOT NEEDED: InvalidIndexedPropertyConstraintError
// NOT NEEDED: InvalidInstantAssetLockProofError
// NOT NEEDED: InvalidInstantAssetLockProofSignatureError
// NOT NEEDED: InvalidJsonSchemaRefError
// NOT NEEDED: InvalidSignaturePublicKeyError
// NOT NEEDED: InvalidSignaturePublicKeyPurposeError
// NOT NEEDED: InvalidSignaturePublicKeySecurityLevelError
// NOT NEEDED: InvalidStateTransitionSignatureError
// NOT NEEDED: InvalidStateTransitionTypeError
// NOT NEEDED: InvalidVectorSizeError
// NOT NEEDED: Inventory
// NOT NEEDED: IoWrapper
// NOT NEEDED: IsIndexUnique
// NOT NEEDED: Iter
// NOT NEEDED: IterReader
// NOT NEEDED: JsonPath
// NOT NEEDED: JsonPathLiteral
// NOT NEEDED: JsonPathStep
// NOT NEEDED: JsonSchema
// NOT NEEDED: JsonSchemaCompilationError
// NOT NEEDED: DUPLICATE_JsonSchemaError
// NOT NEEDED: JsonSchemaErrorData
// NOT NEEDED: DUPLICATE_JsonSchemaValidator
// NOT NEEDED: JsonStateTransitionSerializationOptions
// NOT NEEDED: Key
// NOT NEEDED: KeyCount
// NOT NEEDED: KeyDerivationType
// NOT NEEDED: KeyRequest
// NOT NEEDED: KeySource
// NOT NEEDED: Keys
// NOT NEEDED: KnownCostItem
// NOT NEEDED: LLMQEntryVerificationSkipStatus
// NOT NEEDED: LLMQEntryVerificationStatus
// NOT NEEDED: LLMQModifierType
// NOT NEEDED: LLMQParams
// NOT NEEDED: LLMQQuarterReconstructionType
// NOT NEEDED: LLMQQuarterType
// NOT NEEDED: LLMQQuarterUsageType
// NOT NEEDED: LLMQType
// NOT NEEDED: LeafNode
// NOT NEEDED: LeafNodes
// NOT NEEDED: LeafVersion
// NOT NEEDED: LegacySighash
// NOT NEEDED: DUPLICATE_LockTime
// NOT NEEDED: LockTimeUnit
// NOT NEEDED: LockedVotePollCounter
// NOT NEEDED: Lower
// NOT NEEDED: MNSkipListMode
// NOT NEEDED: MapKeySerializer
// NOT NEEDED: MasterPublicKeyUpdateError
// NOT NEEDED: MasternodeIncorrectVoterIdentityIdError
// NOT NEEDED: MasternodeIncorrectVotingAddressError
// NOT NEEDED: MasternodeList
// NOT NEEDED: MasternodeListBuilder
// NOT NEEDED: MasternodeListEngine
// NOT NEEDED: MasternodeListEntry
// NOT NEEDED: MasternodeNotFoundError
// NOT NEEDED: MasternodeVoteAlreadyPresentError
// NOT NEEDED: MasternodeVoteTransitionLatest
// NOT NEEDED: MasternodeVotedTooManyTimesError
// NOT NEEDED: MaxDepthValidationResult
// NOT NEEDED: MaxDocumentsTransitionsExceededError
// NOT NEEDED: MaxIdentityPublicKeyLimitReachedError
// NOT NEEDED: MergeIdentityNonceResult
// NOT NEEDED: MerkleBlock
// NOT NEEDED: MerkleBlockError
// NOT NEEDED: MerkleRootMasternodeList
// NOT NEEDED: MerkleRootQuorums
// NOT NEEDED: MessageSignature
// NOT NEEDED: MessageSignatureError
// NOT NEEDED: MessageVerificationError
// NOT NEEDED: Metadata
// NOT NEEDED: MissingDataContractIdBasicError
// NOT NEEDED: MissingDocumentTransitionActionError
// NOT NEEDED: MissingDocumentTransitionTypeError
// NOT NEEDED: MissingDocumentTypeError
// NOT NEEDED: MissingIdentityPublicKeyIdsError
// NOT NEEDED: MissingMasterPublicKeyError
// NOT NEEDED: MissingPositionsInDocumentTypePropertiesError
// NOT NEEDED: MissingPublicKeyError
// NOT NEEDED: MissingStateTransitionTypeError
// NOT NEEDED: MissingTransferKeyError
// NOT NEEDED: MnListDiff
// NOT NEEDED: MoveOperation
// NOT NEEDED: NativeBlsModule
// NOT NEEDED: Network
// NOT NEEDED: NetworkChecked
// NOT NEEDED: NetworkMessage
// NOT NEEDED: NetworkUnchecked
// NOT NEEDED: NoTransferKeyForCoreWithdrawalAvailableError
// NOT NEEDED: NodeInfo
// NOT NEEDED: NonConsensusError
// NOT NEEDED: DUPLICATE_NonStandardSighashType
// NOT NEEDED: NonceOutOfBoundsError
// NOT NEEDED: NotImplementedIdentityCreditWithdrawalTransitionPoolingError
// NOT NEEDED: OperationError
// NOT NEEDED: OperatorPublicKey
// NOT NEEDED: OrderBy
// NOT NEEDED: Output
// NOT NEEDED: OutputType
// NOT NEEDED: OverflowError
// NOT NEEDED: OwnedPair
// NOT NEEDED: Pair
// NOT NEEDED: Params
// NOT NEEDED: ParentDocumentOptions
// NOT NEEDED: ParseAmountError
// NOT NEEDED: ParseIntError
// NOT NEEDED: ParseNetworkError
// NOT NEEDED: ParseOutPointError
// NOT NEEDED: PartialIdentity
// NOT NEEDED: PartialMerkleTree
// NOT NEEDED: PartiallySignedTransaction
// NOT NEEDED: PastAssetLockStateTransitionHashes
// NOT NEEDED: Patch
// NOT NEEDED: PatchDiffer
// NOT NEEDED: PatchError
// NOT NEEDED: PatchErrorKind
// NOT NEEDED: PatchOperation
// NOT NEEDED: Payload
// NOT NEEDED: PlatformItemKey
// NOT NEEDED: PreferredKeyPurposeForSigningWithdrawal
// NOT NEEDED: PrefilledTransaction
// NOT NEEDED: PrefundedSpecializedBalanceIdentifier
// NOT NEEDED: PrefundedSpecializedBalanceInsufficientError
// NOT NEEDED: PrefundedSpecializedBalanceNotFoundError
// NOT NEEDED: Prevouts
// NOT NEEDED: PrivateKey
// NOT NEEDED: ProTxHash
// NOT NEEDED: PropertyPath
// NOT NEEDED: ProprietaryKey
// NOT NEEDED: ProprietaryType
// NOT NEEDED: ProtocolError
// NOT NEEDED: ProtocolValidationOperation
// NOT NEEDED: ProtocolVersion
// NOT NEEDED: ProtocolVersionParsingError
// NOT NEEDED: ProtocolVersionVoteCount
// NOT NEEDED: ProviderMasternodeType
// NOT NEEDED: ProviderRegistrationPayload
// NOT NEEDED: ProviderUpdateRegistrarPayload
// NOT NEEDED: ProviderUpdateRevocationPayload
// NOT NEEDED: ProviderUpdateServicePayload
// NOT NEEDED: Psbt
// NOT NEEDED: PsbtHash
// NOT NEEDED: PsbtParseError
// NOT NEEDED: PsbtSighashType
// NOT NEEDED: PubkeyHash
// NOT NEEDED: PublicKey
// NOT NEEDED: PublicKeyIsDisabledError
// NOT NEEDED: PublicKeyMismatchError
// NOT NEEDED: DUPLICATE_PublicKeySecurityLevelNotMetError
// NOT NEEDED: PublicKeyValidationError
// NOT NEEDED: PushBytes
// NOT NEEDED: PushBytesBuf
// NOT NEEDED: DUPLICATE_PushBytesError
// NOT NEEDED: PushDataLenLen
// NOT NEEDED: QRInfo
// NOT NEEDED: QualifiedMasternodeListEntry
// NOT NEEDED: QualifiedQuorumEntry
// NOT NEEDED: QuorumCLSigObject
// NOT NEEDED: QuorumCommitmentHash
// NOT NEEDED: QuorumCommitmentPayload
// NOT NEEDED: QuorumEntry
// NOT NEEDED: QuorumEntryHash
// NOT NEEDED: QuorumHash
// NOT NEEDED: QuorumModifierHash
// NOT NEEDED: QuorumOrderingHash
// NOT NEEDED: QuorumSigningRequestId
// NOT NEEDED: QuorumSigningSignId
// NOT NEEDED: QuorumSnapshot
// NOT NEEDED: QuorumVVecHash
// NOT NEEDED: QuorumValidationError
// NOT NEEDED: RandomDocumentTypeParameters
// NOT NEEDED: RawAssetLockProof
// NOT NEEDED: RawNetworkMessage
// NOT NEEDED: ReadBytesFromFiniteReaderOpts
// NOT NEEDED: Reject
// NOT NEEDED: RejectReason
// NOT NEEDED: RemoveOperation
// NOT NEEDED: ReplaceOperation
// NOT NEEDED: ReplacementType
// NOT NEEDED: SMLEntry
// NOT NEEDED: SMLStore
// NOT NEEDED: Script
// NOT NEEDED: ScriptHash
// NOT NEEDED: ScriptLeaf
// NOT NEEDED: ScriptLeaves
// NOT NEEDED: ScriptMerkleProofMap
// NOT NEEDED: ScriptPath
// NOT NEEDED: SegwitCache
// NOT NEEDED: SegwitV0Sighash
// NOT NEEDED: SendCmpct
// NOT NEEDED: SeqIterator
// NOT NEEDED: SerdeParsingError
// NOT NEEDED: SerializeBytesAsHex
// NOT NEEDED: SerializeMap
// NOT NEEDED: SerializeStructVariant
// NOT NEEDED: SerializeTupleVariant
// NOT NEEDED: SerializeVec
// NOT NEEDED: SerializedObjectParsingError
// NOT NEEDED: SerializedSignature
// NOT NEEDED: Serializer
// NOT NEEDED: ServiceFlags
// NOT NEEDED: Sha256dHash
// NOT NEEDED: ShortId
// NOT NEEDED: ShouldInsertWithAllNull
// NOT NEEDED: SigHashCache
// NOT NEEDED: SigHashType
// NOT NEEDED: SighashCache
// NOT NEEDED: SighashComponents
// NOT NEEDED: DUPLICATE_SighashTypeParseError
// NOT NEEDED: SignError
// NOT NEEDED: SignableBytesHasher
// NOT NEEDED: DUPLICATE_Signature
// NOT NEEDED: SignatureError
// NOT NEEDED: SignatureShouldNotBePresentError
// NOT NEEDED: SignedAmount
// NOT NEEDED: SignedCredits
// NOT NEEDED: SignedCreditsPerEpoch
// NOT NEEDED: SigningAlgorithm
// NOT NEEDED: SigningErrors
// NOT NEEDED: SigningKeys
// NOT NEEDED: SimpleConsensusValidationResult
// NOT NEEDED: SimpleValidationResult
// NOT NEEDED: SimplifiedMNList
// NOT NEEDED: Sink
// NOT NEEDED: SmallVec
// NOT NEEDED: SmlError
// NOT NEEDED: SortKey
// NOT NEEDED: SpecialTransactionPayloadHash
// NOT NEEDED: SpecializedDocumentFactory
// NOT NEEDED: SpecializedDocumentFactoryV0
// NOT NEEDED: SplitFeatureVersionOutcome
// NOT NEEDED: StateError
// NOT NEEDED: StateTransitionError
// NOT NEEDED: StateTransitionFactory
// NOT NEEDED: StateTransitionIsNotSignedError
// NOT NEEDED: StateTransitionMaxSizeExceededError
// NOT NEEDED: StateTransitionProofResult
// NOT NEEDED: StateTransitionType
// NOT NEEDED: StatelessJsonSchemaLazyValidator
// NOT NEEDED: StoredAssetLockInfo
// NOT NEEDED: StringPropertySizes
// NOT NEEDED: SubValidator
// NOT NEEDED: SystemPropertyIndexAlreadyPresentError
// NOT NEEDED: TapLeaf
// NOT NEEDED: TapSighashType
// NOT NEEDED: TapTree
// NOT NEEDED: TaprootBuilder
// NOT NEEDED: TaprootBuilderError
// NOT NEEDED: TaprootCache
// NOT NEEDED: TaprootError
// NOT NEEDED: TaprootMerkleBranch
// NOT NEEDED: TaprootSpendInfo
// NOT NEEDED: Target
// NOT NEEDED: TestConsensusError
// NOT NEEDED: DUPLICATE_TestData
// NOT NEEDED: TestOperation
// NOT NEEDED: DUPLICATE_Time
// NOT NEEDED: TimestampIncluded
// NOT NEEDED: TooManyMasterPublicKeyError
// NOT NEEDED: TotalCreditsBalance
// NOT NEEDED: TradeMode
// NOT NEEDED: TransactionPayload
// NOT NEEDED: TransactionType
// NOT NEEDED: Transferable
// NOT NEEDED: TransitionFingerprint
// NOT NEEDED: TryFromError
// NOT NEEDED: TweakedKeyPair
// NOT NEEDED: TweakedPublicKey
// NOT NEEDED: TxIn
// NOT NEEDED: TxIndexOutOfRangeError
// NOT NEEDED: TxMerkleNode
// NOT NEEDED: Type
// NOT NEEDED: U256
// NOT NEEDED: UintError
// NOT NEEDED: UndefinedIndexPropertyError
// NOT NEEDED: UniqueIndicesLimitReachedError
// NOT NEEDED: UnknownAssetLockProofTypeError
// NOT NEEDED: UnknownChainHash
// NOT NEEDED: UnknownDocumentCreationRestrictionModeError
// NOT NEEDED: UnknownSecurityLevelError
// NOT NEEDED: UnknownStorageKeyRequirementsError
// NOT NEEDED: UnknownTradeModeError
// NOT NEEDED: UnknownTransferableTypeError
// NOT NEEDED: UnsupportedFeatureError
// NOT NEEDED: UnsupportedProtocolVersionError
// NOT NEEDED: UnsupportedVersionError
// NOT NEEDED: UntweakedKeyPair
// NOT NEEDED: UntweakedPublicKey
// NOT NEEDED: Upper
// NOT NEEDED: UpperWriter
// NOT NEEDED: DUPLICATE_UsedKeyMatrix
// NOT NEEDED: ValidationResult
// NOT NEEDED: Validator
// NOT NEEDED: ValidatorSet
// NOT NEEDED: ValidatorSetV0
// NOT NEEDED: ValidatorV0
// NOT NEEDED: ValueError
// NOT NEEDED: ValueMapDeserializer
// NOT NEEDED: VarInt
// NOT NEEDED: Version
// NOT NEEDED: VersionError
// NOT NEEDED: VersionMessage
// NOT NEEDED: Visitor
// NOT NEEDED: VotePollNotAvailableForVotingError
// NOT NEEDED: VotePollNotFoundError
// NOT NEEDED: WPubkeyHash
// NOT NEEDED: WScriptHash
// NOT NEEDED: Weight
// NOT NEEDED: With
// NOT NEEDED: WithdrawalOutputScriptNotAllowedWhenSigningWithOwnerKeyError
// NOT NEEDED: WithdrawalTransactionIndex
// NOT NEEDED: WithdrawalTransactionIndexAndBytes
// NOT NEEDED: Witness
// NOT NEEDED: WitnessCommitment
// NOT NEEDED: WitnessMerkleNode
// NOT NEEDED: WitnessProgram
// NOT NEEDED: WitnessVersion
// NOT NEEDED: Work
// NOT NEEDED: DUPLICATE_WrongPublicKeyPurposeError
// NOT NEEDED: Wtxid
// NOT NEEDED: XpubIdentifier
// NOT NEEDED: YesNoAbstainVoteChoice
