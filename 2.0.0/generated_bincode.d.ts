import { BinCode, BinCodeable } from "./bincode.ts";
import { Option, FixedBytes, Hash, SocketAddr, Transaction } from "./bincode_types.ts";
declare module "./generated_bincode.js" {

/**
 * An Asset Lock payload. This is contained as the payload of an asset lock special transaction.
 *  The Asset Lock Special transaction and this payload is described in the Asset Lock DIP2X
 *  (todo:update this).
 *  An Asset Lock can fund multiple Identity registrations or top ups.
 *  The Asset Lock payload credit outputs field contains a vector of TxOuts.
 *  Each TxOut refers to a funding of an Identity.
 */
interface AssetLockPayload {
  version: number;
  credit_outputs: TxOut[];
}
/** @ignore */
const AssetLockPayload : BinCodeable<AssetLockPayload> & ((data: {
  version: number,
  credit_outputs: TxOut[],
}) => AssetLockPayload);

/** @ignore */
export abstract class AssetLockProof {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: AssetLockProof): void;
  /** @ignore */
  static decode(bc: BinCode): AssetLockProof;
}
namespace AssetLockProof {
  /** @function */
  interface Instant extends AssetLockProof {
    [0]: InstantAssetLockProof;
  }
  /** @ignore */
  const Instant: (f0: InstantAssetLockProof) => AssetLockProof.Instant;
  /** @function */
  interface Chain extends AssetLockProof {
    [0]: ChainAssetLockProof;
  }
  /** @ignore */
  const Chain: (f0: ChainAssetLockProof) => AssetLockProof.Chain;
}

/** @ignore */
export abstract class AuthorizedActionTakers {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: AuthorizedActionTakers): void;
  /** @ignore */
  static decode(bc: BinCode): AuthorizedActionTakers;
}
namespace AuthorizedActionTakers {
  /** default */
  const NoOne: () => AuthorizedActionTakers;
  const ContractOwner: () => AuthorizedActionTakers;
  /** @function */
  interface Identity extends AuthorizedActionTakers {
    [0]: Identifier;
  }
  /** @ignore */
  const Identity: (f0: Identifier) => AuthorizedActionTakers.Identity;
  const MainGroup: () => AuthorizedActionTakers;
  /** @function */
  interface Group extends AuthorizedActionTakers {
    [0]: GroupContractPosition;
  }
  /** @ignore */
  const Group: (f0: GroupContractPosition) => AuthorizedActionTakers.Group;
}

/** platform_version_path_bounds "dpp.state_transition_serialization_versions.batch_state_transition" */
/** @ignore */
export abstract class BatchTransition {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: BatchTransition): void;
  /** @ignore */
  static decode(bc: BinCode): BatchTransition;
}
namespace BatchTransition {
  /** @function */
  interface V0 extends BatchTransition {
    [0]: BatchTransitionV0;
  }
  /** @ignore */
  const V0: (f0: BatchTransitionV0) => BatchTransition.V0;
  /** @function */
  interface V1 extends BatchTransition {
    [0]: BatchTransitionV1;
  }
  /** @ignore */
  const V1: (f0: BatchTransitionV1) => BatchTransition.V1;
}

interface BatchTransitionV0 {
  owner_id: Identifier;
  transitions: DocumentTransition[];
  user_fee_increase: UserFeeIncrease;
  /** platform_signable exclude_from_sig_hash */
  signature_public_key_id: KeyID;
  /** platform_signable exclude_from_sig_hash */
  signature: BinaryData;
}
/** @ignore */
const BatchTransitionV0 : BinCodeable<BatchTransitionV0> & ((data: {
  owner_id: Identifier,
  transitions: DocumentTransition[],
  user_fee_increase: UserFeeIncrease,
  /** platform_signable exclude_from_sig_hash */
  signature_public_key_id: KeyID,
  /** platform_signable exclude_from_sig_hash */
  signature: BinaryData,
}) => BatchTransitionV0);

interface BatchTransitionV1 {
  owner_id: Identifier;
  transitions: BatchedTransition[];
  user_fee_increase: UserFeeIncrease;
  /** platform_signable exclude_from_sig_hash */
  signature_public_key_id: KeyID;
  /** platform_signable exclude_from_sig_hash */
  signature: BinaryData;
}
/** @ignore */
const BatchTransitionV1 : BinCodeable<BatchTransitionV1> & ((data: {
  owner_id: Identifier,
  transitions: BatchedTransition[],
  user_fee_increase: UserFeeIncrease,
  /** platform_signable exclude_from_sig_hash */
  signature_public_key_id: KeyID,
  /** platform_signable exclude_from_sig_hash */
  signature: BinaryData,
}) => BatchTransitionV1);

/** @ignore */
export abstract class BatchedTransition {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: BatchedTransition): void;
  /** @ignore */
  static decode(bc: BinCode): BatchedTransition;
}
namespace BatchedTransition {
  /** @function */
  interface Document extends BatchedTransition {
    [0]: DocumentTransition;
  }
  /** @ignore */
  const Document: (f0: DocumentTransition) => BatchedTransition.Document;
  /** @function */
  interface Token extends BatchedTransition {
    [0]: TokenTransition;
  }
  /** @ignore */
  const Token: (f0: TokenTransition) => BatchedTransition.Token;
}

interface BinaryData {
  [0]: Uint8Array;
}
/** @ignore */
const BinaryData : BinCodeable<BinaryData> & ((
    f0: Uint8Array,
) => BinaryData);

export type BlockHeight = bigint;

export type BlockHeightInterval = bigint;

/**
 * Instant Asset Lock Proof is a part of Identity Create and Identity Topup
 *  transitions. It is a proof that specific output of dash is locked in credits
 *  pull and the transitions can mint credits and populate identity's balance.
 *  To prove that the output is locked, a height where transaction was chain locked is provided.
 */
interface ChainAssetLockProof {
  /** Core height on which the asset lock transaction was chain locked or higher */
  core_chain_locked_height: number;
  /** A reference to Asset Lock Special Transaction ID and output index in the payload */
  out_point: OutPoint;
}
/** @ignore */
const ChainAssetLockProof : BinCodeable<ChainAssetLockProof> & ((data: {
  /** Core height on which the asset lock transaction was chain locked or higher */
  core_chain_locked_height: number,
  /** A reference to Asset Lock Special Transaction ID and output index in the payload */
  out_point: OutPoint,
}) => ChainAssetLockProof);

/** @ignore */
export abstract class ChangeControlRules {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: ChangeControlRules): void;
  /** @ignore */
  static decode(bc: BinCode): ChangeControlRules;
}
namespace ChangeControlRules {
  /** @function */
  interface V0 extends ChangeControlRules {
    [0]: ChangeControlRulesV0;
  }
  /** @ignore */
  const V0: (f0: ChangeControlRulesV0) => ChangeControlRules.V0;
}

interface ChangeControlRulesV0 {
  /** This is who is authorized to make such a change */
  authorized_to_make_change: AuthorizedActionTakers;
  /** This is who is authorized to make such a change to the people authorized to make a change */
  admin_action_takers: AuthorizedActionTakers;
  /** Are we allowed to change to None in the future */
  changing_authorized_action_takers_to_no_one_allowed: boolean;
  /** Are we allowed to change the admin action takers to no one in the future */
  changing_admin_action_takers_to_no_one_allowed: boolean;
  /** Can the admin action takers change themselves */
  self_changing_admin_action_takers_allowed: boolean;
}
/** @ignore */
const ChangeControlRulesV0 : BinCodeable<ChangeControlRulesV0> & ((data: {
  /** This is who is authorized to make such a change */
  authorized_to_make_change: AuthorizedActionTakers,
  /** This is who is authorized to make such a change to the people authorized to make a change */
  admin_action_takers: AuthorizedActionTakers,
  /** Are we allowed to change to None in the future */
  changing_authorized_action_takers_to_no_one_allowed: boolean,
  /** Are we allowed to change the admin action takers to no one in the future */
  changing_admin_action_takers_to_no_one_allowed: boolean,
  /** Can the admin action takers change themselves */
  self_changing_admin_action_takers_allowed: boolean,
}) => ChangeControlRulesV0);

interface ContestedDocumentResourceVotePoll {
  contract_id: Identifier;
  document_type_name: string;
  index_name: string;
  index_values: Value[];
}
/** @ignore */
const ContestedDocumentResourceVotePoll : BinCodeable<ContestedDocumentResourceVotePoll> & ((data: {
  contract_id: Identifier,
  document_type_name: string,
  index_name: string,
  index_values: Value[],
}) => ContestedDocumentResourceVotePoll);

/**
 * A contract bounds is the bounds that the key has influence on.
 *  For authentication keys the bounds mean that the keys can only be used to sign
 *  within the specified contract.
 *  For encryption decryption this tells clients to only use these keys for specific
 *  contracts.
 * 
 * repr u8
 */
/** @ignore */
export abstract class ContractBounds {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: ContractBounds): void;
  /** @ignore */
  static decode(bc: BinCode): ContractBounds;
}
namespace ContractBounds {
  /**
   * this key can only be used within a specific contract
   * 
   * @function
   */
  interface SingleContract extends ContractBounds {
    id: Identifier;
  }
  const SingleContract: (data: {
    id: Identifier,
  }) => ContractBounds.SingleContract;
  /**
   * this key can only be used within a specific contract and for a specific document type
   * 
   * @function
   */
  interface SingleContractDocumentType extends ContractBounds {
    id: Identifier;
    document_type_name: string;
  }
  const SingleContractDocumentType: (data: {
    id: Identifier,
    document_type_name: string,
  }) => ContractBounds.SingleContractDocumentType;
}

interface CoreScript {
  [0]: DashcoreScript;
}
/** @ignore */
const CoreScript : BinCodeable<CoreScript> & ((
    f0: DashcoreScript,
) => CoreScript);

export type Credits = bigint;

export type DashcoreScript = ScriptBuf;

/** @ignore */
export abstract class DataContractConfig {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: DataContractConfig): void;
  /** @ignore */
  static decode(bc: BinCode): DataContractConfig;
}
namespace DataContractConfig {
  /** @function */
  interface V0 extends DataContractConfig {
    [0]: DataContractConfigV0;
  }
  /** @ignore */
  const V0: (f0: DataContractConfigV0) => DataContractConfig.V0;
  /** @function */
  interface V1 extends DataContractConfig {
    [0]: DataContractConfigV1;
  }
  /** @ignore */
  const V1: (f0: DataContractConfigV1) => DataContractConfig.V1;
}

interface DataContractConfigV0 {
  /**
   * Can the contract ever be deleted. If the contract is deleted, so should be all
   *  documents associated with it. TODO: There should also be a way to "stop" the contract -
   *  contract and documents are kept in the system, but no new documents can be added to it
   */
  can_be_deleted: boolean;
  /**
   * Is the contract mutable. Means that the document definitions can be changed or new
   *  document definitions can be added to the contract
   */
  readonly: boolean;
  /** Does the contract keep history when the contract itself changes */
  keeps_history: boolean;
  /**
   * Do documents in the contract keep history. This is a default for all documents in
   *  the contract, but can be overridden by the document itself
   */
  documents_keep_history_contract_default: boolean;
  /**
   * Are documents in the contract mutable? This specifies whether the documents can be
   *  changed. This is a default for all document types in the contract, but can be
   *  overridden by the document type config.
   */
  documents_mutable_contract_default: boolean;
  /**
   * Can documents in the contract be deleted? This specifies whether the documents can be
   *  deleted. This is a default for all document types in the contract, but can be
   *  overridden by the document types itself.
   */
  documents_can_be_deleted_contract_default: boolean;
  /** Encryption key storage requirements */
  requires_identity_encryption_bounded_key?: StorageKeyRequirements;
  /** Decryption key storage requirements */
  requires_identity_decryption_bounded_key?: StorageKeyRequirements;
}
/** @ignore */
const DataContractConfigV0 : BinCodeable<DataContractConfigV0> & ((data: {
  /**
   * Can the contract ever be deleted. If the contract is deleted, so should be all
   *  documents associated with it. TODO: There should also be a way to "stop" the contract -
   *  contract and documents are kept in the system, but no new documents can be added to it
   */
  can_be_deleted: boolean,
  /**
   * Is the contract mutable. Means that the document definitions can be changed or new
   *  document definitions can be added to the contract
   */
  readonly: boolean,
  /** Does the contract keep history when the contract itself changes */
  keeps_history: boolean,
  /**
   * Do documents in the contract keep history. This is a default for all documents in
   *  the contract, but can be overridden by the document itself
   */
  documents_keep_history_contract_default: boolean,
  /**
   * Are documents in the contract mutable? This specifies whether the documents can be
   *  changed. This is a default for all document types in the contract, but can be
   *  overridden by the document type config.
   */
  documents_mutable_contract_default: boolean,
  /**
   * Can documents in the contract be deleted? This specifies whether the documents can be
   *  deleted. This is a default for all document types in the contract, but can be
   *  overridden by the document types itself.
   */
  documents_can_be_deleted_contract_default: boolean,
  /** Encryption key storage requirements */
  requires_identity_encryption_bounded_key?: StorageKeyRequirements,
  /** Decryption key storage requirements */
  requires_identity_decryption_bounded_key?: StorageKeyRequirements,
}) => DataContractConfigV0);

interface DataContractConfigV1 {
  /**
   * Can the contract ever be deleted. If the contract is deleted, so should be all
   *  documents associated with it. TODO: There should also be a way to "stop" the contract -
   *  contract and documents are kept in the system, but no new documents can be added to it
   */
  can_be_deleted: boolean;
  /**
   * Is the contract mutable. Means that the document definitions can be changed or new
   *  document definitions can be added to the contract
   */
  readonly: boolean;
  /** Does the contract keep history when the contract itself changes */
  keeps_history: boolean;
  /**
   * Do documents in the contract keep history. This is a default for all documents in
   *  the contract, but can be overridden by the document itself
   */
  documents_keep_history_contract_default: boolean;
  /**
   * Are documents in the contract mutable? This specifies whether the documents can be
   *  changed. This is a default for all document types in the contract, but can be
   *  overridden by the document type config.
   */
  documents_mutable_contract_default: boolean;
  /**
   * Can documents in the contract be deleted? This specifies whether the documents can be
   *  deleted. This is a default for all document types in the contract, but can be
   *  overridden by the document types itself.
   */
  documents_can_be_deleted_contract_default: boolean;
  /** Encryption key storage requirements */
  requires_identity_encryption_bounded_key?: StorageKeyRequirements;
  /** Decryption key storage requirements */
  requires_identity_decryption_bounded_key?: StorageKeyRequirements;
  /** Use sized integer Rust types for `integer` property type based on validation rules */
  sized_integer_types: boolean;
}
/** @ignore */
const DataContractConfigV1 : BinCodeable<DataContractConfigV1> & ((data: {
  /**
   * Can the contract ever be deleted. If the contract is deleted, so should be all
   *  documents associated with it. TODO: There should also be a way to "stop" the contract -
   *  contract and documents are kept in the system, but no new documents can be added to it
   */
  can_be_deleted: boolean,
  /**
   * Is the contract mutable. Means that the document definitions can be changed or new
   *  document definitions can be added to the contract
   */
  readonly: boolean,
  /** Does the contract keep history when the contract itself changes */
  keeps_history: boolean,
  /**
   * Do documents in the contract keep history. This is a default for all documents in
   *  the contract, but can be overridden by the document itself
   */
  documents_keep_history_contract_default: boolean,
  /**
   * Are documents in the contract mutable? This specifies whether the documents can be
   *  changed. This is a default for all document types in the contract, but can be
   *  overridden by the document type config.
   */
  documents_mutable_contract_default: boolean,
  /**
   * Can documents in the contract be deleted? This specifies whether the documents can be
   *  deleted. This is a default for all document types in the contract, but can be
   *  overridden by the document types itself.
   */
  documents_can_be_deleted_contract_default: boolean,
  /** Encryption key storage requirements */
  requires_identity_encryption_bounded_key?: StorageKeyRequirements,
  /** Decryption key storage requirements */
  requires_identity_decryption_bounded_key?: StorageKeyRequirements,
  /** Use sized integer Rust types for `integer` property type based on validation rules */
  sized_integer_types: boolean,
}) => DataContractConfigV1);

/** platform_version_path_bounds "dpp.state_transition_serialization_versions.contract_create_state_transition" */
/** @ignore */
export abstract class DataContractCreateTransition {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: DataContractCreateTransition): void;
  /** @ignore */
  static decode(bc: BinCode): DataContractCreateTransition;
}
namespace DataContractCreateTransition {
  /** @function */
  interface V0 extends DataContractCreateTransition {
    [0]: DataContractCreateTransitionV0;
  }
  /** @ignore */
  const V0: (f0: DataContractCreateTransitionV0) => DataContractCreateTransition.V0;
}

/** DataContractCreateTransitionV0 has the same encoding structure */
interface DataContractCreateTransitionV0 {
  data_contract: DataContractInSerializationFormat;
  identity_nonce: IdentityNonce;
  user_fee_increase: UserFeeIncrease;
  /** platform_signable exclude_from_sig_hash */
  signature_public_key_id: KeyID;
  /** platform_signable exclude_from_sig_hash */
  signature: BinaryData;
}
/** @ignore */
const DataContractCreateTransitionV0 : BinCodeable<DataContractCreateTransitionV0> & ((data: {
  data_contract: DataContractInSerializationFormat,
  identity_nonce: IdentityNonce,
  user_fee_increase: UserFeeIncrease,
  /** platform_signable exclude_from_sig_hash */
  signature_public_key_id: KeyID,
  /** platform_signable exclude_from_sig_hash */
  signature: BinaryData,
}) => DataContractCreateTransitionV0);

/** @ignore */
export abstract class DataContractInSerializationFormat {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: DataContractInSerializationFormat): void;
  /** @ignore */
  static decode(bc: BinCode): DataContractInSerializationFormat;
}
namespace DataContractInSerializationFormat {
  /** @function */
  interface V0 extends DataContractInSerializationFormat {
    [0]: DataContractInSerializationFormatV0;
  }
  /** @ignore */
  const V0: (f0: DataContractInSerializationFormatV0) => DataContractInSerializationFormat.V0;
  /** @function */
  interface V1 extends DataContractInSerializationFormat {
    [0]: DataContractInSerializationFormatV1;
  }
  /** @ignore */
  const V1: (f0: DataContractInSerializationFormatV1) => DataContractInSerializationFormat.V1;
}

interface DataContractInSerializationFormatV0 {
  /** A unique identifier for the data contract. */
  id: Identifier;
  /** Internal configuration for the contract. */
  config: DataContractConfig;
  /** The version of this data contract. */
  version: number;
  /** The identifier of the contract owner. */
  owner_id: Identifier;
  /** Shared subschemas to reuse across documents as $defs object */
  schema_defs?: Map<DefinitionName, Value>;
  /** Document JSON Schemas per type */
  document_schemas: Map<DocumentName, Value>;
}
/** @ignore */
const DataContractInSerializationFormatV0 : BinCodeable<DataContractInSerializationFormatV0> & ((data: {
  /** A unique identifier for the data contract. */
  id: Identifier,
  /** Internal configuration for the contract. */
  config: DataContractConfig,
  /** The version of this data contract. */
  version: number,
  /** The identifier of the contract owner. */
  owner_id: Identifier,
  /** Shared subschemas to reuse across documents as $defs object */
  schema_defs?: Map<DefinitionName, Value>,
  /** Document JSON Schemas per type */
  document_schemas: Map<DocumentName, Value>,
}) => DataContractInSerializationFormatV0);

interface DataContractInSerializationFormatV1 {
  /** A unique identifier for the data contract. */
  id: Identifier;
  /** Internal configuration for the contract. */
  config: DataContractConfig;
  /** The version of this data contract. */
  version: number;
  /** The identifier of the contract owner. */
  owner_id: Identifier;
  /** Shared subschemas to reuse across documents as $defs object */
  schema_defs?: Map<DefinitionName, Value>;
  /** Document JSON Schemas per type */
  document_schemas: Map<DocumentName, Value>;
  /** The time in milliseconds that the contract was created. */
  created_at?: TimestampMillis;
  /** The time in milliseconds that the contract was last updated. */
  updated_at?: TimestampMillis;
  /** The block that the document was created. */
  created_at_block_height?: BlockHeight;
  /** The block that the contract was last updated */
  updated_at_block_height?: BlockHeight;
  /** The epoch at which the contract was created. */
  created_at_epoch?: EpochIndex;
  /** The epoch at which the contract was last updated. */
  updated_at_epoch?: EpochIndex;
  /** Groups that allow for specific multiparty actions on the contract */
  groups: Map<GroupContractPosition, Group>;
  /** The tokens on the contract. */
  tokens: Map<TokenContractPosition, TokenConfiguration>;
}
/** @ignore */
const DataContractInSerializationFormatV1 : BinCodeable<DataContractInSerializationFormatV1> & ((data: {
  /** A unique identifier for the data contract. */
  id: Identifier,
  /** Internal configuration for the contract. */
  config: DataContractConfig,
  /** The version of this data contract. */
  version: number,
  /** The identifier of the contract owner. */
  owner_id: Identifier,
  /** Shared subschemas to reuse across documents as $defs object */
  schema_defs?: Map<DefinitionName, Value>,
  /** Document JSON Schemas per type */
  document_schemas: Map<DocumentName, Value>,
  /** The time in milliseconds that the contract was created. */
  created_at?: TimestampMillis,
  /** The time in milliseconds that the contract was last updated. */
  updated_at?: TimestampMillis,
  /** The block that the document was created. */
  created_at_block_height?: BlockHeight,
  /** The block that the contract was last updated */
  updated_at_block_height?: BlockHeight,
  /** The epoch at which the contract was created. */
  created_at_epoch?: EpochIndex,
  /** The epoch at which the contract was last updated. */
  updated_at_epoch?: EpochIndex,
  /** Groups that allow for specific multiparty actions on the contract */
  groups: Map<GroupContractPosition, Group>,
  /** The tokens on the contract. */
  tokens: Map<TokenContractPosition, TokenConfiguration>,
}) => DataContractInSerializationFormatV1);

/** platform_version_path_bounds "dpp.state_transition_serialization_versions.contract_update_state_transition" */
/** @ignore */
export abstract class DataContractUpdateTransition {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: DataContractUpdateTransition): void;
  /** @ignore */
  static decode(bc: BinCode): DataContractUpdateTransition;
}
namespace DataContractUpdateTransition {
  /** @function */
  interface V0 extends DataContractUpdateTransition {
    [0]: DataContractUpdateTransitionV0;
  }
  /** @ignore */
  const V0: (f0: DataContractUpdateTransitionV0) => DataContractUpdateTransition.V0;
}

interface DataContractUpdateTransitionV0 {
  identity_contract_nonce: IdentityNonce;
  data_contract: DataContractInSerializationFormat;
  user_fee_increase: UserFeeIncrease;
  /** platform_signable exclude_from_sig_hash */
  signature_public_key_id: KeyID;
  /** platform_signable exclude_from_sig_hash */
  signature: BinaryData;
}
/** @ignore */
const DataContractUpdateTransitionV0 : BinCodeable<DataContractUpdateTransitionV0> & ((data: {
  identity_contract_nonce: IdentityNonce,
  data_contract: DataContractInSerializationFormat,
  user_fee_increase: UserFeeIncrease,
  /** platform_signable exclude_from_sig_hash */
  signature_public_key_id: KeyID,
  /** platform_signable exclude_from_sig_hash */
  signature: BinaryData,
}) => DataContractUpdateTransitionV0);

export type DefinitionName = string;

export type DerivationEncryptionKeyIndex = number;

/** @ignore */
export abstract class DistributionFunction {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: DistributionFunction): void;
  /** @ignore */
  static decode(bc: BinCode): DistributionFunction;
}
namespace DistributionFunction {
  /**
   * Emits a constant (fixed) number of tokens for every period.
   * 
   *  # Formula
   *  For any period `x`, the emitted tokens are:
   * 
   *  ```text
   *  f(x) = n
   *  ```
   * 
   *  # Use Case
   *  - When a predictable, unchanging reward is desired.
   *  - Simplicity and stable emissions.
   * 
   *  # Example
   *  - If `n = 5` tokens per block, then after 3 blocks the total emission is 15 tokens.
   * 
   * @function
   */
  interface FixedAmount extends DistributionFunction {
    amount: TokenAmount;
  }
  const FixedAmount: (data: {
    amount: TokenAmount,
  }) => DistributionFunction.FixedAmount;
  /**
   * Emits a random number of tokens within a specified range.
   * 
   *  # Description
   *  - This function selects a **random** token emission amount between `min` and `max`.
   *  - The value is drawn **uniformly** between the bounds.
   *  - The randomness uses a Pseudo Random Function (PRF) from x.
   * 
   *  # Formula
   *  For any period `x`, the emitted tokens follow:
   * 
   *  ```text
   *  f(x) ∈ [min, max]
   *  ```
   * 
   *  # Parameters
   *  - `min`: The **minimum** possible number of tokens emitted.
   *  - `max`: The **maximum** possible number of tokens emitted.
   * 
   *  # Use Cases
   *  - **Stochastic Rewards**: Introduces randomness into rewards to incentivize unpredictability.
   *  - **Lottery-Based Systems**: Used for randomized emissions, such as block rewards with probabilistic payouts.
   * 
   *  # Example
   *  Suppose a system emits **between 10 and 100 tokens per period**.
   * 
   *  ```text
   *  Random { min: 10, max: 100 }
   *  ```
   * 
   *  | Period (x) | Emitted Tokens (Random) |
   *  |------------|------------------------|
   *  | 1          | 27                     |
   *  | 2          | 94                     |
   *  | 3          | 63                     |
   *  | 4          | 12                     |
   * 
   *  - Each period, the function emits a **random number of tokens** between `min = 10` and `max = 100`.
   *  - Over time, the **average reward trends toward the midpoint** `(min + max) / 2`.
   * 
   *  # Constraints
   *  - **`min` must be ≤ `max`**, otherwise the function is invalid.
   *  - If `min == max`, this behaves like a `FixedAmount` function with a constant emission.
   * 
   * @function
   */
  interface Random extends DistributionFunction {
    min: TokenAmount;
    max: TokenAmount;
  }
  const Random: (data: {
    min: TokenAmount,
    max: TokenAmount,
  }) => DistributionFunction.Random;
  /**
   * Emits tokens that decrease in discrete steps at fixed intervals.
   * 
   *  # Formula
   *  For a given period `x`, the emission is calculated as:
   * 
   *  ```text
   *  f(x) = n * (1 - (decrease_per_interval_numerator / decrease_per_interval_denominator))^((x - s) / step_count)
   *  ```
   * 
   *  # Parameters
   *  - `step_count`: The number of periods between each step.
   *  - `decrease_per_interval_numerator` and `decrease_per_interval_denominator`: Define the reduction factor per step.
   *  - `s`: Optional start period offset (e.g., start block or time). If not provided, the contract creation start is used.
   *  - `n`: The initial token emission.
   *  - `min_value`: Optional minimum emission value.
   * 
   *  # Use Case
   *  - Modeling reward systems similar to Bitcoin or Dash Core.
   *  - Encouraging early participation by providing higher rewards initially.
   * 
   *  # Example
   *  - Bitcoin-style: 50% reduction every 210,000 blocks.
   *  - Dash-style: Approximately a 7% reduction every 210,000 blocks.
   * 
   * @function
   */
  interface StepDecreasingAmount extends DistributionFunction {
    step_count: number;
    decrease_per_interval_numerator: number;
    decrease_per_interval_denominator: number;
    s?: bigint;
    n: TokenAmount;
    min_value?: bigint;
  }
  const StepDecreasingAmount: (data: {
    step_count: number,
    decrease_per_interval_numerator: number,
    decrease_per_interval_denominator: number,
    s?: bigint,
    n: TokenAmount,
    min_value?: bigint,
  }) => DistributionFunction.StepDecreasingAmount;
  /**
   * Emits tokens in fixed amounts for predefined intervals (steps).
   * 
   *  # Details
   *  - Within each step, the emission remains constant.
   *  - The keys in the `BTreeMap` represent the starting period for each interval,
   *    and the corresponding values are the fixed token amounts to emit during that interval.
   * 
   *  # Use Case
   *  - Adjusting rewards at specific milestones or time intervals.
   * 
   *  # Example
   *  - Emit 100 tokens per block for the first 1,000 blocks, then 50 tokens per block thereafter.
   * 
   * @function
   */
  interface Stepwise extends DistributionFunction {
    [0]: Map<bigint, TokenAmount>;
  }
  /** @ignore */
  const Stepwise: (f0: Map<bigint, TokenAmount>) => DistributionFunction.Stepwise;
  /**
   * Emits tokens following a linear function that can increase or decrease over time
   *  with fractional precision.
   * 
   *  # Formula
   *  The emission at period `x` is given by:
   * 
   *  ```text
   *  f(x) = (a * (x - start_moment) / d) + starting_amount
   *  ```
   * 
   *  # Parameters
   *  - `a`: The slope numerator; determines the rate of change.
   *  - `d`: The slope divisor; together with `a` controls the fractional rate.
   *  - `s`: Optional start period offset. If not set, the contract creation start is assumed.
   *  - `b`: The initial token emission (offset).
   *  - `min_value` / `max_value`: Optional bounds to clamp the emission.
   * 
   *  # Details
   *  - If `a > 0`, emissions increase over time.
   *  - If `a < 0`, emissions decrease over time.
   * 
   *  # Behavior
   *  - **If `a > 0`**, emissions increase linearly over time.
   *  - **If `a < 0`**, emissions decrease linearly over time.
   *  - **If `a = 0`**, emissions remain constant at `b`.
   * 
   *  # Use Cases
   *  - **Predictable Inflation or Deflation:** A simple mechanism to adjust token supply dynamically.
   *  - **Long-Term Incentive Structures:** Ensures steady and measurable growth or reduction of rewards.
   *  - **Decaying Emissions:** Can be used to gradually taper off token rewards over time.
   *  - **Sustained Growth Models:** Encourages prolonged engagement by steadily increasing rewards.
   * 
   *  # Examples
   * 
   *  ## **1️⃣ Increasing Linear Emission (`a > 0`)**
   *  - Tokens increase by **1 token per block** starting from 10.
   * 
   *  ```text
   *  f(x) = (1 * (x - 0) / 1) + 10
   *  ```
   * 
   *  | Block (x) | f(x) (Tokens) |
   *  |-----------|---------------|
   *  | 0         | 10            |
   *  | 1         | 11            |
   *  | 2         | 12            |
   *  | 3         | 13            |
   * 
   *  **Use Case:** Encourages continued participation by providing increasing rewards over time.
   * 
   *  ---
   * 
   *  ## **2️⃣ Decreasing Linear Emission (`a < 0`)**
   *  - Tokens **start at 100 and decrease by 2 per period**.
   * 
   *  ```text
   *  f(x) = (-2 * (x - 0) / 1) + 100
   *  ```
   * 
   *  | Block (x) | f(x) (Tokens) |
   *  |-----------|---------------|
   *  | 0         | 100           |
   *  | 1         | 98            |
   *  | 2         | 96            |
   *  | 3         | 94            |
   * 
   *  **Use Case:** Suitable for deflationary models where rewards need to decrease over time.
   * 
   *  ---
   * 
   *  ## **3️⃣ Emission with a Delayed Start (`s > 0`)**
   *  - **No emissions before `x = s`** (e.g., rewards start at block `10`).
   * 
   *  ```text
   *  f(x) = (5 * (x - 10) / 1) + 50
   *  ```
   * 
   *  | Block (x) | f(x) (Tokens) |
   *  |-----------|---------------|
   *  | 9         | 50 (no change)|
   *  | 10        | 50            |
   *  | 11        | 55            |
   *  | 12        | 60            |
   * 
   *  **Use Case:** Useful when rewards should only begin at a specific milestone.
   * 
   *  ---
   * 
   *  ## **4️⃣ Clamping Emissions with `min_value` and `max_value`**
   *  - **Start at 50, increase by 2, but never exceed 60.**
   * 
   *  ```text
   *  f(x) = (2 * (x - 0) / 1) + 50
   *  ```
   * 
   *  | Block (x) | f(x) (Tokens) |
   *  |-----------|---------------|
   *  | 0         | 50            |
   *  | 1         | 52            |
   *  | 2         | 54            |
   *  | 5         | 60 (max cap)  |
   * 
   *  **Use Case:** Prevents runaway inflation by limiting the emission range.
   * 
   *  ---
   * 
   *  # Summary
   *  - **Increasing rewards (`a > 0`)**: Encourages longer participation.
   *  - **Decreasing rewards (`a < 0`)**: Supports controlled deflation.
   *  - **Delayed start (`s > 0`)**: Ensures rewards only begin at a specific point.
   *  - **Clamping (`min_value`, `max_value`)**: Maintains controlled emission boundaries.
   * 
   * @function
   */
  interface Linear extends DistributionFunction {
    a: bigint;
    d: bigint;
    start_step?: bigint;
    starting_amount: TokenAmount;
    min_value?: bigint;
    max_value?: bigint;
  }
  const Linear: (data: {
    a: bigint,
    d: bigint,
    start_step?: bigint,
    starting_amount: TokenAmount,
    min_value?: bigint,
    max_value?: bigint,
  }) => DistributionFunction.Linear;
  /**
   * Emits tokens following a polynomial curve with integer arithmetic.
   * 
   *  # Formula
   *  The emission at period `x` is given by:
   * 
   *  ```text
   *  f(x) = (a * (x - s + o)^(m/n)) / d + b
   *  ```
   * 
   *  # Parameters
   *  - `a`: Scaling factor for the polynomial term.
   *  - `m` and `n`: Together specify the exponent as a rational number (allowing non-integer exponents).
   *  - `d`: A divisor for scaling.
   *  - `s`: Optional start period offset. If not provided, the contract creation start is used.
   *  - `o`: An offset for the polynomial function, this is useful if s is in None,
   *  - `b`: An offset added to the computed value.
   *  - `min_value` / `max_value`: Optional bounds to constrain the emission.
   * 
   *  # Behavior & Use Cases
   *  The polynomial function's behavior depends on the values of `a` (scaling factor) and `m` (exponent numerator).
   * 
   *  ## **1️⃣ `a > 0`, `m > 0` (Increasing Polynomial Growth)**
   *  - **Behavior**: Emissions **increase at an accelerating rate** over time.
   *  - **Use Case**: Suitable for models where incentives start small and grow over time (e.g., boosting late-stage participation).
   *  - **Example**:
   *    ```text
   *    f(x) = (2 * (x - s + o)^2) / d + 10
   *    ```
   *    - If `s = 0`, `o = 0`, and `d = 1`, then:
   *      - `f(1) = 12`
   *      - `f(2) = 18`
   *      - `f(3) = 28` (Emissions **accelerate over time**)
   * 
   *  ## **2️⃣ `a > 0`, `m < 0` (Decreasing Polynomial Decay)**
   *  - **Behavior**: Emissions **start high and gradually decline**.
   *  - **Use Case**: Useful for front-loaded incentives where rewards are larger at the beginning and taper off over time.
   *  - **Example**:
   *    ```text
   *    f(x) = (5 * (x - s + o)^(-1)) / d + 10
   *    ```
   *    - If `s = 0`, `o = 0`, and `d = 1`, then:
   *      - `f(1) = 15`
   *      - `f(2) = 12.5`
   *      - `f(3) = 11.67` (Emissions **shrink but never hit zero**)
   * 
   *  ## **3️⃣ `a < 0`, `m > 0` (Inverted Growth → Decreasing Over Time)**
   *  - **Behavior**: Emissions **start large but decrease faster over time**.
   *  - **Use Case**: Suitable for cases where high initial incentives quickly drop off (e.g., limited early rewards).
   *  - **Example**:
   *    ```text
   *    f(x) = (-3 * (x - s + o)^2) / d + 50
   *    ```
   *    - If `s = 0`, `o = 0`, and `d = 1`, then:
   *      - `f(1) = 47`
   *      - `f(2) = 38`
   *      - `f(3) = 23` (Emissions **fall sharply**)
   * 
   *  ## **4️⃣ `a < 0`, `m < 0` (Inverted Decay → Slowing Increase)**
   *  - **Behavior**: Emissions **start low, rise gradually, and then flatten out**.
   *  - **Use Case**: Useful for controlled inflation where rewards increase over time but approach a stable maximum.
   *  - **Example**:
   *    ```text
   *    f(x) = (-10 * (x - s + o)^(-2)) / d + 50
   *    ```
   *    - If `s = 0`, `o = 0`, and `d = 1`, then:
   *      - `f(1) = 40`
   *      - `f(2) = 47.5`
   *      - `f(3) = 48.89` (Growth **slows as it approaches 50**)
   * 
   *  # Summary
   *  - **Positive `a` means increasing emissions**, while **negative `a` means decreasing emissions**.
   *  - **Positive `m` leads to growth**, while **negative `m` leads to decay**.
   *  - The combination of `a` and `m` defines whether emissions accelerate, decay, or remain stable.
   * 
   * @function
   */
  interface Polynomial extends DistributionFunction {
    a: bigint;
    d: bigint;
    m: bigint;
    n: bigint;
    o: bigint;
    start_moment?: bigint;
    b: TokenAmount;
    min_value?: bigint;
    max_value?: bigint;
  }
  const Polynomial: (data: {
    a: bigint,
    d: bigint,
    m: bigint,
    n: bigint,
    o: bigint,
    start_moment?: bigint,
    b: TokenAmount,
    min_value?: bigint,
    max_value?: bigint,
  }) => DistributionFunction.Polynomial;
  /**
   * Emits tokens following an exponential function.
   * 
   *  # Formula
   *  The emission at period `x` is given by:
   * 
   *  ```text
   *  f(x) = (a * e^(m * (x - s) / n)) / d + c
   *  ```
   * 
   *  # Parameters
   *  - `a`: The scaling factor.
   *  - `m` and `n`: Define the exponent rate (with `m > 0` for growth and `m < 0` for decay).
   *  - `d`: A divisor used to scale the exponential term.
   *  - `s`: Optional start period offset. If not set, the contract creation start is assumed.
   *  - `o`: An offset for the exp function, this is useful if s is in None.
   *  - `c`: An offset added to the result.
   *  - `min_value` / `max_value`: Optional constraints on the emitted tokens.
   * 
   *  # Use Cases
   *  ## **Exponential Growth (`m > 0`):**
   *  - **Incentivized Spending**: Higher emissions over time increase the circulating supply, encouraging users to spend tokens.
   *  - **Progressive Emission Models**: Useful for models where early emissions are low but increase significantly over time.
   *  - **Early-Stage Adoption Strategies**: Helps drive later participation by offering increasing rewards as time progresses.
   * 
   *  ## **Exponential Decay (`m < 0`):**
   *  - **Deflationary Reward Models**: Reduces emissions over time, ensuring token scarcity.
   *  - **Early Participation Incentives**: Encourages early users by distributing more tokens initially and gradually decreasing rewards.
   *  - **Sustainable Emission Models**: Helps manage token supply while preventing runaway inflation.
   * 
   *  # Examples
   *  ## **Example 1: Exponential Growth (`m > 0`)**
   *  - **Use Case**: A staking model where rewards increase over time to encourage long-term participation.
   *  - **Parameters**: `a = 100`, `m = 2`, `n = 50`, `d = 10`, `c = 5`
   *  - **Formula**:
   *    ```text
   *    f(x) = (100 * e^(2 * (x - s) / 50)) / 10 + 5
   *    ```
   *  - **Effect**: Emissions start small but **increase exponentially** over time, rewarding late stakers more than early ones.
   * 
   *  ## **Example 2: Exponential Decay (`m < 0`)**
   *  - **Use Case**: A deflationary model where emissions start high and gradually decrease to ensure scarcity.
   *  - **Parameters**: `a = 500`, `m = -3`, `n = 100`, `d = 20`, `c = 10`
   *  - **Formula**:
   *    ```text
   *    f(x) = (500 * e^(-3 * (x - s) / 100)) / 20 + 10
   *    ```
   *  - **Effect**: Emissions start **high and decay exponentially**, ensuring early participants get larger rewards.
   * 
   * @function
   */
  interface Exponential extends DistributionFunction {
    a: bigint;
    d: bigint;
    m: bigint;
    n: bigint;
    o: bigint;
    start_moment?: bigint;
    c: TokenAmount;
    min_value?: bigint;
    max_value?: bigint;
  }
  const Exponential: (data: {
    a: bigint,
    d: bigint,
    m: bigint,
    n: bigint,
    o: bigint,
    start_moment?: bigint,
    c: TokenAmount,
    min_value?: bigint,
    max_value?: bigint,
  }) => DistributionFunction.Exponential;
  /**
   * Emits tokens following a logarithmic function.
   * 
   *  # Formula
   *  The emission at period `x` is computed as:
   * 
   *  ```text
   *  f(x) = (a * log(m * (x - s + o) / n)) / d + b
   *  ```
   * 
   *  # Parameters
   *  - `a`: Scaling factor for the logarithmic term.
   *  - `d`: A divisor for scaling.
   *  - `m` and `n`: Adjust the input to the logarithm function.
   *  - `s`: Optional start period offset. If not provided, the contract creation start is used.
   *  - `o`: An offset for the log function, this is useful if s is in None.
   *  - `b`: An offset added to the result.
   *  - `min_value` / `max_value`: Optional bounds to ensure the emission remains within limits.
   * 
   *  # Use Case
   *  - **Gradual Growth with a Slowing Rate**: Suitable for reward schedules where the emission
   *    starts at a lower rate, increases quickly at first, but then slows down over time.
   *  - **Predictable Emission Scaling**: Ensures a growing but controlled emission curve that
   *    does not escalate too quickly.
   *  - **Sustainability and Inflation Control**: Helps prevent runaway token supply growth
   *    by ensuring rewards increase at a decreasing rate.
   * 
   *  # Example
   *  - Suppose we want token emissions to start at a low value and grow over time, but at a
   *    **decreasing rate**, ensuring controlled long-term growth.
   * 
   *  - Given the formula:
   *    ```text
   *    f(x) = (a * log(m * (x - s + o) / n)) / d + b
   *    ```
   * 
   *  - Let’s assume the following parameters:
   *    - `a = 100`: Scaling factor.
   *    - `d = 10`: Divisor to control overall scaling.
   *    - `m = 2`, `n = 1`: Adjust the logarithmic input.
   *    - `s = 0`, `o = 1`: Starting conditions.
   *    - `b = 50`: Base amount added.
   * 
   *  - This results in:
   *    ```text
   *    f(x) = (100 * log(2 * (x + 1) / 1)) / 10 + 50
   *    ```
   * 
   *  - **Expected Behavior:**
   *    - At `x = 1`, emission = `f(1) = (100 * log(4)) / 10 + 50 ≈ 82`
   *    - At `x = 10`, emission = `f(10) = (100 * log(22)) / 10 + 50 ≈ 106`
   *    - At `x = 100`, emission = `f(100) = (100 * log(202)) / 10 + 50 ≈ 130`
   * 
   *  - **Observations:**
   *    - The emission **increases** over time, but at a **slowing rate**.
   *    - Early increases are more pronounced, but as `x` grows, the additional reward per
   *      period gets smaller.
   *    - This makes it ideal for long-term, controlled emission models.
   * 
   * @function
   */
  interface Logarithmic extends DistributionFunction {
    a: bigint;
    d: bigint;
    m: bigint;
    n: bigint;
    o: bigint;
    start_moment?: bigint;
    b: TokenAmount;
    min_value?: bigint;
    max_value?: bigint;
  }
  const Logarithmic: (data: {
    a: bigint,
    d: bigint,
    m: bigint,
    n: bigint,
    o: bigint,
    start_moment?: bigint,
    b: TokenAmount,
    min_value?: bigint,
    max_value?: bigint,
  }) => DistributionFunction.Logarithmic;
  /**
   * Emits tokens following an inverted logarithmic function.
   * 
   *  # Formula
   *  The emission at period `x` is given by:
   * 
   *  ```text
   *  f(x) = (a * log( n / (m * (x - s + o)) )) / d + b
   *  ```
   * 
   *  # Parameters
   *  - `a`: Scaling factor.
   *  - `d`: Divisor for scaling.
   *  - `m` and `n`: Together control the logarithm argument inversion.
   *  - `o`: Offset applied inside the logarithm.
   *  - `s`: Optional start period offset.
   *  - `b`: Offset added to the computed value.
   *  - `min_value` / `max_value`: Optional boundaries for the emission.
   * 
   *  # Use Case
   *  - **Gradual Decay of Rewards**: Suitable when early adopters should receive higher rewards,
   *    but later participants should receive smaller but still meaningful amounts.
   *  - **Resource Draining / Controlled Burn**: Used when token emissions should drop significantly
   *    at first but slow down over time to preserve capital.
   *  - **Airdrop or Grant System**: Ensures early claimants receive larger distributions, but later
   *    claimants receive diminishing rewards.
   * 
   *  # Example
   *  - Suppose a system starts with **500 tokens per period** and gradually reduces over time:
   * 
   *    ```text
   *    f(x) = (1000 * log(5000 / (5 * (x - 1000)))) / 10 + 10
   *    ```
   * 
   *    Example values:
   * 
   *    | Period (x) | Emission (f(x)) |
   *    |------------|----------------|
   *    | 1000       | 500 tokens      |
   *    | 1500       | 230 tokens      |
   *    | 2000       | 150 tokens      |
   *    | 5000       | 50 tokens       |
   *    | 10,000     | 20 tokens       |
   *    | 50,000     | 10 tokens       |
   * 
   *    - The emission **starts high** and **gradually decreases**, ensuring early adopters receive
   *      more tokens while later participants still get rewards.
   *    - The function **slows down the rate of decrease** over time, preventing emissions from
   *      hitting zero too quickly.
   * 
   * @function
   */
  interface InvertedLogarithmic extends DistributionFunction {
    a: bigint;
    d: bigint;
    m: bigint;
    n: bigint;
    o: bigint;
    start_moment?: bigint;
    b: TokenAmount;
    min_value?: bigint;
    max_value?: bigint;
  }
  const InvertedLogarithmic: (data: {
    a: bigint,
    d: bigint,
    m: bigint,
    n: bigint,
    o: bigint,
    start_moment?: bigint,
    b: TokenAmount,
    min_value?: bigint,
    max_value?: bigint,
  }) => DistributionFunction.InvertedLogarithmic;
}

/** @ignore */
export abstract class DocumentBaseTransition {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: DocumentBaseTransition): void;
  /** @ignore */
  static decode(bc: BinCode): DocumentBaseTransition;
}
namespace DocumentBaseTransition {
  /** @function */
  interface V0 extends DocumentBaseTransition {
    [0]: DocumentBaseTransitionV0;
  }
  /** @ignore */
  const V0: (f0: DocumentBaseTransitionV0) => DocumentBaseTransition.V0;
}

interface DocumentBaseTransitionV0 {
  /** The document ID */
  id: Identifier;
  identity_contract_nonce: IdentityNonce;
  /** Name of document type found int the data contract associated with the `data_contract_id` */
  document_type_name: string;
  /** Data contract ID generated from the data contract's `owner_id` and `entropy` */
  data_contract_id: Identifier;
}
/** @ignore */
const DocumentBaseTransitionV0 : BinCodeable<DocumentBaseTransitionV0> & ((data: {
  /** The document ID */
  id: Identifier,
  identity_contract_nonce: IdentityNonce,
  /** Name of document type found int the data contract associated with the `data_contract_id` */
  document_type_name: string,
  /** Data contract ID generated from the data contract's `owner_id` and `entropy` */
  data_contract_id: Identifier,
}) => DocumentBaseTransitionV0);

/** @ignore */
export abstract class DocumentCreateTransition {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: DocumentCreateTransition): void;
  /** @ignore */
  static decode(bc: BinCode): DocumentCreateTransition;
}
namespace DocumentCreateTransition {
  /** @function */
  interface V0 extends DocumentCreateTransition {
    [0]: DocumentCreateTransitionV0;
  }
  /** @ignore */
  const V0: (f0: DocumentCreateTransitionV0) => DocumentCreateTransition.V0;
}

interface DocumentCreateTransitionV0 {
  /** Document Base Transition */
  base: DocumentBaseTransition;
  /** Entropy used to create a Document ID. */
  entropy: FixedBytes<32>;
  data: Map<string, Value>;
  /**
   * Pre funded balance (for unique index conflict resolution voting - the identity will put money
   *  aside that will be used by voters to vote)
   *  This is a map of index names to the amount we want to prefund them for
   *  Since index conflict resolution is not a common feature most often nothing should be added here.
   */
  prefunded_voting_balance?: [string, Credits];
}
/** @ignore */
const DocumentCreateTransitionV0 : BinCodeable<DocumentCreateTransitionV0> & ((data: {
  /** Document Base Transition */
  base: DocumentBaseTransition,
  /** Entropy used to create a Document ID. */
  entropy: FixedBytes<32>,
  data: Map<string, Value>,
  /**
   * Pre funded balance (for unique index conflict resolution voting - the identity will put money
   *  aside that will be used by voters to vote)
   *  This is a map of index names to the amount we want to prefund them for
   *  Since index conflict resolution is not a common feature most often nothing should be added here.
   */
  prefunded_voting_balance?: [string, Credits],
}) => DocumentCreateTransitionV0);

/** @ignore */
export abstract class DocumentDeleteTransition {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: DocumentDeleteTransition): void;
  /** @ignore */
  static decode(bc: BinCode): DocumentDeleteTransition;
}
namespace DocumentDeleteTransition {
  /** @function */
  interface V0 extends DocumentDeleteTransition {
    [0]: DocumentDeleteTransitionV0;
  }
  /** @ignore */
  const V0: (f0: DocumentDeleteTransitionV0) => DocumentDeleteTransition.V0;
}

interface DocumentDeleteTransitionV0 {
  base: DocumentBaseTransition;
}
/** @ignore */
const DocumentDeleteTransitionV0 : BinCodeable<DocumentDeleteTransitionV0> & ((data: {
  base: DocumentBaseTransition,
}) => DocumentDeleteTransitionV0);

export type DocumentName = string;

/** @ignore */
export abstract class DocumentPurchaseTransition {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: DocumentPurchaseTransition): void;
  /** @ignore */
  static decode(bc: BinCode): DocumentPurchaseTransition;
}
namespace DocumentPurchaseTransition {
  /** @function */
  interface V0 extends DocumentPurchaseTransition {
    [0]: DocumentPurchaseTransitionV0;
  }
  /** @ignore */
  const V0: (f0: DocumentPurchaseTransitionV0) => DocumentPurchaseTransition.V0;
}

interface DocumentPurchaseTransitionV0 {
  base: DocumentBaseTransition;
  revision: Revision;
  price: Credits;
}
/** @ignore */
const DocumentPurchaseTransitionV0 : BinCodeable<DocumentPurchaseTransitionV0> & ((data: {
  base: DocumentBaseTransition,
  revision: Revision,
  price: Credits,
}) => DocumentPurchaseTransitionV0);

/** @ignore */
export abstract class DocumentReplaceTransition {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: DocumentReplaceTransition): void;
  /** @ignore */
  static decode(bc: BinCode): DocumentReplaceTransition;
}
namespace DocumentReplaceTransition {
  /** @function */
  interface V0 extends DocumentReplaceTransition {
    [0]: DocumentReplaceTransitionV0;
  }
  /** @ignore */
  const V0: (f0: DocumentReplaceTransitionV0) => DocumentReplaceTransition.V0;
}

interface DocumentReplaceTransitionV0 {
  base: DocumentBaseTransition;
  revision: Revision;
  data: Map<string, Value>;
}
/** @ignore */
const DocumentReplaceTransitionV0 : BinCodeable<DocumentReplaceTransitionV0> & ((data: {
  base: DocumentBaseTransition,
  revision: Revision,
  data: Map<string, Value>,
}) => DocumentReplaceTransitionV0);

/** @ignore */
export abstract class DocumentTransferTransition {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: DocumentTransferTransition): void;
  /** @ignore */
  static decode(bc: BinCode): DocumentTransferTransition;
}
namespace DocumentTransferTransition {
  /** @function */
  interface V0 extends DocumentTransferTransition {
    [0]: DocumentTransferTransitionV0;
  }
  /** @ignore */
  const V0: (f0: DocumentTransferTransitionV0) => DocumentTransferTransition.V0;
}

interface DocumentTransferTransitionV0 {
  base: DocumentBaseTransition;
  revision: Revision;
  recipient_owner_id: Identifier;
}
/** @ignore */
const DocumentTransferTransitionV0 : BinCodeable<DocumentTransferTransitionV0> & ((data: {
  base: DocumentBaseTransition,
  revision: Revision,
  recipient_owner_id: Identifier,
}) => DocumentTransferTransitionV0);

/** @ignore */
export abstract class DocumentTransition {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: DocumentTransition): void;
  /** @ignore */
  static decode(bc: BinCode): DocumentTransition;
}
namespace DocumentTransition {
  /** @function */
  interface Create extends DocumentTransition {
    [0]: DocumentCreateTransition;
  }
  /** @ignore */
  const Create: (f0: DocumentCreateTransition) => DocumentTransition.Create;
  /** @function */
  interface Replace extends DocumentTransition {
    [0]: DocumentReplaceTransition;
  }
  /** @ignore */
  const Replace: (f0: DocumentReplaceTransition) => DocumentTransition.Replace;
  /** @function */
  interface Delete extends DocumentTransition {
    [0]: DocumentDeleteTransition;
  }
  /** @ignore */
  const Delete: (f0: DocumentDeleteTransition) => DocumentTransition.Delete;
  /** @function */
  interface Transfer extends DocumentTransition {
    [0]: DocumentTransferTransition;
  }
  /** @ignore */
  const Transfer: (f0: DocumentTransferTransition) => DocumentTransition.Transfer;
  /** @function */
  interface UpdatePrice extends DocumentTransition {
    [0]: DocumentUpdatePriceTransition;
  }
  /** @ignore */
  const UpdatePrice: (f0: DocumentUpdatePriceTransition) => DocumentTransition.UpdatePrice;
  /** @function */
  interface Purchase extends DocumentTransition {
    [0]: DocumentPurchaseTransition;
  }
  /** @ignore */
  const Purchase: (f0: DocumentPurchaseTransition) => DocumentTransition.Purchase;
}

/** @ignore */
export abstract class DocumentUpdatePriceTransition {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: DocumentUpdatePriceTransition): void;
  /** @ignore */
  static decode(bc: BinCode): DocumentUpdatePriceTransition;
}
namespace DocumentUpdatePriceTransition {
  /** @function */
  interface V0 extends DocumentUpdatePriceTransition {
    [0]: DocumentUpdatePriceTransitionV0;
  }
  /** @ignore */
  const V0: (f0: DocumentUpdatePriceTransitionV0) => DocumentUpdatePriceTransition.V0;
}

interface DocumentUpdatePriceTransitionV0 {
  base: DocumentBaseTransition;
  revision: Revision;
  price: Credits;
}
/** @ignore */
const DocumentUpdatePriceTransitionV0 : BinCodeable<DocumentUpdatePriceTransitionV0> & ((data: {
  base: DocumentBaseTransition,
  revision: Revision,
  price: Credits,
}) => DocumentUpdatePriceTransitionV0);

export type EpochIndex = number;

export type EpochInterval = number;

/** @ignore */
export abstract class Group {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: Group): void;
  /** @ignore */
  static decode(bc: BinCode): Group;
}
namespace Group {
  /** @function */
  interface V0 extends Group {
    [0]: GroupV0;
  }
  /** @ignore */
  const V0: (f0: GroupV0) => Group.V0;
}

export type GroupContractPosition = number;

export type GroupMemberPower = number;

export type GroupRequiredPower = number;

interface GroupStateTransitionInfo {
  group_contract_position: GroupContractPosition;
  action_id: Identifier;
  /** This is true if we are the proposer, otherwise we are just voting on a previous action. */
  action_is_proposer: boolean;
}
/** @ignore */
const GroupStateTransitionInfo : BinCodeable<GroupStateTransitionInfo> & ((data: {
  group_contract_position: GroupContractPosition,
  action_id: Identifier,
  /** This is true if we are the proposer, otherwise we are just voting on a previous action. */
  action_is_proposer: boolean,
}) => GroupStateTransitionInfo);

interface GroupV0 {
  members: Map<Identifier, GroupMemberPower>;
  required_power: GroupRequiredPower;
}
/** @ignore */
const GroupV0 : BinCodeable<GroupV0> & ((data: {
  members: Map<Identifier, GroupMemberPower>,
  required_power: GroupRequiredPower,
}) => GroupV0);

export type Hash256 = FixedBytes<32>;

interface Identifier {
  [0]: IdentifierBytes32;
}
/** @ignore */
const Identifier : BinCodeable<Identifier> & ((
    f0: IdentifierBytes32,
) => Identifier);

interface IdentifierBytes32 {
  [0]: FixedBytes<32>;
}
/** @ignore */
const IdentifierBytes32 : BinCodeable<IdentifierBytes32> & ((
    f0: FixedBytes<32>,
) => IdentifierBytes32);

/** platform_version_path_bounds "dpp.state_transition_serialization_versions.identity_create_state_transition" */
/** @ignore */
export abstract class IdentityCreateTransition {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: IdentityCreateTransition): void;
  /** @ignore */
  static decode(bc: BinCode): IdentityCreateTransition;
}
namespace IdentityCreateTransition {
  /** @function */
  interface V0 extends IdentityCreateTransition {
    [0]: IdentityCreateTransitionV0;
  }
  /** @ignore */
  const V0: (f0: IdentityCreateTransitionV0) => IdentityCreateTransition.V0;
}

/** platform_signable derive_bincode_with_borrowed_vec */
interface IdentityCreateTransitionV0 {
  /** platform_signable into = "Vec<IdentityPublicKeyInCreationSignable>" */
  public_keys: IdentityPublicKeyInCreation[];
  asset_lock_proof: AssetLockProof;
  user_fee_increase: UserFeeIncrease;
  /** platform_signable exclude_from_sig_hash */
  signature: BinaryData;
  /** platform_signable exclude_from_sig_hash */
  identity_id: Identifier;
}
/** @ignore */
const IdentityCreateTransitionV0 : BinCodeable<IdentityCreateTransitionV0> & ((data: {
  /** platform_signable into = "Vec<IdentityPublicKeyInCreationSignable>" */
  public_keys: IdentityPublicKeyInCreation[],
  asset_lock_proof: AssetLockProof,
  user_fee_increase: UserFeeIncrease,
  /** platform_signable exclude_from_sig_hash */
  signature: BinaryData,
  /** platform_signable exclude_from_sig_hash */
  identity_id: Identifier,
}) => IdentityCreateTransitionV0);

/** platform_version_path_bounds "dpp.state_transition_serialization_versions.identity_credit_transfer_state_transition" */
/** @ignore */
export abstract class IdentityCreditTransferTransition {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: IdentityCreditTransferTransition): void;
  /** @ignore */
  static decode(bc: BinCode): IdentityCreditTransferTransition;
}
namespace IdentityCreditTransferTransition {
  /** @function */
  interface V0 extends IdentityCreditTransferTransition {
    [0]: IdentityCreditTransferTransitionV0;
  }
  /** @ignore */
  const V0: (f0: IdentityCreditTransferTransitionV0) => IdentityCreditTransferTransition.V0;
}

interface IdentityCreditTransferTransitionV0 {
  identity_id: Identifier;
  recipient_id: Identifier;
  amount: bigint;
  nonce: IdentityNonce;
  user_fee_increase: UserFeeIncrease;
  /** platform_signable exclude_from_sig_hash */
  signature_public_key_id: KeyID;
  /** platform_signable exclude_from_sig_hash */
  signature: BinaryData;
}
/** @ignore */
const IdentityCreditTransferTransitionV0 : BinCodeable<IdentityCreditTransferTransitionV0> & ((data: {
  identity_id: Identifier,
  recipient_id: Identifier,
  amount: bigint,
  nonce: IdentityNonce,
  user_fee_increase: UserFeeIncrease,
  /** platform_signable exclude_from_sig_hash */
  signature_public_key_id: KeyID,
  /** platform_signable exclude_from_sig_hash */
  signature: BinaryData,
}) => IdentityCreditTransferTransitionV0);

/** platform_version_path "dpp.state_transition_serialization_versions.identity_credit_withdrawal_state_transition" */
/** @ignore */
export abstract class IdentityCreditWithdrawalTransition {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: IdentityCreditWithdrawalTransition): void;
  /** @ignore */
  static decode(bc: BinCode): IdentityCreditWithdrawalTransition;
}
namespace IdentityCreditWithdrawalTransition {
  /** @function */
  interface V0 extends IdentityCreditWithdrawalTransition {
    [0]: IdentityCreditWithdrawalTransitionV0;
  }
  /** @ignore */
  const V0: (f0: IdentityCreditWithdrawalTransitionV0) => IdentityCreditWithdrawalTransition.V0;
  /** @function */
  interface V1 extends IdentityCreditWithdrawalTransition {
    [0]: IdentityCreditWithdrawalTransitionV1;
  }
  /** @ignore */
  const V1: (f0: IdentityCreditWithdrawalTransitionV1) => IdentityCreditWithdrawalTransition.V1;
}

interface IdentityCreditWithdrawalTransitionV0 {
  identity_id: Identifier;
  amount: bigint;
  core_fee_per_byte: number;
  pooling: Pooling;
  output_script: CoreScript;
  nonce: IdentityNonce;
  user_fee_increase: UserFeeIncrease;
  /** platform_signable exclude_from_sig_hash */
  signature_public_key_id: KeyID;
  /** platform_signable exclude_from_sig_hash */
  signature: BinaryData;
}
/** @ignore */
const IdentityCreditWithdrawalTransitionV0 : BinCodeable<IdentityCreditWithdrawalTransitionV0> & ((data: {
  identity_id: Identifier,
  amount: bigint,
  core_fee_per_byte: number,
  pooling: Pooling,
  output_script: CoreScript,
  nonce: IdentityNonce,
  user_fee_increase: UserFeeIncrease,
  /** platform_signable exclude_from_sig_hash */
  signature_public_key_id: KeyID,
  /** platform_signable exclude_from_sig_hash */
  signature: BinaryData,
}) => IdentityCreditWithdrawalTransitionV0);

interface IdentityCreditWithdrawalTransitionV1 {
  identity_id: Identifier;
  amount: bigint;
  core_fee_per_byte: number;
  pooling: Pooling;
  /** If the send to output script is None, then we send the withdrawal to the address set by core */
  output_script?: CoreScript;
  nonce: IdentityNonce;
  user_fee_increase: UserFeeIncrease;
  /** platform_signable exclude_from_sig_hash */
  signature_public_key_id: KeyID;
  /** platform_signable exclude_from_sig_hash */
  signature: BinaryData;
}
/** @ignore */
const IdentityCreditWithdrawalTransitionV1 : BinCodeable<IdentityCreditWithdrawalTransitionV1> & ((data: {
  identity_id: Identifier,
  amount: bigint,
  core_fee_per_byte: number,
  pooling: Pooling,
  /** If the send to output script is None, then we send the withdrawal to the address set by core */
  output_script?: CoreScript,
  nonce: IdentityNonce,
  user_fee_increase: UserFeeIncrease,
  /** platform_signable exclude_from_sig_hash */
  signature_public_key_id: KeyID,
  /** platform_signable exclude_from_sig_hash */
  signature: BinaryData,
}) => IdentityCreditWithdrawalTransitionV1);

export type IdentityNonce = bigint;

/** @ignore */
export abstract class IdentityPublicKey {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: IdentityPublicKey): void;
  /** @ignore */
  static decode(bc: BinCode): IdentityPublicKey;
}
namespace IdentityPublicKey {
  /** @function */
  interface V0 extends IdentityPublicKey {
    [0]: IdentityPublicKeyV0;
  }
  /** @ignore */
  const V0: (f0: IdentityPublicKeyV0) => IdentityPublicKey.V0;
}

/** platform_signable derive_into */
/** @ignore */
export abstract class IdentityPublicKeyInCreation {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: IdentityPublicKeyInCreation): void;
  /** @ignore */
  static decode(bc: BinCode): IdentityPublicKeyInCreation;
}
namespace IdentityPublicKeyInCreation {
  /** @function */
  interface V0 extends IdentityPublicKeyInCreation {
    [0]: IdentityPublicKeyInCreationV0;
  }
  /** @ignore */
  const V0: (f0: IdentityPublicKeyInCreationV0) => IdentityPublicKeyInCreation.V0;
}

interface IdentityPublicKeyInCreationV0 {
  id: KeyID;
  key_type: KeyType;
  purpose: Purpose;
  security_level: SecurityLevel;
  contract_bounds?: ContractBounds;
  read_only: boolean;
  data: BinaryData;
  /**
   * The signature is needed for ECDSA_SECP256K1 Key type and BLS12_381 Key type
   * platform_signable exclude_from_sig_hash
   */
  signature: BinaryData;
}
/** @ignore */
const IdentityPublicKeyInCreationV0 : BinCodeable<IdentityPublicKeyInCreationV0> & ((data: {
  id: KeyID,
  key_type: KeyType,
  purpose: Purpose,
  security_level: SecurityLevel,
  contract_bounds?: ContractBounds,
  read_only: boolean,
  data: BinaryData,
  /**
   * The signature is needed for ECDSA_SECP256K1 Key type and BLS12_381 Key type
   * platform_signable exclude_from_sig_hash
   */
  signature: BinaryData,
}) => IdentityPublicKeyInCreationV0);

interface IdentityPublicKeyV0 {
  id: KeyID;
  purpose: Purpose;
  security_level: SecurityLevel;
  contract_bounds?: ContractBounds;
  key_type: KeyType;
  read_only: boolean;
  data: BinaryData;
  disabled_at?: TimestampMillis;
}
/** @ignore */
const IdentityPublicKeyV0 : BinCodeable<IdentityPublicKeyV0> & ((data: {
  id: KeyID,
  purpose: Purpose,
  security_level: SecurityLevel,
  contract_bounds?: ContractBounds,
  key_type: KeyType,
  read_only: boolean,
  data: BinaryData,
  disabled_at?: TimestampMillis,
}) => IdentityPublicKeyV0);

/** platform_version_path_bounds "dpp.state_transition_serialization_versions.identity_top_up_state_transition" */
/** @ignore */
export abstract class IdentityTopUpTransition {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: IdentityTopUpTransition): void;
  /** @ignore */
  static decode(bc: BinCode): IdentityTopUpTransition;
}
namespace IdentityTopUpTransition {
  /** @function */
  interface V0 extends IdentityTopUpTransition {
    [0]: IdentityTopUpTransitionV0;
  }
  /** @ignore */
  const V0: (f0: IdentityTopUpTransitionV0) => IdentityTopUpTransition.V0;
}

interface IdentityTopUpTransitionV0 {
  asset_lock_proof: AssetLockProof;
  identity_id: Identifier;
  user_fee_increase: UserFeeIncrease;
  /** platform_signable exclude_from_sig_hash */
  signature: BinaryData;
}
/** @ignore */
const IdentityTopUpTransitionV0 : BinCodeable<IdentityTopUpTransitionV0> & ((data: {
  asset_lock_proof: AssetLockProof,
  identity_id: Identifier,
  user_fee_increase: UserFeeIncrease,
  /** platform_signable exclude_from_sig_hash */
  signature: BinaryData,
}) => IdentityTopUpTransitionV0);

/** platform_version_path_bounds "dpp.state_transition_serialization_versions.identity_update_state_transition" */
/** @ignore */
export abstract class IdentityUpdateTransition {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: IdentityUpdateTransition): void;
  /** @ignore */
  static decode(bc: BinCode): IdentityUpdateTransition;
}
namespace IdentityUpdateTransition {
  /** @function */
  interface V0 extends IdentityUpdateTransition {
    [0]: IdentityUpdateTransitionV0;
  }
  /** @ignore */
  const V0: (f0: IdentityUpdateTransitionV0) => IdentityUpdateTransition.V0;
}

/** platform_signable derive_bincode_with_borrowed_vec */
interface IdentityUpdateTransitionV0 {
  /** Unique identifier of the identity to be updated */
  identity_id: Identifier;
  /** The revision of the identity after update */
  revision: Revision;
  /** Identity nonce for this transition to prevent replay attacks */
  nonce: IdentityNonce;
  /**
   * Public Keys to add to the Identity
   *  we want to skip serialization of transitions, as we does it manually in `to_object()`  and `to_json()`
   * platform_signable into = "Vec<IdentityPublicKeyInCreationSignable>"
   */
  add_public_keys: IdentityPublicKeyInCreation[];
  /** Identity Public Keys ID's to disable for the Identity */
  disable_public_keys: KeyID[];
  /** The fee multiplier */
  user_fee_increase: UserFeeIncrease;
  /**
   * The ID of the public key used to sing the State Transition
   * platform_signable exclude_from_sig_hash
   */
  signature_public_key_id: KeyID;
  /**
   * Cryptographic signature of the State Transition
   * platform_signable exclude_from_sig_hash
   */
  signature: BinaryData;
}
/** @ignore */
const IdentityUpdateTransitionV0 : BinCodeable<IdentityUpdateTransitionV0> & ((data: {
  /** Unique identifier of the identity to be updated */
  identity_id: Identifier,
  /** The revision of the identity after update */
  revision: Revision,
  /** Identity nonce for this transition to prevent replay attacks */
  nonce: IdentityNonce,
  /**
   * Public Keys to add to the Identity
   *  we want to skip serialization of transitions, as we does it manually in `to_object()`  and `to_json()`
   * platform_signable into = "Vec<IdentityPublicKeyInCreationSignable>"
   */
  add_public_keys: IdentityPublicKeyInCreation[],
  /** Identity Public Keys ID's to disable for the Identity */
  disable_public_keys: KeyID[],
  /** The fee multiplier */
  user_fee_increase: UserFeeIncrease,
  /**
   * The ID of the public key used to sing the State Transition
   * platform_signable exclude_from_sig_hash
   */
  signature_public_key_id: KeyID,
  /**
   * Cryptographic signature of the State Transition
   * platform_signable exclude_from_sig_hash
   */
  signature: BinaryData,
}) => IdentityUpdateTransitionV0);

export type InstantAssetLockProof = RawInstantLockProof;

export type KeyID = number;

/**
 * allow non_camel_case_types
 * repr u8
 */
/** @ignore */
export abstract class KeyType {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: KeyType): void;
  /** @ignore */
  static decode(bc: BinCode): KeyType;
}
namespace KeyType {
  /** default */
  const ECDSA_SECP256K1: () => KeyType;
  const BLS12_381: () => KeyType;
  const ECDSA_HASH160: () => KeyType;
  const BIP13_SCRIPT_HASH: () => KeyType;
  const EDDSA_25519_HASH160: () => KeyType;
}

/** platform_version_path_bounds "dpp.state_transition_serialization_versions.masternode_vote_state_transition" */
/** @ignore */
export abstract class MasternodeVoteTransition {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: MasternodeVoteTransition): void;
  /** @ignore */
  static decode(bc: BinCode): MasternodeVoteTransition;
}
namespace MasternodeVoteTransition {
  /** @function */
  interface V0 extends MasternodeVoteTransition {
    [0]: MasternodeVoteTransitionV0;
  }
  /** @ignore */
  const V0: (f0: MasternodeVoteTransitionV0) => MasternodeVoteTransition.V0;
}

interface MasternodeVoteTransitionV0 {
  pro_tx_hash: Identifier;
  voter_identity_id: Identifier;
  vote: Vote;
  nonce: IdentityNonce;
  /** platform_signable exclude_from_sig_hash */
  signature_public_key_id: KeyID;
  /** platform_signable exclude_from_sig_hash */
  signature: BinaryData;
}
/** @ignore */
const MasternodeVoteTransitionV0 : BinCodeable<MasternodeVoteTransitionV0> & ((data: {
  pro_tx_hash: Identifier,
  voter_identity_id: Identifier,
  vote: Vote,
  nonce: IdentityNonce,
  /** platform_signable exclude_from_sig_hash */
  signature_public_key_id: KeyID,
  /** platform_signable exclude_from_sig_hash */
  signature: BinaryData,
}) => MasternodeVoteTransitionV0);

/** A reference to a transaction output. */
interface OutPoint {
  /** The referenced transaction's txid. */
  txid: Txid;
  /** The index of the referenced output in its transaction's vout. */
  vout: number;
}
/** @ignore */
const OutPoint : BinCodeable<OutPoint> & ((data: {
  /** The referenced transaction's txid. */
  txid: Txid,
  /** The index of the referenced output in its transaction's vout. */
  vout: number,
}) => OutPoint);

/** repr u8 */
/** @ignore */
export abstract class Pooling {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: Pooling): void;
  /** @ignore */
  static decode(bc: BinCode): Pooling;
}
namespace Pooling {
  /** default */
  const Never: () => Pooling;
  const IfAvailable: () => Pooling;
  const Standard: () => Pooling;
}

export type PrivateEncryptedNote = [RootEncryptionKeyIndex, DerivationEncryptionKeyIndex, Uint8Array];

/** repr u8 */
/** @ignore */
export abstract class Purpose {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: Purpose): void;
  /** @ignore */
  static decode(bc: BinCode): Purpose;
}
namespace Purpose {
  /**
   * at least one authentication key must be registered for all security levels
   * default
   */
  const AUTHENTICATION: () => Purpose;
  /** this key cannot be used for signing documents */
  const ENCRYPTION: () => Purpose;
  /** this key cannot be used for signing documents */
  const DECRYPTION: () => Purpose;
  /** this key is used to sign credit transfer and withdrawal state transitions */
  const TRANSFER: () => Purpose;
  /** this key cannot be used for signing documents */
  const SYSTEM: () => Purpose;
  /** this key cannot be used for signing documents */
  const VOTING: () => Purpose;
  /** this key is used to prove ownership of a masternode or evonode */
  const OWNER: () => Purpose;
}

/**
 * A representation of a dynamic value that can handled dynamically
 * non_exhaustive
 */
/** @ignore */
export abstract class Value {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: Value): void;
  /** @ignore */
  static decode(bc: BinCode): Value;
}
namespace Value {
  /**
   * A u128 integer
   * 
   * @function
   */
  interface U128 extends Value {
    [0]: bigint;
  }
  /** @ignore */
  const U128: (f0: bigint) => Value.U128;
  /**
   * A i128 integer
   * 
   * @function
   */
  interface I128 extends Value {
    [0]: bigint;
  }
  /** @ignore */
  const I128: (f0: bigint) => Value.I128;
  /**
   * A u64 integer
   * 
   * @function
   */
  interface U64 extends Value {
    [0]: bigint;
  }
  /** @ignore */
  const U64: (f0: bigint) => Value.U64;
  /**
   * A i64 integer
   * 
   * @function
   */
  interface I64 extends Value {
    [0]: bigint;
  }
  /** @ignore */
  const I64: (f0: bigint) => Value.I64;
  /**
   * A u32 integer
   * 
   * @function
   */
  interface U32 extends Value {
    [0]: number;
  }
  /** @ignore */
  const U32: (f0: number) => Value.U32;
  /**
   * A i32 integer
   * 
   * @function
   */
  interface I32 extends Value {
    [0]: number;
  }
  /** @ignore */
  const I32: (f0: number) => Value.I32;
  /**
   * A u16 integer
   * 
   * @function
   */
  interface U16 extends Value {
    [0]: number;
  }
  /** @ignore */
  const U16: (f0: number) => Value.U16;
  /**
   * A i16 integer
   * 
   * @function
   */
  interface I16 extends Value {
    [0]: number;
  }
  /** @ignore */
  const I16: (f0: number) => Value.I16;
  /**
   * A u8 integer
   * 
   * @function
   */
  interface U8 extends Value {
    [0]: number;
  }
  /** @ignore */
  const U8: (f0: number) => Value.U8;
  /**
   * A i8 integer
   * 
   * @function
   */
  interface I8 extends Value {
    [0]: number;
  }
  /** @ignore */
  const I8: (f0: number) => Value.I8;
  /**
   * Bytes
   * 
   * @function
   */
  interface Bytes extends Value {
    [0]: Uint8Array;
  }
  /** @ignore */
  const Bytes: (f0: Uint8Array) => Value.Bytes;
  /**
   * Bytes 20
   * 
   * @function
   */
  interface Bytes20 extends Value {
    [0]: FixedBytes<20>;
  }
  /** @ignore */
  const Bytes20: (f0: FixedBytes<20>) => Value.Bytes20;
  /**
   * Bytes 32
   * 
   * @function
   */
  interface Bytes32 extends Value {
    [0]: FixedBytes<32>;
  }
  /** @ignore */
  const Bytes32: (f0: FixedBytes<32>) => Value.Bytes32;
  /**
   * Bytes 36 : Useful for outpoints
   * 
   * @function
   */
  interface Bytes36 extends Value {
    [0]: FixedBytes<36>;
  }
  /** @ignore */
  const Bytes36: (f0: FixedBytes<36>) => Value.Bytes36;
  /**
   * An enumeration of u8
   * 
   * @function
   */
  interface EnumU8 extends Value {
    [0]: Uint8Array;
  }
  /** @ignore */
  const EnumU8: (f0: Uint8Array) => Value.EnumU8;
  /**
   * An enumeration of strings
   * 
   * @function
   */
  interface EnumString extends Value {
    [0]: string[];
  }
  /** @ignore */
  const EnumString: (f0: string[]) => Value.EnumString;
  /**
   * Identifier
   *  The identifier is very similar to bytes, however it is serialized to Base58 when converted
   *  to a JSON Value
   * 
   * @function
   */
  interface Identifier extends Value {
    [0]: Hash256;
  }
  /** @ignore */
  const Identifier: (f0: Hash256) => Value.Identifier;
  /**
   * A float
   * 
   * @function
   */
  interface Float extends Value {
    [0]: number;
  }
  /** @ignore */
  const Float: (f0: number) => Value.Float;
  /**
   * A string
   * 
   * @function
   */
  interface Text extends Value {
    [0]: string;
  }
  /** @ignore */
  const Text: (f0: string) => Value.Text;
  /**
   * A boolean
   * 
   * @function
   */
  interface Bool extends Value {
    [0]: boolean;
  }
  /** @ignore */
  const Bool: (f0: boolean) => Value.Bool;
  /** Null */
  const Null: () => Value;
  /**
   * An array
   * 
   * @function
   */
  interface Array extends Value {
    [0]: Value[];
  }
  /** @ignore */
  const Array: (f0: Value[]) => Value.Array;
  /**
   * A map
   * 
   * @function
   */
  interface Map extends Value {
    [0]: ValueMap;
  }
  /** @ignore */
  const Map: (f0: ValueMap) => Value.Map;
}

/** "Raw" instant lock for serialization */
interface RawInstantLockProof {
  instant_lock: BinaryData;
  transaction: BinaryData;
  output_index: number;
}
/** @ignore */
const RawInstantLockProof : BinCodeable<RawInstantLockProof> & ((data: {
  instant_lock: BinaryData,
  transaction: BinaryData,
  output_index: number,
}) => RawInstantLockProof);

export type RecipientKeyIndex = number;

/** @ignore */
export abstract class ResourceVote {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: ResourceVote): void;
  /** @ignore */
  static decode(bc: BinCode): ResourceVote;
}
namespace ResourceVote {
  /** @function */
  interface V0 extends ResourceVote {
    [0]: ResourceVoteV0;
  }
  /** @ignore */
  const V0: (f0: ResourceVoteV0) => ResourceVote.V0;
}

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
/** @ignore */
export abstract class ResourceVoteChoice {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: ResourceVoteChoice): void;
  /** @ignore */
  static decode(bc: BinCode): ResourceVoteChoice;
}
namespace ResourceVoteChoice {
  /** @function */
  interface TowardsIdentity extends ResourceVoteChoice {
    [0]: Identifier;
  }
  /** @ignore */
  const TowardsIdentity: (f0: Identifier) => ResourceVoteChoice.TowardsIdentity;
  /** default */
  const Abstain: () => ResourceVoteChoice;
  const Lock: () => ResourceVoteChoice;
}

interface ResourceVoteV0 {
  vote_poll: VotePoll;
  resource_vote_choice: ResourceVoteChoice;
}
/** @ignore */
const ResourceVoteV0 : BinCodeable<ResourceVoteV0> & ((data: {
  vote_poll: VotePoll,
  resource_vote_choice: ResourceVoteChoice,
}) => ResourceVoteV0);

export type Revision = bigint;

/** @ignore */
export abstract class RewardDistributionType {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: RewardDistributionType): void;
  /** @ignore */
  static decode(bc: BinCode): RewardDistributionType;
}
namespace RewardDistributionType {
  /**
   * An amount of tokens is emitted every n blocks.
   *  The start and end are included if set.
   *  If start is not set then it will start at the height of the block when the data contract
   *  is registered.
   * 
   * @function
   */
  interface BlockBasedDistribution extends RewardDistributionType {
    interval: BlockHeightInterval;
    function: DistributionFunction;
  }
  const BlockBasedDistribution: (data: {
    interval: BlockHeightInterval,
    function: DistributionFunction,
  }) => RewardDistributionType.BlockBasedDistribution;
  /**
   * An amount of tokens is emitted every amount of time given.
   *  The start and end are included if set.
   *  If start is not set then it will start at the time of the block when the data contract
   *  is registered.
   * 
   * @function
   */
  interface TimeBasedDistribution extends RewardDistributionType {
    interval: TimestampMillisInterval;
    function: DistributionFunction;
  }
  const TimeBasedDistribution: (data: {
    interval: TimestampMillisInterval,
    function: DistributionFunction,
  }) => RewardDistributionType.TimeBasedDistribution;
  /**
   * An amount of tokens is emitted every amount of epochs.
   *  The start and end are included if set.
   *  If start is not set then it will start at the epoch of the block when the data contract
   *  is registered. A distribution would happen at the start of the following epoch, even if it
   *  is just 1 block later.
   * 
   * @function
   */
  interface EpochBasedDistribution extends RewardDistributionType {
    interval: EpochInterval;
    function: DistributionFunction;
  }
  const EpochBasedDistribution: (data: {
    interval: EpochInterval,
    function: DistributionFunction,
  }) => RewardDistributionType.EpochBasedDistribution;
}

export type RootEncryptionKeyIndex = number;

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
interface ScriptBuf {
  [0]: Uint8Array;
}
/** @ignore */
const ScriptBuf : BinCodeable<ScriptBuf> & ((
    f0: Uint8Array,
) => ScriptBuf);

/** repr u8 */
/** @ignore */
export abstract class SecurityLevel {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: SecurityLevel): void;
  /** @ignore */
  static decode(bc: BinCode): SecurityLevel;
}
namespace SecurityLevel {
  const MASTER: () => SecurityLevel;
  const CRITICAL: () => SecurityLevel;
  /** default */
  const HIGH: () => SecurityLevel;
  const MEDIUM: () => SecurityLevel;
}

export type SenderKeyIndex = number;

export type SharedEncryptedNote = [SenderKeyIndex, RecipientKeyIndex, Uint8Array];

/** @ignore */
export abstract class StateTransition {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: StateTransition): void;
  /** @ignore */
  static decode(bc: BinCode): StateTransition;
}
namespace StateTransition {
  /** @function */
  interface DataContractCreate extends StateTransition {
    [0]: DataContractCreateTransition;
  }
  /** @ignore */
  const DataContractCreate: (f0: DataContractCreateTransition) => StateTransition.DataContractCreate;
  /** @function */
  interface DataContractUpdate extends StateTransition {
    [0]: DataContractUpdateTransition;
  }
  /** @ignore */
  const DataContractUpdate: (f0: DataContractUpdateTransition) => StateTransition.DataContractUpdate;
  /** @function */
  interface Batch extends StateTransition {
    [0]: BatchTransition;
  }
  /** @ignore */
  const Batch: (f0: BatchTransition) => StateTransition.Batch;
  /** @function */
  interface IdentityCreate extends StateTransition {
    [0]: IdentityCreateTransition;
  }
  /** @ignore */
  const IdentityCreate: (f0: IdentityCreateTransition) => StateTransition.IdentityCreate;
  /** @function */
  interface IdentityTopUp extends StateTransition {
    [0]: IdentityTopUpTransition;
  }
  /** @ignore */
  const IdentityTopUp: (f0: IdentityTopUpTransition) => StateTransition.IdentityTopUp;
  /** @function */
  interface IdentityCreditWithdrawal extends StateTransition {
    [0]: IdentityCreditWithdrawalTransition;
  }
  /** @ignore */
  const IdentityCreditWithdrawal: (f0: IdentityCreditWithdrawalTransition) => StateTransition.IdentityCreditWithdrawal;
  /** @function */
  interface IdentityUpdate extends StateTransition {
    [0]: IdentityUpdateTransition;
  }
  /** @ignore */
  const IdentityUpdate: (f0: IdentityUpdateTransition) => StateTransition.IdentityUpdate;
  /** @function */
  interface IdentityCreditTransfer extends StateTransition {
    [0]: IdentityCreditTransferTransition;
  }
  /** @ignore */
  const IdentityCreditTransfer: (f0: IdentityCreditTransferTransition) => StateTransition.IdentityCreditTransfer;
  /** @function */
  interface MasternodeVote extends StateTransition {
    [0]: MasternodeVoteTransition;
  }
  /** @ignore */
  const MasternodeVote: (f0: MasternodeVoteTransition) => StateTransition.MasternodeVote;
}

/**
 * The Storage Key requirements
 * repr u8
 */
/** @ignore */
export abstract class StorageKeyRequirements {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: StorageKeyRequirements): void;
  /** @ignore */
  static decode(bc: BinCode): StorageKeyRequirements;
}
namespace StorageKeyRequirements {
  const Unique: () => StorageKeyRequirements;
  const Multiple: () => StorageKeyRequirements;
  const MultipleReferenceToLatest: () => StorageKeyRequirements;
}

export type TimestampMillis = bigint;

export type TimestampMillisInterval = bigint;

export type TokenAmount = bigint;

/** @ignore */
export abstract class TokenBaseTransition {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: TokenBaseTransition): void;
  /** @ignore */
  static decode(bc: BinCode): TokenBaseTransition;
}
namespace TokenBaseTransition {
  /** @function */
  interface V0 extends TokenBaseTransition {
    [0]: TokenBaseTransitionV0;
  }
  /** @ignore */
  const V0: (f0: TokenBaseTransitionV0) => TokenBaseTransition.V0;
}

interface TokenBaseTransitionV0 {
  identity_contract_nonce: IdentityNonce;
  /** ID of the token within the contract */
  token_contract_position: number;
  /** Data contract ID generated from the data contract's `owner_id` and `entropy` */
  data_contract_id: Identifier;
  /** Token ID generated from the data contract ID and the token position */
  token_id: Identifier;
  /** Using group multi party rules for authentication */
  using_group_info?: GroupStateTransitionInfo;
}
/** @ignore */
const TokenBaseTransitionV0 : BinCodeable<TokenBaseTransitionV0> & ((data: {
  identity_contract_nonce: IdentityNonce,
  /** ID of the token within the contract */
  token_contract_position: number,
  /** Data contract ID generated from the data contract's `owner_id` and `entropy` */
  data_contract_id: Identifier,
  /** Token ID generated from the data contract ID and the token position */
  token_id: Identifier,
  /** Using group multi party rules for authentication */
  using_group_info?: GroupStateTransitionInfo,
}) => TokenBaseTransitionV0);

/** @ignore */
export abstract class TokenBurnTransition {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: TokenBurnTransition): void;
  /** @ignore */
  static decode(bc: BinCode): TokenBurnTransition;
}
namespace TokenBurnTransition {
  /** @function */
  interface V0 extends TokenBurnTransition {
    [0]: TokenBurnTransitionV0;
  }
  /** @ignore */
  const V0: (f0: TokenBurnTransitionV0) => TokenBurnTransition.V0;
}

interface TokenBurnTransitionV0 {
  /** Document Base Transition */
  base: TokenBaseTransition;
  /** How much should we burn */
  burn_amount: bigint;
  /** The public note */
  public_note?: string;
}
/** @ignore */
const TokenBurnTransitionV0 : BinCodeable<TokenBurnTransitionV0> & ((data: {
  /** Document Base Transition */
  base: TokenBaseTransition,
  /** How much should we burn */
  burn_amount: bigint,
  /** The public note */
  public_note?: string,
}) => TokenBurnTransitionV0);

/** @ignore */
export abstract class TokenClaimTransition {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: TokenClaimTransition): void;
  /** @ignore */
  static decode(bc: BinCode): TokenClaimTransition;
}
namespace TokenClaimTransition {
  /** @function */
  interface V0 extends TokenClaimTransition {
    [0]: TokenClaimTransitionV0;
  }
  /** @ignore */
  const V0: (f0: TokenClaimTransitionV0) => TokenClaimTransition.V0;
}

interface TokenClaimTransitionV0 {
  /** Document Base Transition */
  base: TokenBaseTransition;
  /** The type of distribution we are targeting */
  distribution_type: TokenDistributionType;
  /** A public note, this will only get saved to the state if we are using a historical contract */
  public_note?: string;
}
/** @ignore */
const TokenClaimTransitionV0 : BinCodeable<TokenClaimTransitionV0> & ((data: {
  /** Document Base Transition */
  base: TokenBaseTransition,
  /** The type of distribution we are targeting */
  distribution_type: TokenDistributionType,
  /** A public note, this will only get saved to the state if we are using a historical contract */
  public_note?: string,
}) => TokenClaimTransitionV0);

/** @ignore */
export abstract class TokenConfigUpdateTransition {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: TokenConfigUpdateTransition): void;
  /** @ignore */
  static decode(bc: BinCode): TokenConfigUpdateTransition;
}
namespace TokenConfigUpdateTransition {
  /** @function */
  interface V0 extends TokenConfigUpdateTransition {
    [0]: TokenConfigUpdateTransitionV0;
  }
  /** @ignore */
  const V0: (f0: TokenConfigUpdateTransitionV0) => TokenConfigUpdateTransition.V0;
}

interface TokenConfigUpdateTransitionV0 {
  /** Document Base Transition */
  base: TokenBaseTransition;
  /** Updated token configuration item */
  update_token_configuration_item: TokenConfigurationChangeItem;
  /** The public note */
  public_note?: string;
}
/** @ignore */
const TokenConfigUpdateTransitionV0 : BinCodeable<TokenConfigUpdateTransitionV0> & ((data: {
  /** Document Base Transition */
  base: TokenBaseTransition,
  /** Updated token configuration item */
  update_token_configuration_item: TokenConfigurationChangeItem,
  /** The public note */
  public_note?: string,
}) => TokenConfigUpdateTransitionV0);

/** @ignore */
export abstract class TokenConfiguration {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: TokenConfiguration): void;
  /** @ignore */
  static decode(bc: BinCode): TokenConfiguration;
}
namespace TokenConfiguration {
  /** @function */
  interface V0 extends TokenConfiguration {
    [0]: TokenConfigurationV0;
  }
  /** @ignore */
  const V0: (f0: TokenConfigurationV0) => TokenConfiguration.V0;
}

/** @ignore */
export abstract class TokenConfigurationChangeItem {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: TokenConfigurationChangeItem): void;
  /** @ignore */
  static decode(bc: BinCode): TokenConfigurationChangeItem;
}
namespace TokenConfigurationChangeItem {
  /** default */
  const TokenConfigurationNoChange: () => TokenConfigurationChangeItem;
  /** @function */
  interface Conventions extends TokenConfigurationChangeItem {
    [0]: TokenConfigurationConvention;
  }
  /** @ignore */
  const Conventions: (f0: TokenConfigurationConvention) => TokenConfigurationChangeItem.Conventions;
  /** @function */
  interface ConventionsControlGroup extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  /** @ignore */
  const ConventionsControlGroup: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.ConventionsControlGroup;
  /** @function */
  interface ConventionsAdminGroup extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  /** @ignore */
  const ConventionsAdminGroup: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.ConventionsAdminGroup;
  /** @function */
  interface MaxSupply extends TokenConfigurationChangeItem {
    [0]: Option<TokenAmount>;
  }
  /** @ignore */
  const MaxSupply: (f0: Option<TokenAmount>) => TokenConfigurationChangeItem.MaxSupply;
  /** @function */
  interface MaxSupplyControlGroup extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  /** @ignore */
  const MaxSupplyControlGroup: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.MaxSupplyControlGroup;
  /** @function */
  interface MaxSupplyAdminGroup extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  /** @ignore */
  const MaxSupplyAdminGroup: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.MaxSupplyAdminGroup;
  /** @function */
  interface PerpetualDistribution extends TokenConfigurationChangeItem {
    [0]: Option<TokenPerpetualDistribution>;
  }
  /** @ignore */
  const PerpetualDistribution: (f0: Option<TokenPerpetualDistribution>) => TokenConfigurationChangeItem.PerpetualDistribution;
  /** @function */
  interface PerpetualDistributionControlGroup extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  /** @ignore */
  const PerpetualDistributionControlGroup: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.PerpetualDistributionControlGroup;
  /** @function */
  interface PerpetualDistributionAdminGroup extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  /** @ignore */
  const PerpetualDistributionAdminGroup: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.PerpetualDistributionAdminGroup;
  /** @function */
  interface NewTokensDestinationIdentity extends TokenConfigurationChangeItem {
    [0]: Option<Identifier>;
  }
  /** @ignore */
  const NewTokensDestinationIdentity: (f0: Option<Identifier>) => TokenConfigurationChangeItem.NewTokensDestinationIdentity;
  /** @function */
  interface NewTokensDestinationIdentityControlGroup extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  /** @ignore */
  const NewTokensDestinationIdentityControlGroup: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.NewTokensDestinationIdentityControlGroup;
  /** @function */
  interface NewTokensDestinationIdentityAdminGroup extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  /** @ignore */
  const NewTokensDestinationIdentityAdminGroup: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.NewTokensDestinationIdentityAdminGroup;
  /** @function */
  interface MintingAllowChoosingDestination extends TokenConfigurationChangeItem {
    [0]: boolean;
  }
  /** @ignore */
  const MintingAllowChoosingDestination: (f0: boolean) => TokenConfigurationChangeItem.MintingAllowChoosingDestination;
  /** @function */
  interface MintingAllowChoosingDestinationControlGroup extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  /** @ignore */
  const MintingAllowChoosingDestinationControlGroup: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.MintingAllowChoosingDestinationControlGroup;
  /** @function */
  interface MintingAllowChoosingDestinationAdminGroup extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  /** @ignore */
  const MintingAllowChoosingDestinationAdminGroup: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.MintingAllowChoosingDestinationAdminGroup;
  /** @function */
  interface ManualMinting extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  /** @ignore */
  const ManualMinting: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.ManualMinting;
  /** @function */
  interface ManualMintingAdminGroup extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  /** @ignore */
  const ManualMintingAdminGroup: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.ManualMintingAdminGroup;
  /** @function */
  interface ManualBurning extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  /** @ignore */
  const ManualBurning: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.ManualBurning;
  /** @function */
  interface ManualBurningAdminGroup extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  /** @ignore */
  const ManualBurningAdminGroup: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.ManualBurningAdminGroup;
  /** @function */
  interface Freeze extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  /** @ignore */
  const Freeze: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.Freeze;
  /** @function */
  interface FreezeAdminGroup extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  /** @ignore */
  const FreezeAdminGroup: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.FreezeAdminGroup;
  /** @function */
  interface Unfreeze extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  /** @ignore */
  const Unfreeze: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.Unfreeze;
  /** @function */
  interface UnfreezeAdminGroup extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  /** @ignore */
  const UnfreezeAdminGroup: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.UnfreezeAdminGroup;
  /** @function */
  interface DestroyFrozenFunds extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  /** @ignore */
  const DestroyFrozenFunds: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.DestroyFrozenFunds;
  /** @function */
  interface DestroyFrozenFundsAdminGroup extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  /** @ignore */
  const DestroyFrozenFundsAdminGroup: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.DestroyFrozenFundsAdminGroup;
  /** @function */
  interface EmergencyAction extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  /** @ignore */
  const EmergencyAction: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.EmergencyAction;
  /** @function */
  interface EmergencyActionAdminGroup extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  /** @ignore */
  const EmergencyActionAdminGroup: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.EmergencyActionAdminGroup;
  /** @function */
  interface MainControlGroup extends TokenConfigurationChangeItem {
    [0]: Option<GroupContractPosition>;
  }
  /** @ignore */
  const MainControlGroup: (f0: Option<GroupContractPosition>) => TokenConfigurationChangeItem.MainControlGroup;
}

/** @ignore */
export abstract class TokenConfigurationConvention {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: TokenConfigurationConvention): void;
  /** @ignore */
  static decode(bc: BinCode): TokenConfigurationConvention;
}
namespace TokenConfigurationConvention {
  /** @function */
  interface V0 extends TokenConfigurationConvention {
    [0]: TokenConfigurationConventionV0;
  }
  /** @ignore */
  const V0: (f0: TokenConfigurationConventionV0) => TokenConfigurationConvention.V0;
}

interface TokenConfigurationConventionV0 {
  /**
   * Localizations for the token name.
   *  The key must be a ISO 639 2-chars language code
   */
  localizations: Map<string, TokenConfigurationLocalization>;
  decimals: number;
}
/** @ignore */
const TokenConfigurationConventionV0 : BinCodeable<TokenConfigurationConventionV0> & ((data: {
  /**
   * Localizations for the token name.
   *  The key must be a ISO 639 2-chars language code
   */
  localizations: Map<string, TokenConfigurationLocalization>,
  decimals: number,
}) => TokenConfigurationConventionV0);

/** @ignore */
export abstract class TokenConfigurationLocalization {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: TokenConfigurationLocalization): void;
  /** @ignore */
  static decode(bc: BinCode): TokenConfigurationLocalization;
}
namespace TokenConfigurationLocalization {
  /** @function */
  interface V0 extends TokenConfigurationLocalization {
    [0]: TokenConfigurationLocalizationV0;
  }
  /** @ignore */
  const V0: (f0: TokenConfigurationLocalizationV0) => TokenConfigurationLocalization.V0;
}

interface TokenConfigurationLocalizationV0 {
  should_capitalize: boolean;
  singular_form: string;
  plural_form: string;
}
/** @ignore */
const TokenConfigurationLocalizationV0 : BinCodeable<TokenConfigurationLocalizationV0> & ((data: {
  should_capitalize: boolean,
  singular_form: string,
  plural_form: string,
}) => TokenConfigurationLocalizationV0);

interface TokenConfigurationV0 {
  conventions: TokenConfigurationConvention;
  /** Who can change the conventions */
  conventions_change_rules: ChangeControlRules;
  /** The supply at the creation of the token */
  base_supply: TokenAmount;
  /** The maximum supply the token can ever have */
  max_supply?: TokenAmount;
  /** The rules for keeping history. */
  keeps_history: TokenKeepsHistoryRules;
  /** Do we start off as paused, meaning that we can not transfer till we unpause. */
  start_as_paused: boolean;
  /**
   * Who can change the max supply
   *  Even if set no one can ever change this under the base supply
   */
  max_supply_change_rules: ChangeControlRules;
  /** The distribution rules for the token */
  distribution_rules: TokenDistributionRules;
  manual_minting_rules: ChangeControlRules;
  manual_burning_rules: ChangeControlRules;
  freeze_rules: ChangeControlRules;
  unfreeze_rules: ChangeControlRules;
  destroy_frozen_funds_rules: ChangeControlRules;
  emergency_action_rules: ChangeControlRules;
  main_control_group?: GroupContractPosition;
  main_control_group_can_be_modified: AuthorizedActionTakers;
}
/** @ignore */
const TokenConfigurationV0 : BinCodeable<TokenConfigurationV0> & ((data: {
  conventions: TokenConfigurationConvention,
  /** Who can change the conventions */
  conventions_change_rules: ChangeControlRules,
  /** The supply at the creation of the token */
  base_supply: TokenAmount,
  /** The maximum supply the token can ever have */
  max_supply?: TokenAmount,
  /** The rules for keeping history. */
  keeps_history: TokenKeepsHistoryRules,
  /** Do we start off as paused, meaning that we can not transfer till we unpause. */
  start_as_paused: boolean,
  /**
   * Who can change the max supply
   *  Even if set no one can ever change this under the base supply
   */
  max_supply_change_rules: ChangeControlRules,
  /** The distribution rules for the token */
  distribution_rules: TokenDistributionRules,
  manual_minting_rules: ChangeControlRules,
  manual_burning_rules: ChangeControlRules,
  freeze_rules: ChangeControlRules,
  unfreeze_rules: ChangeControlRules,
  destroy_frozen_funds_rules: ChangeControlRules,
  emergency_action_rules: ChangeControlRules,
  main_control_group?: GroupContractPosition,
  main_control_group_can_be_modified: AuthorizedActionTakers,
}) => TokenConfigurationV0);

export type TokenContractPosition = number;

/** @ignore */
export abstract class TokenDestroyFrozenFundsTransition {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: TokenDestroyFrozenFundsTransition): void;
  /** @ignore */
  static decode(bc: BinCode): TokenDestroyFrozenFundsTransition;
}
namespace TokenDestroyFrozenFundsTransition {
  /** @function */
  interface V0 extends TokenDestroyFrozenFundsTransition {
    [0]: TokenDestroyFrozenFundsTransitionV0;
  }
  /** @ignore */
  const V0: (f0: TokenDestroyFrozenFundsTransitionV0) => TokenDestroyFrozenFundsTransition.V0;
}

interface TokenDestroyFrozenFundsTransitionV0 {
  /** Document Base Transition */
  base: TokenBaseTransition;
  /** The identity id of the account whose balance should be destroyed */
  frozen_identity_id: Identifier;
  /** The public note */
  public_note?: string;
}
/** @ignore */
const TokenDestroyFrozenFundsTransitionV0 : BinCodeable<TokenDestroyFrozenFundsTransitionV0> & ((data: {
  /** Document Base Transition */
  base: TokenBaseTransition,
  /** The identity id of the account whose balance should be destroyed */
  frozen_identity_id: Identifier,
  /** The public note */
  public_note?: string,
}) => TokenDestroyFrozenFundsTransitionV0);

/** @ignore */
export abstract class TokenDistributionRecipient {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: TokenDistributionRecipient): void;
  /** @ignore */
  static decode(bc: BinCode): TokenDistributionRecipient;
}
namespace TokenDistributionRecipient {
  /**
   * Distribute to the contract Owner
   * default
   */
  const ContractOwner: () => TokenDistributionRecipient;
  /**
   * Distribute to a single identity
   * 
   * @function
   */
  interface Identity extends TokenDistributionRecipient {
    [0]: Identifier;
  }
  /** @ignore */
  const Identity: (f0: Identifier) => TokenDistributionRecipient.Identity;
  /**
   * Distribute tokens by participation
   *  This distribution can only happen when choosing epoch based distribution
   */
  const EvonodesByParticipation: () => TokenDistributionRecipient;
}

/** @ignore */
export abstract class TokenDistributionRules {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: TokenDistributionRules): void;
  /** @ignore */
  static decode(bc: BinCode): TokenDistributionRules;
}
namespace TokenDistributionRules {
  /** @function */
  interface V0 extends TokenDistributionRules {
    [0]: TokenDistributionRulesV0;
  }
  /** @ignore */
  const V0: (f0: TokenDistributionRulesV0) => TokenDistributionRules.V0;
}

interface TokenDistributionRulesV0 {
  perpetual_distribution?: TokenPerpetualDistribution;
  perpetual_distribution_rules: ChangeControlRules;
  pre_programmed_distribution?: TokenPreProgrammedDistribution;
  new_tokens_destination_identity?: Identifier;
  new_tokens_destination_identity_rules: ChangeControlRules;
  minting_allow_choosing_destination: boolean;
  minting_allow_choosing_destination_rules: ChangeControlRules;
}
/** @ignore */
const TokenDistributionRulesV0 : BinCodeable<TokenDistributionRulesV0> & ((data: {
  perpetual_distribution?: TokenPerpetualDistribution,
  perpetual_distribution_rules: ChangeControlRules,
  pre_programmed_distribution?: TokenPreProgrammedDistribution,
  new_tokens_destination_identity?: Identifier,
  new_tokens_destination_identity_rules: ChangeControlRules,
  minting_allow_choosing_destination: boolean,
  minting_allow_choosing_destination_rules: ChangeControlRules,
}) => TokenDistributionRulesV0);

/**
 * Represents the type of token distribution.
 * 
 *  - `PreProgrammed`: A scheduled distribution with predefined rules.
 *  - `Perpetual`: A continuous or recurring distribution.
 */
/** @ignore */
export abstract class TokenDistributionType {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: TokenDistributionType): void;
  /** @ignore */
  static decode(bc: BinCode): TokenDistributionType;
}
namespace TokenDistributionType {
  /**
   * A pre-programmed distribution scheduled for a specific time.
   * default
   */
  const PreProgrammed: () => TokenDistributionType;
  /** A perpetual distribution that occurs at regular intervals. */
  const Perpetual: () => TokenDistributionType;
}

/** @ignore */
export abstract class TokenEmergencyAction {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: TokenEmergencyAction): void;
  /** @ignore */
  static decode(bc: BinCode): TokenEmergencyAction;
}
namespace TokenEmergencyAction {
  /** default */
  const Pause: () => TokenEmergencyAction;
  const Resume: () => TokenEmergencyAction;
}

/** @ignore */
export abstract class TokenEmergencyActionTransition {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: TokenEmergencyActionTransition): void;
  /** @ignore */
  static decode(bc: BinCode): TokenEmergencyActionTransition;
}
namespace TokenEmergencyActionTransition {
  /** @function */
  interface V0 extends TokenEmergencyActionTransition {
    [0]: TokenEmergencyActionTransitionV0;
  }
  /** @ignore */
  const V0: (f0: TokenEmergencyActionTransitionV0) => TokenEmergencyActionTransition.V0;
}

interface TokenEmergencyActionTransitionV0 {
  /** Document Base Transition */
  base: TokenBaseTransition;
  /** The emergency action */
  emergency_action: TokenEmergencyAction;
  /** The public note */
  public_note?: string;
}
/** @ignore */
const TokenEmergencyActionTransitionV0 : BinCodeable<TokenEmergencyActionTransitionV0> & ((data: {
  /** Document Base Transition */
  base: TokenBaseTransition,
  /** The emergency action */
  emergency_action: TokenEmergencyAction,
  /** The public note */
  public_note?: string,
}) => TokenEmergencyActionTransitionV0);

/** @ignore */
export abstract class TokenFreezeTransition {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: TokenFreezeTransition): void;
  /** @ignore */
  static decode(bc: BinCode): TokenFreezeTransition;
}
namespace TokenFreezeTransition {
  /** @function */
  interface V0 extends TokenFreezeTransition {
    [0]: TokenFreezeTransitionV0;
  }
  /** @ignore */
  const V0: (f0: TokenFreezeTransitionV0) => TokenFreezeTransition.V0;
}

interface TokenFreezeTransitionV0 {
  /** Document Base Transition */
  base: TokenBaseTransition;
  /** The identity that we are freezing */
  identity_to_freeze_id: Identifier;
  /** The public note */
  public_note?: string;
}
/** @ignore */
const TokenFreezeTransitionV0 : BinCodeable<TokenFreezeTransitionV0> & ((data: {
  /** Document Base Transition */
  base: TokenBaseTransition,
  /** The identity that we are freezing */
  identity_to_freeze_id: Identifier,
  /** The public note */
  public_note?: string,
}) => TokenFreezeTransitionV0);

/** @ignore */
export abstract class TokenKeepsHistoryRules {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: TokenKeepsHistoryRules): void;
  /** @ignore */
  static decode(bc: BinCode): TokenKeepsHistoryRules;
}
namespace TokenKeepsHistoryRules {
  /** @function */
  interface V0 extends TokenKeepsHistoryRules {
    [0]: TokenKeepsHistoryRulesV0;
  }
  /** @ignore */
  const V0: (f0: TokenKeepsHistoryRulesV0) => TokenKeepsHistoryRules.V0;
}

/**
 * The rules for keeping a ledger as documents of token events.
 *  Config update, Destroying Frozen Funds, Emergency Action,
 *  Pre Programmed Token Release always require an entry to the ledger
 */
interface TokenKeepsHistoryRulesV0 {
  /** Whether transfer history is recorded. */
  keeps_transfer_history: boolean;
  /** Whether freezing history is recorded. */
  keeps_freezing_history: boolean;
  /** Whether minting history is recorded. */
  keeps_minting_history: boolean;
  /** Whether burning history is recorded. */
  keeps_burning_history: boolean;
}
/** @ignore */
const TokenKeepsHistoryRulesV0 : BinCodeable<TokenKeepsHistoryRulesV0> & ((data: {
  /** Whether transfer history is recorded. */
  keeps_transfer_history: boolean,
  /** Whether freezing history is recorded. */
  keeps_freezing_history: boolean,
  /** Whether minting history is recorded. */
  keeps_minting_history: boolean,
  /** Whether burning history is recorded. */
  keeps_burning_history: boolean,
}) => TokenKeepsHistoryRulesV0);

/** @ignore */
export abstract class TokenMintTransition {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: TokenMintTransition): void;
  /** @ignore */
  static decode(bc: BinCode): TokenMintTransition;
}
namespace TokenMintTransition {
  /** @function */
  interface V0 extends TokenMintTransition {
    [0]: TokenMintTransitionV0;
  }
  /** @ignore */
  const V0: (f0: TokenMintTransitionV0) => TokenMintTransition.V0;
}

interface TokenMintTransitionV0 {
  /** Document Base Transition */
  base: TokenBaseTransition;
  /**
   * Who should we issue the token to? If this is not set then we issue to the identity set in
   *  contract settings. If such an operation is allowed.
   */
  issued_to_identity_id?: Identifier;
  /** How much should we issue */
  amount: bigint;
  /** The public note */
  public_note?: string;
}
/** @ignore */
const TokenMintTransitionV0 : BinCodeable<TokenMintTransitionV0> & ((data: {
  /** Document Base Transition */
  base: TokenBaseTransition,
  /**
   * Who should we issue the token to? If this is not set then we issue to the identity set in
   *  contract settings. If such an operation is allowed.
   */
  issued_to_identity_id?: Identifier,
  /** How much should we issue */
  amount: bigint,
  /** The public note */
  public_note?: string,
}) => TokenMintTransitionV0);

/** @ignore */
export abstract class TokenPerpetualDistribution {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: TokenPerpetualDistribution): void;
  /** @ignore */
  static decode(bc: BinCode): TokenPerpetualDistribution;
}
namespace TokenPerpetualDistribution {
  /** @function */
  interface V0 extends TokenPerpetualDistribution {
    [0]: TokenPerpetualDistributionV0;
  }
  /** @ignore */
  const V0: (f0: TokenPerpetualDistributionV0) => TokenPerpetualDistribution.V0;
}

interface TokenPerpetualDistributionV0 {
  /** The distribution type that the token will use */
  distribution_type: RewardDistributionType;
  /** The recipient type */
  distribution_recipient: TokenDistributionRecipient;
}
/** @ignore */
const TokenPerpetualDistributionV0 : BinCodeable<TokenPerpetualDistributionV0> & ((data: {
  /** The distribution type that the token will use */
  distribution_type: RewardDistributionType,
  /** The recipient type */
  distribution_recipient: TokenDistributionRecipient,
}) => TokenPerpetualDistributionV0);

/** @ignore */
export abstract class TokenPreProgrammedDistribution {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: TokenPreProgrammedDistribution): void;
  /** @ignore */
  static decode(bc: BinCode): TokenPreProgrammedDistribution;
}
namespace TokenPreProgrammedDistribution {
  /** @function */
  interface V0 extends TokenPreProgrammedDistribution {
    [0]: TokenPreProgrammedDistributionV0;
  }
  /** @ignore */
  const V0: (f0: TokenPreProgrammedDistributionV0) => TokenPreProgrammedDistribution.V0;
}

interface TokenPreProgrammedDistributionV0 {
  distributions: Map<TimestampMillis, Map<Identifier, TokenAmount>>;
}
/** @ignore */
const TokenPreProgrammedDistributionV0 : BinCodeable<TokenPreProgrammedDistributionV0> & ((data: {
  distributions: Map<TimestampMillis, Map<Identifier, TokenAmount>>,
}) => TokenPreProgrammedDistributionV0);

/** @ignore */
export abstract class TokenTransferTransition {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: TokenTransferTransition): void;
  /** @ignore */
  static decode(bc: BinCode): TokenTransferTransition;
}
namespace TokenTransferTransition {
  /** @function */
  interface V0 extends TokenTransferTransition {
    [0]: TokenTransferTransitionV0;
  }
  /** @ignore */
  const V0: (f0: TokenTransferTransitionV0) => TokenTransferTransition.V0;
}

interface TokenTransferTransitionV0 {
  base: TokenBaseTransition;
  amount: bigint;
  recipient_id: Identifier;
  /** The public note */
  public_note?: string;
  /** An optional shared encrypted note */
  shared_encrypted_note?: SharedEncryptedNote;
  /** An optional private encrypted note */
  private_encrypted_note?: PrivateEncryptedNote;
}
/** @ignore */
const TokenTransferTransitionV0 : BinCodeable<TokenTransferTransitionV0> & ((data: {
  base: TokenBaseTransition,
  amount: bigint,
  recipient_id: Identifier,
  /** The public note */
  public_note?: string,
  /** An optional shared encrypted note */
  shared_encrypted_note?: SharedEncryptedNote,
  /** An optional private encrypted note */
  private_encrypted_note?: PrivateEncryptedNote,
}) => TokenTransferTransitionV0);

/** @ignore */
export abstract class TokenTransition {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: TokenTransition): void;
  /** @ignore */
  static decode(bc: BinCode): TokenTransition;
}
namespace TokenTransition {
  /** @function */
  interface Burn extends TokenTransition {
    [0]: TokenBurnTransition;
  }
  /** @ignore */
  const Burn: (f0: TokenBurnTransition) => TokenTransition.Burn;
  /** @function */
  interface Mint extends TokenTransition {
    [0]: TokenMintTransition;
  }
  /** @ignore */
  const Mint: (f0: TokenMintTransition) => TokenTransition.Mint;
  /** @function */
  interface Transfer extends TokenTransition {
    [0]: TokenTransferTransition;
  }
  /** @ignore */
  const Transfer: (f0: TokenTransferTransition) => TokenTransition.Transfer;
  /** @function */
  interface Freeze extends TokenTransition {
    [0]: TokenFreezeTransition;
  }
  /** @ignore */
  const Freeze: (f0: TokenFreezeTransition) => TokenTransition.Freeze;
  /** @function */
  interface Unfreeze extends TokenTransition {
    [0]: TokenUnfreezeTransition;
  }
  /** @ignore */
  const Unfreeze: (f0: TokenUnfreezeTransition) => TokenTransition.Unfreeze;
  /** @function */
  interface DestroyFrozenFunds extends TokenTransition {
    [0]: TokenDestroyFrozenFundsTransition;
  }
  /** @ignore */
  const DestroyFrozenFunds: (f0: TokenDestroyFrozenFundsTransition) => TokenTransition.DestroyFrozenFunds;
  /** @function */
  interface Claim extends TokenTransition {
    [0]: TokenClaimTransition;
  }
  /** @ignore */
  const Claim: (f0: TokenClaimTransition) => TokenTransition.Claim;
  /** @function */
  interface EmergencyAction extends TokenTransition {
    [0]: TokenEmergencyActionTransition;
  }
  /** @ignore */
  const EmergencyAction: (f0: TokenEmergencyActionTransition) => TokenTransition.EmergencyAction;
  /** @function */
  interface ConfigUpdate extends TokenTransition {
    [0]: TokenConfigUpdateTransition;
  }
  /** @ignore */
  const ConfigUpdate: (f0: TokenConfigUpdateTransition) => TokenTransition.ConfigUpdate;
}

/** @ignore */
export abstract class TokenUnfreezeTransition {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: TokenUnfreezeTransition): void;
  /** @ignore */
  static decode(bc: BinCode): TokenUnfreezeTransition;
}
namespace TokenUnfreezeTransition {
  /** @function */
  interface V0 extends TokenUnfreezeTransition {
    [0]: TokenUnfreezeTransitionV0;
  }
  /** @ignore */
  const V0: (f0: TokenUnfreezeTransitionV0) => TokenUnfreezeTransition.V0;
}

interface TokenUnfreezeTransitionV0 {
  /** Document Base Transition */
  base: TokenBaseTransition;
  /** The identity that we are freezing */
  frozen_identity_id: Identifier;
  /** The public note */
  public_note?: string;
}
/** @ignore */
const TokenUnfreezeTransitionV0 : BinCodeable<TokenUnfreezeTransitionV0> & ((data: {
  /** Document Base Transition */
  base: TokenBaseTransition,
  /** The identity that we are freezing */
  frozen_identity_id: Identifier,
  /** The public note */
  public_note?: string,
}) => TokenUnfreezeTransitionV0);

/** A transaction output, which defines new coins to be created from old ones. */
interface TxOut {
  /** The value of the output, in satoshis. */
  value: bigint;
  /** The script which must be satisfied for the output to be spent. */
  script_pubkey: ScriptBuf;
}
/** @ignore */
const TxOut : BinCodeable<TxOut> & ((data: {
  /** The value of the output, in satoshis. */
  value: bigint,
  /** The script which must be satisfied for the output to be spent. */
  script_pubkey: ScriptBuf,
}) => TxOut);

/** A dash transaction hash/transaction ID. */
interface Txid {
  [0]: Hash;
}
/** @ignore */
const Txid : BinCodeable<Txid> & ((
    f0: Hash,
) => Txid);

export type UserFeeIncrease = number;

export type ValueMap = [Value, Value][];

/** @ignore */
export abstract class Vote {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: Vote): void;
  /** @ignore */
  static decode(bc: BinCode): Vote;
}
namespace Vote {
  /** @function */
  interface ResourceVote extends Vote {
    [0]: ResourceVote;
  }
  /** @ignore */
  const ResourceVote: (f0: ResourceVote) => Vote.ResourceVote;
}

/** @ignore */
export abstract class VotePoll {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: VotePoll): void;
  /** @ignore */
  static decode(bc: BinCode): VotePoll;
}
namespace VotePoll {
  /** @function */
  interface ContestedDocumentResourceVotePoll extends VotePoll {
    [0]: ContestedDocumentResourceVotePoll;
  }
  /** @ignore */
  const ContestedDocumentResourceVotePoll: (f0: ContestedDocumentResourceVotePoll) => VotePoll.ContestedDocumentResourceVotePoll;
}


}
