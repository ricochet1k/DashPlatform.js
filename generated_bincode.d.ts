import { BinCode, BinCodeable } from "./bincode.ts";
import { Option, FixedBytes, Hash, SocketAddr, Transaction } from "./bincode_types.ts";
declare module "./generated_bincode.js" {

/**
 * An Asset Lock payload. This is contained as the payload of an asset lock special transaction.
 * The Asset Lock Special transaction and this payload is described in the Asset Lock DIP2X
 * (todo:update this).
 * An Asset Lock can fund multiple Identity registrations or top ups.
 * The Asset Lock payload credit outputs field contains a vector of TxOuts.
 * Each TxOut refers to a funding of an Identity.
 *
 */
const AssetLockPayload : BinCodeable<AssetLockPayload> & ((data: {
  version: number,
  credit_outputs: TxOut[],
}) => AssetLockPayload);
interface AssetLockPayload {
  version: number;
  credit_outputs: TxOut[];
}

export abstract class AssetLockProof {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: AssetLockProof): void;
  static decode(bc: BinCode): AssetLockProof;
}
namespace AssetLockProof {
  const Instant: (f0: InstantAssetLockProof) => AssetLockProof.Instant;
  interface Instant extends AssetLockProof {
    [0]: InstantAssetLockProof;
  }
  const Chain: (f0: ChainAssetLockProof) => AssetLockProof.Chain;
  interface Chain extends AssetLockProof {
    [0]: ChainAssetLockProof;
  }
}

export abstract class AuthorizedActionTakers {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: AuthorizedActionTakers): void;
  static decode(bc: BinCode): AuthorizedActionTakers;
}
namespace AuthorizedActionTakers {
  // default
  const Identity: (f0: Identifier) => AuthorizedActionTakers.Identity;
  interface Identity extends AuthorizedActionTakers {
    [0]: Identifier;
  }
  const Group: (f0: GroupContractPosition) => AuthorizedActionTakers.Group;
  interface Group extends AuthorizedActionTakers {
    [0]: GroupContractPosition;
  }
}

// platform_version_path_bounds "dpp.state_transition_serialization_versions.batch_state_transition"
export abstract class BatchTransition {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: BatchTransition): void;
  static decode(bc: BinCode): BatchTransition;
}
namespace BatchTransition {
  const V0: (f0: BatchTransitionV0) => BatchTransition.V0;
  interface V0 extends BatchTransition {
    [0]: BatchTransitionV0;
  }
  const V1: (f0: BatchTransitionV1) => BatchTransition.V1;
  interface V1 extends BatchTransition {
    [0]: BatchTransitionV1;
  }
}

const BatchTransitionV0 : BinCodeable<BatchTransitionV0> & ((data: {
  owner_id: Identifier,
  transitions: DocumentTransition[],
  user_fee_increase: UserFeeIncrease,
    // platform_signable exclude_from_sig_hash
  signature_public_key_id: KeyID,
    // platform_signable exclude_from_sig_hash
  signature: BinaryData,
}) => BatchTransitionV0);
interface BatchTransitionV0 {
  owner_id: Identifier;
  transitions: DocumentTransition[];
  user_fee_increase: UserFeeIncrease;
  // platform_signable exclude_from_sig_hash
  signature_public_key_id: KeyID;
  // platform_signable exclude_from_sig_hash
  signature: BinaryData;
}

const BatchTransitionV1 : BinCodeable<BatchTransitionV1> & ((data: {
  owner_id: Identifier,
  transitions: BatchedTransition[],
  user_fee_increase: UserFeeIncrease,
    // platform_signable exclude_from_sig_hash
  signature_public_key_id: KeyID,
    // platform_signable exclude_from_sig_hash
  signature: BinaryData,
}) => BatchTransitionV1);
interface BatchTransitionV1 {
  owner_id: Identifier;
  transitions: BatchedTransition[];
  user_fee_increase: UserFeeIncrease;
  // platform_signable exclude_from_sig_hash
  signature_public_key_id: KeyID;
  // platform_signable exclude_from_sig_hash
  signature: BinaryData;
}

export abstract class BatchedTransition {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: BatchedTransition): void;
  static decode(bc: BinCode): BatchedTransition;
}
namespace BatchedTransition {
  const Document: (f0: DocumentTransition) => BatchedTransition.Document;
  interface Document extends BatchedTransition {
    [0]: DocumentTransition;
  }
  const Token: (f0: TokenTransition) => BatchedTransition.Token;
  interface Token extends BatchedTransition {
    [0]: TokenTransition;
  }
}

const BinaryData : BinCodeable<BinaryData> & ((
    f0: Uint8Array,
) => BinaryData);
interface BinaryData {
  [0]: Uint8Array;
}

export type BlockHeight = number;

export type BlockHeightInterval = number;

/**
 * Instant Asset Lock Proof is a part of Identity Create and Identity Topup
 * transitions. It is a proof that specific output of dash is locked in credits
 * pull and the transitions can mint credits and populate identity's balance.
 * To prove that the output is locked, a height where transaction was chain locked is provided.
 */
const ChainAssetLockProof : BinCodeable<ChainAssetLockProof> & ((data: {
    /**
     * Core height on which the asset lock transaction was chain locked or higher
     */
  core_chain_locked_height: number,
    /**
     * A reference to Asset Lock Special Transaction ID and output index in the payload
     */
  out_point: OutPoint,
}) => ChainAssetLockProof);
interface ChainAssetLockProof {
  /**
   * Core height on which the asset lock transaction was chain locked or higher
   */
  core_chain_locked_height: number;
  /**
   * A reference to Asset Lock Special Transaction ID and output index in the payload
   */
  out_point: OutPoint;
}

export abstract class ChangeControlRules {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: ChangeControlRules): void;
  static decode(bc: BinCode): ChangeControlRules;
}
namespace ChangeControlRules {
  const V0: (f0: ChangeControlRulesV0) => ChangeControlRules.V0;
  interface V0 extends ChangeControlRules {
    [0]: ChangeControlRulesV0;
  }
}

const ChangeControlRulesV0 : BinCodeable<ChangeControlRulesV0> & ((data: {
    /**
     * This is who is authorized to make such a change
     */
  authorized_to_make_change: AuthorizedActionTakers,
    /**
     * This is who is authorized to make such a change to the people authorized to make a change
     */
  admin_action_takers: AuthorizedActionTakers,
    /**
     * Are we allowed to change to None in the future
     */
  changing_authorized_action_takers_to_no_one_allowed: boolean,
    /**
     * Are we allowed to change the admin action takers to no one in the future
     */
  changing_admin_action_takers_to_no_one_allowed: boolean,
    /**
     * Can the admin action takers change themselves
     */
  self_changing_admin_action_takers_allowed: boolean,
}) => ChangeControlRulesV0);
interface ChangeControlRulesV0 {
  /**
   * This is who is authorized to make such a change
   */
  authorized_to_make_change: AuthorizedActionTakers;
  /**
   * This is who is authorized to make such a change to the people authorized to make a change
   */
  admin_action_takers: AuthorizedActionTakers;
  /**
   * Are we allowed to change to None in the future
   */
  changing_authorized_action_takers_to_no_one_allowed: boolean;
  /**
   * Are we allowed to change the admin action takers to no one in the future
   */
  changing_admin_action_takers_to_no_one_allowed: boolean;
  /**
   * Can the admin action takers change themselves
   */
  self_changing_admin_action_takers_allowed: boolean;
}

const ContestedDocumentResourceVotePoll : BinCodeable<ContestedDocumentResourceVotePoll> & ((data: {
  contract_id: Identifier,
  document_type_name: string,
  index_name: string,
  index_values: Value[],
}) => ContestedDocumentResourceVotePoll);
interface ContestedDocumentResourceVotePoll {
  contract_id: Identifier;
  document_type_name: string;
  index_name: string;
  index_values: Value[];
}

/**
 * A contract bounds is the bounds that the key has influence on.
 * For authentication keys the bounds mean that the keys can only be used to sign
 * within the specified contract.
 * For encryption decryption this tells clients to only use these keys for specific
 * contracts.
 *
// repr u8
 */
export abstract class ContractBounds {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: ContractBounds): void;
  static decode(bc: BinCode): ContractBounds;
}
namespace ContractBounds {
  /**
   * this key can only be used within a specific contract
   */
  const SingleContract: (data: {
    id: Identifier,
  }) => ContractBounds.SingleContract;
  interface SingleContract extends ContractBounds {
    id: Identifier;
  }
  /**
   * this key can only be used within a specific contract and for a specific document type
   */
  const SingleContractDocumentType: (data: {
    id: Identifier,
    document_type_name: string,
  }) => ContractBounds.SingleContractDocumentType;
  interface SingleContractDocumentType extends ContractBounds {
    id: Identifier;
    document_type_name: string;
  }
}

const CoreScript : BinCodeable<CoreScript> & ((
    f0: DashcoreScript,
) => CoreScript);
interface CoreScript {
  [0]: DashcoreScript;
}

export type Credits = number;

export type DashcoreScript = ScriptBuf;

export abstract class DataContractConfig {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: DataContractConfig): void;
  static decode(bc: BinCode): DataContractConfig;
}
namespace DataContractConfig {
  const V0: (f0: DataContractConfigV0) => DataContractConfig.V0;
  interface V0 extends DataContractConfig {
    [0]: DataContractConfigV0;
  }
  const V1: (f0: DataContractConfigV1) => DataContractConfig.V1;
  interface V1 extends DataContractConfig {
    [0]: DataContractConfigV1;
  }
}

const DataContractConfigV0 : BinCodeable<DataContractConfigV0> & ((data: {
    /**
     * Can the contract ever be deleted. If the contract is deleted, so should be all
     * documents associated with it. TODO: There should also be a way to "stop" the contract -
     * contract and documents are kept in the system, but no new documents can be added to it
     */
  can_be_deleted: boolean,
    /**
     * Is the contract mutable. Means that the document definitions can be changed or new
     * document definitions can be added to the contract
     */
  readonly: boolean,
    /**
     * Does the contract keep history when the contract itself changes
     */
  keeps_history: boolean,
    /**
     * Do documents in the contract keep history. This is a default for all documents in
     * the contract, but can be overridden by the document itself
     */
  documents_keep_history_contract_default: boolean,
    /**
     * Are documents in the contract mutable? This specifies whether the documents can be
     * changed. This is a default for all document types in the contract, but can be
     * overridden by the document type config.
     */
  documents_mutable_contract_default: boolean,
    /**
     * Can documents in the contract be deleted? This specifies whether the documents can be
     * deleted. This is a default for all document types in the contract, but can be
     * overridden by the document types itself.
     */
  documents_can_be_deleted_contract_default: boolean,
    /**
     * Encryption key storage requirements
     */
  requires_identity_encryption_bounded_key?: StorageKeyRequirements,
    /**
     * Decryption key storage requirements
     */
  requires_identity_decryption_bounded_key?: StorageKeyRequirements,
}) => DataContractConfigV0);
interface DataContractConfigV0 {
  /**
   * Can the contract ever be deleted. If the contract is deleted, so should be all
   * documents associated with it. TODO: There should also be a way to "stop" the contract -
   * contract and documents are kept in the system, but no new documents can be added to it
   */
  can_be_deleted: boolean;
  /**
   * Is the contract mutable. Means that the document definitions can be changed or new
   * document definitions can be added to the contract
   */
  readonly: boolean;
  /**
   * Does the contract keep history when the contract itself changes
   */
  keeps_history: boolean;
  /**
   * Do documents in the contract keep history. This is a default for all documents in
   * the contract, but can be overridden by the document itself
   */
  documents_keep_history_contract_default: boolean;
  /**
   * Are documents in the contract mutable? This specifies whether the documents can be
   * changed. This is a default for all document types in the contract, but can be
   * overridden by the document type config.
   */
  documents_mutable_contract_default: boolean;
  /**
   * Can documents in the contract be deleted? This specifies whether the documents can be
   * deleted. This is a default for all document types in the contract, but can be
   * overridden by the document types itself.
   */
  documents_can_be_deleted_contract_default: boolean;
  /**
   * Encryption key storage requirements
   */
  requires_identity_encryption_bounded_key?: StorageKeyRequirements;
  /**
   * Decryption key storage requirements
   */
  requires_identity_decryption_bounded_key?: StorageKeyRequirements;
}

const DataContractConfigV1 : BinCodeable<DataContractConfigV1> & ((data: {
    /**
     * Can the contract ever be deleted. If the contract is deleted, so should be all
     * documents associated with it. TODO: There should also be a way to "stop" the contract -
     * contract and documents are kept in the system, but no new documents can be added to it
     */
  can_be_deleted: boolean,
    /**
     * Is the contract mutable. Means that the document definitions can be changed or new
     * document definitions can be added to the contract
     */
  readonly: boolean,
    /**
     * Does the contract keep history when the contract itself changes
     */
  keeps_history: boolean,
    /**
     * Do documents in the contract keep history. This is a default for all documents in
     * the contract, but can be overridden by the document itself
     */
  documents_keep_history_contract_default: boolean,
    /**
     * Are documents in the contract mutable? This specifies whether the documents can be
     * changed. This is a default for all document types in the contract, but can be
     * overridden by the document type config.
     */
  documents_mutable_contract_default: boolean,
    /**
     * Can documents in the contract be deleted? This specifies whether the documents can be
     * deleted. This is a default for all document types in the contract, but can be
     * overridden by the document types itself.
     */
  documents_can_be_deleted_contract_default: boolean,
    /**
     * Encryption key storage requirements
     */
  requires_identity_encryption_bounded_key?: StorageKeyRequirements,
    /**
     * Decryption key storage requirements
     */
  requires_identity_decryption_bounded_key?: StorageKeyRequirements,
    /**
     * Use sized integer Rust types for `integer` property type based on validation rules
     */
  sized_integer_types: boolean,
}) => DataContractConfigV1);
interface DataContractConfigV1 {
  /**
   * Can the contract ever be deleted. If the contract is deleted, so should be all
   * documents associated with it. TODO: There should also be a way to "stop" the contract -
   * contract and documents are kept in the system, but no new documents can be added to it
   */
  can_be_deleted: boolean;
  /**
   * Is the contract mutable. Means that the document definitions can be changed or new
   * document definitions can be added to the contract
   */
  readonly: boolean;
  /**
   * Does the contract keep history when the contract itself changes
   */
  keeps_history: boolean;
  /**
   * Do documents in the contract keep history. This is a default for all documents in
   * the contract, but can be overridden by the document itself
   */
  documents_keep_history_contract_default: boolean;
  /**
   * Are documents in the contract mutable? This specifies whether the documents can be
   * changed. This is a default for all document types in the contract, but can be
   * overridden by the document type config.
   */
  documents_mutable_contract_default: boolean;
  /**
   * Can documents in the contract be deleted? This specifies whether the documents can be
   * deleted. This is a default for all document types in the contract, but can be
   * overridden by the document types itself.
   */
  documents_can_be_deleted_contract_default: boolean;
  /**
   * Encryption key storage requirements
   */
  requires_identity_encryption_bounded_key?: StorageKeyRequirements;
  /**
   * Decryption key storage requirements
   */
  requires_identity_decryption_bounded_key?: StorageKeyRequirements;
  /**
   * Use sized integer Rust types for `integer` property type based on validation rules
   */
  sized_integer_types: boolean;
}

// platform_version_path_bounds "dpp.state_transition_serialization_versions.contract_create_state_transition"
export abstract class DataContractCreateTransition {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: DataContractCreateTransition): void;
  static decode(bc: BinCode): DataContractCreateTransition;
}
namespace DataContractCreateTransition {
  const V0: (f0: DataContractCreateTransitionV0) => DataContractCreateTransition.V0;
  interface V0 extends DataContractCreateTransition {
    [0]: DataContractCreateTransitionV0;
  }
}

/**
 *DataContractCreateTransitionV0 has the same encoding structure
 */
const DataContractCreateTransitionV0 : BinCodeable<DataContractCreateTransitionV0> & ((data: {
  data_contract: DataContractInSerializationFormat,
  identity_nonce: IdentityNonce,
  user_fee_increase: UserFeeIncrease,
    // platform_signable exclude_from_sig_hash
  signature_public_key_id: KeyID,
    // platform_signable exclude_from_sig_hash
  signature: BinaryData,
}) => DataContractCreateTransitionV0);
interface DataContractCreateTransitionV0 {
  data_contract: DataContractInSerializationFormat;
  identity_nonce: IdentityNonce;
  user_fee_increase: UserFeeIncrease;
  // platform_signable exclude_from_sig_hash
  signature_public_key_id: KeyID;
  // platform_signable exclude_from_sig_hash
  signature: BinaryData;
}

export abstract class DataContractInSerializationFormat {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: DataContractInSerializationFormat): void;
  static decode(bc: BinCode): DataContractInSerializationFormat;
}
namespace DataContractInSerializationFormat {
  const V0: (f0: DataContractInSerializationFormatV0) => DataContractInSerializationFormat.V0;
  interface V0 extends DataContractInSerializationFormat {
    [0]: DataContractInSerializationFormatV0;
  }
  const V1: (f0: DataContractInSerializationFormatV1) => DataContractInSerializationFormat.V1;
  interface V1 extends DataContractInSerializationFormat {
    [0]: DataContractInSerializationFormatV1;
  }
}

const DataContractInSerializationFormatV0 : BinCodeable<DataContractInSerializationFormatV0> & ((data: {
    /**
     * A unique identifier for the data contract.
     */
  id: Identifier,
    /**
     * Internal configuration for the contract.
     */
  config: DataContractConfig,
    /**
     * The version of this data contract.
     */
  version: number,
    /**
     * The identifier of the contract owner.
     */
  owner_id: Identifier,
    /**
     * Shared subschemas to reuse across documents as $defs object
     */
  schema_defs?: Map<DefinitionName, Value>,
    /**
     * Document JSON Schemas per type
     */
  document_schemas: Map<DocumentName, Value>,
}) => DataContractInSerializationFormatV0);
interface DataContractInSerializationFormatV0 {
  /**
   * A unique identifier for the data contract.
   */
  id: Identifier;
  /**
   * Internal configuration for the contract.
   */
  config: DataContractConfig;
  /**
   * The version of this data contract.
   */
  version: number;
  /**
   * The identifier of the contract owner.
   */
  owner_id: Identifier;
  /**
   * Shared subschemas to reuse across documents as $defs object
   */
  schema_defs?: Map<DefinitionName, Value>;
  /**
   * Document JSON Schemas per type
   */
  document_schemas: Map<DocumentName, Value>;
}

const DataContractInSerializationFormatV1 : BinCodeable<DataContractInSerializationFormatV1> & ((data: {
    /**
     * A unique identifier for the data contract.
     */
  id: Identifier,
    /**
     * Internal configuration for the contract.
     */
  config: DataContractConfig,
    /**
     * The version of this data contract.
     */
  version: number,
    /**
     * The identifier of the contract owner.
     */
  owner_id: Identifier,
    /**
     * Shared subschemas to reuse across documents as $defs object
     */
  schema_defs?: Map<DefinitionName, Value>,
    /**
     * Document JSON Schemas per type
     */
  document_schemas: Map<DocumentName, Value>,
    /**
     * The time in milliseconds that the contract was created.
     */
  created_at?: TimestampMillis,
    /**
     * The time in milliseconds that the contract was last updated.
     */
  updated_at?: TimestampMillis,
    /**
     * The block that the document was created.
     */
  created_at_block_height?: BlockHeight,
    /**
     * The block that the contract was last updated
     */
  updated_at_block_height?: BlockHeight,
    /**
     * The epoch at which the contract was created.
     */
  created_at_epoch?: EpochIndex,
    /**
     * The epoch at which the contract was last updated.
     */
  updated_at_epoch?: EpochIndex,
    /**
     * Groups that allow for specific multiparty actions on the contract
     */
  groups: Map<GroupContractPosition, Group>,
    /**
     * The tokens on the contract.
     */
  tokens: Map<TokenContractPosition, TokenConfiguration>,
}) => DataContractInSerializationFormatV1);
interface DataContractInSerializationFormatV1 {
  /**
   * A unique identifier for the data contract.
   */
  id: Identifier;
  /**
   * Internal configuration for the contract.
   */
  config: DataContractConfig;
  /**
   * The version of this data contract.
   */
  version: number;
  /**
   * The identifier of the contract owner.
   */
  owner_id: Identifier;
  /**
   * Shared subschemas to reuse across documents as $defs object
   */
  schema_defs?: Map<DefinitionName, Value>;
  /**
   * Document JSON Schemas per type
   */
  document_schemas: Map<DocumentName, Value>;
  /**
   * The time in milliseconds that the contract was created.
   */
  created_at?: TimestampMillis;
  /**
   * The time in milliseconds that the contract was last updated.
   */
  updated_at?: TimestampMillis;
  /**
   * The block that the document was created.
   */
  created_at_block_height?: BlockHeight;
  /**
   * The block that the contract was last updated
   */
  updated_at_block_height?: BlockHeight;
  /**
   * The epoch at which the contract was created.
   */
  created_at_epoch?: EpochIndex;
  /**
   * The epoch at which the contract was last updated.
   */
  updated_at_epoch?: EpochIndex;
  /**
   * Groups that allow for specific multiparty actions on the contract
   */
  groups: Map<GroupContractPosition, Group>;
  /**
   * The tokens on the contract.
   */
  tokens: Map<TokenContractPosition, TokenConfiguration>;
}

// platform_version_path_bounds "dpp.state_transition_serialization_versions.contract_update_state_transition"
export abstract class DataContractUpdateTransition {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: DataContractUpdateTransition): void;
  static decode(bc: BinCode): DataContractUpdateTransition;
}
namespace DataContractUpdateTransition {
  const V0: (f0: DataContractUpdateTransitionV0) => DataContractUpdateTransition.V0;
  interface V0 extends DataContractUpdateTransition {
    [0]: DataContractUpdateTransitionV0;
  }
}

const DataContractUpdateTransitionV0 : BinCodeable<DataContractUpdateTransitionV0> & ((data: {
  identity_contract_nonce: IdentityNonce,
  data_contract: DataContractInSerializationFormat,
  user_fee_increase: UserFeeIncrease,
    // platform_signable exclude_from_sig_hash
  signature_public_key_id: KeyID,
    // platform_signable exclude_from_sig_hash
  signature: BinaryData,
}) => DataContractUpdateTransitionV0);
interface DataContractUpdateTransitionV0 {
  identity_contract_nonce: IdentityNonce;
  data_contract: DataContractInSerializationFormat;
  user_fee_increase: UserFeeIncrease;
  // platform_signable exclude_from_sig_hash
  signature_public_key_id: KeyID;
  // platform_signable exclude_from_sig_hash
  signature: BinaryData;
}

export type DefinitionName = string;

export type DerivationEncryptionKeyIndex = number;

export abstract class DistributionFunction {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: DistributionFunction): void;
  static decode(bc: BinCode): DistributionFunction;
}
namespace DistributionFunction {
  /**
   * Emits a constant (fixed) number of tokens for every period.
   *
   * # Formula
   * For any period `x`, the emitted tokens are:
   *
   * ```text
   * f(x) = n
   * ```
   *
   * # Use Case
   * - When a predictable, unchanging reward is desired.
   * - Simplicity and stable emissions.
   *
   * # Example
   * - If `n = 5` tokens per block, then after 3 blocks the total emission is 15 tokens.
   */
  const FixedAmount: (data: {
    amount: TokenAmount,
  }) => DistributionFunction.FixedAmount;
  interface FixedAmount extends DistributionFunction {
    amount: TokenAmount;
  }
  /**
   * Emits a random number of tokens within a specified range.
   *
   * # Description
   * - This function selects a **random** token emission amount between `min` and `max`.
   * - The value is drawn **uniformly** between the bounds.
   * - The randomness uses a Pseudo Random Function (PRF) from x.
   *
   * # Formula
   * For any period `x`, the emitted tokens follow:
   *
   * ```text
   * f(x) ∈ [min, max]
   * ```
   *
   * # Parameters
   * - `min`: The **minimum** possible number of tokens emitted.
   * - `max`: The **maximum** possible number of tokens emitted.
   *
   * # Use Cases
   * - **Stochastic Rewards**: Introduces randomness into rewards to incentivize unpredictability.
   * - **Lottery-Based Systems**: Used for randomized emissions, such as block rewards with probabilistic payouts.
   *
   * # Example
   * Suppose a system emits **between 10 and 100 tokens per period**.
   *
   * ```text
   * Random { min: 10, max: 100 }
   * ```
   *
   * | Period (x) | Emitted Tokens (Random) |
   * |------------|------------------------|
   * | 1          | 27                     |
   * | 2          | 94                     |
   * | 3          | 63                     |
   * | 4          | 12                     |
   *
   * - Each period, the function emits a **random number of tokens** between `min = 10` and `max = 100`.
   * - Over time, the **average reward trends toward the midpoint** `(min + max) / 2`.
   *
   * # Constraints
   * - **`min` must be ≤ `max`**, otherwise the function is invalid.
   * - If `min == max`, this behaves like a `FixedAmount` function with a constant emission.
   */
  const Random: (data: {
    min: TokenAmount,
    max: TokenAmount,
  }) => DistributionFunction.Random;
  interface Random extends DistributionFunction {
    min: TokenAmount;
    max: TokenAmount;
  }
  /**
   * Emits tokens that decrease in discrete steps at fixed intervals.
   *
   * # Formula
   * For a given period `x`, the emission is calculated as:
   *
   * ```text
   * f(x) = n * (1 - (decrease_per_interval_numerator / decrease_per_interval_denominator))^((x - s) / step_count)
   * ```
   *
   * # Parameters
   * - `step_count`: The number of periods between each step.
   * - `decrease_per_interval_numerator` and `decrease_per_interval_denominator`: Define the reduction factor per step.
   * - `s`: Optional start period offset (e.g., start block or time). If not provided, the contract creation start is used.
   * - `n`: The initial token emission.
   * - `min_value`: Optional minimum emission value.
   *
   * # Use Case
   * - Modeling reward systems similar to Bitcoin or Dash Core.
   * - Encouraging early participation by providing higher rewards initially.
   *
   * # Example
   * - Bitcoin-style: 50% reduction every 210,000 blocks.
   * - Dash-style: Approximately a 7% reduction every 210,000 blocks.
   */
  const StepDecreasingAmount: (data: {
    step_count: number,
    decrease_per_interval_numerator: number,
    decrease_per_interval_denominator: number,
    s?: number,
    n: TokenAmount,
    min_value?: number,
  }) => DistributionFunction.StepDecreasingAmount;
  interface StepDecreasingAmount extends DistributionFunction {
    step_count: number;
    decrease_per_interval_numerator: number;
    decrease_per_interval_denominator: number;
    s?: number;
    n: TokenAmount;
    min_value?: number;
  }
  /**
   * Emits tokens in fixed amounts for predefined intervals (steps).
   *
   * # Details
   * - Within each step, the emission remains constant.
   * - The keys in the `BTreeMap` represent the starting period for each interval,
   *   and the corresponding values are the fixed token amounts to emit during that interval.
   *
   * # Use Case
   * - Adjusting rewards at specific milestones or time intervals.
   *
   * # Example
   * - Emit 100 tokens per block for the first 1,000 blocks, then 50 tokens per block thereafter.
   */
  const Stepwise: (f0: Map<number, TokenAmount>) => DistributionFunction.Stepwise;
  interface Stepwise extends DistributionFunction {
    [0]: Map<number, TokenAmount>;
  }
  /**
   * Emits tokens following a linear function that can increase or decrease over time
   * with fractional precision.
   *
   * # Formula
   * The emission at period `x` is given by:
   *
   * ```text
   * f(x) = (a * (x - start_moment) / d) + starting_amount
   * ```
   *
   * # Parameters
   * - `a`: The slope numerator; determines the rate of change.
   * - `d`: The slope divisor; together with `a` controls the fractional rate.
   * - `s`: Optional start period offset. If not set, the contract creation start is assumed.
   * - `b`: The initial token emission (offset).
   * - `min_value` / `max_value`: Optional bounds to clamp the emission.
   *
   * # Details
   * - If `a > 0`, emissions increase over time.
   * - If `a < 0`, emissions decrease over time.
   *
   * # Behavior
   * - **If `a > 0`**, emissions increase linearly over time.
   * - **If `a < 0`**, emissions decrease linearly over time.
   * - **If `a = 0`**, emissions remain constant at `b`.
   *
   * # Use Cases
   * - **Predictable Inflation or Deflation:** A simple mechanism to adjust token supply dynamically.
   * - **Long-Term Incentive Structures:** Ensures steady and measurable growth or reduction of rewards.
   * - **Decaying Emissions:** Can be used to gradually taper off token rewards over time.
   * - **Sustained Growth Models:** Encourages prolonged engagement by steadily increasing rewards.
   *
   * # Examples
   *
   * ## **1️⃣ Increasing Linear Emission (`a > 0`)**
   * - Tokens increase by **1 token per block** starting from 10.
   *
   * ```text
   * f(x) = (1 * (x - 0) / 1) + 10
   * ```
   *
   * | Block (x) | f(x) (Tokens) |
   * |-----------|---------------|
   * | 0         | 10            |
   * | 1         | 11            |
   * | 2         | 12            |
   * | 3         | 13            |
   *
   * **Use Case:** Encourages continued participation by providing increasing rewards over time.
   *
   * ---
   *
   * ## **2️⃣ Decreasing Linear Emission (`a < 0`)**
   * - Tokens **start at 100 and decrease by 2 per period**.
   *
   * ```text
   * f(x) = (-2 * (x - 0) / 1) + 100
   * ```
   *
   * | Block (x) | f(x) (Tokens) |
   * |-----------|---------------|
   * | 0         | 100           |
   * | 1         | 98            |
   * | 2         | 96            |
   * | 3         | 94            |
   *
   * **Use Case:** Suitable for deflationary models where rewards need to decrease over time.
   *
   * ---
   *
   * ## **3️⃣ Emission with a Delayed Start (`s > 0`)**
   * - **No emissions before `x = s`** (e.g., rewards start at block `10`).
   *
   * ```text
   * f(x) = (5 * (x - 10) / 1) + 50
   * ```
   *
   * | Block (x) | f(x) (Tokens) |
   * |-----------|---------------|
   * | 9         | 50 (no change)|
   * | 10        | 50            |
   * | 11        | 55            |
   * | 12        | 60            |
   *
   * **Use Case:** Useful when rewards should only begin at a specific milestone.
   *
   * ---
   *
   * ## **4️⃣ Clamping Emissions with `min_value` and `max_value`**
   * - **Start at 50, increase by 2, but never exceed 60.**
   *
   * ```text
   * f(x) = (2 * (x - 0) / 1) + 50
   * ```
   *
   * | Block (x) | f(x) (Tokens) |
   * |-----------|---------------|
   * | 0         | 50            |
   * | 1         | 52            |
   * | 2         | 54            |
   * | 5         | 60 (max cap)  |
   *
   * **Use Case:** Prevents runaway inflation by limiting the emission range.
   *
   * ---
   *
   * # Summary
   * - **Increasing rewards (`a > 0`)**: Encourages longer participation.
   * - **Decreasing rewards (`a < 0`)**: Supports controlled deflation.
   * - **Delayed start (`s > 0`)**: Ensures rewards only begin at a specific point.
   * - **Clamping (`min_value`, `max_value`)**: Maintains controlled emission boundaries.
   */
  const Linear: (data: {
    a: number,
    d: number,
    start_step?: number,
    starting_amount: TokenAmount,
    min_value?: number,
    max_value?: number,
  }) => DistributionFunction.Linear;
  interface Linear extends DistributionFunction {
    a: number;
    d: number;
    start_step?: number;
    starting_amount: TokenAmount;
    min_value?: number;
    max_value?: number;
  }
  /**
   * Emits tokens following a polynomial curve with integer arithmetic.
   *
   * # Formula
   * The emission at period `x` is given by:
   *
   * ```text
   * f(x) = (a * (x - s + o)^(m/n)) / d + b
   * ```
   *
   * # Parameters
   * - `a`: Scaling factor for the polynomial term.
   * - `m` and `n`: Together specify the exponent as a rational number (allowing non-integer exponents).
   * - `d`: A divisor for scaling.
   * - `s`: Optional start period offset. If not provided, the contract creation start is used.
   * - `o`: An offset for the polynomial function, this is useful if s is in None,
   * - `b`: An offset added to the computed value.
   * - `min_value` / `max_value`: Optional bounds to constrain the emission.
   *
   * # Behavior & Use Cases
   * The polynomial function's behavior depends on the values of `a` (scaling factor) and `m` (exponent numerator).
   *
   * ## **1️⃣ `a > 0`, `m > 0` (Increasing Polynomial Growth)**
   * - **Behavior**: Emissions **increase at an accelerating rate** over time.
   * - **Use Case**: Suitable for models where incentives start small and grow over time (e.g., boosting late-stage participation).
   * - **Example**:
   *   ```text
   *   f(x) = (2 * (x - s + o)^2) / d + 10
   *   ```
   *   - If `s = 0`, `o = 0`, and `d = 1`, then:
   *     - `f(1) = 12`
   *     - `f(2) = 18`
   *     - `f(3) = 28` (Emissions **accelerate over time**)
   *
   * ## **2️⃣ `a > 0`, `m < 0` (Decreasing Polynomial Decay)**
   * - **Behavior**: Emissions **start high and gradually decline**.
   * - **Use Case**: Useful for front-loaded incentives where rewards are larger at the beginning and taper off over time.
   * - **Example**:
   *   ```text
   *   f(x) = (5 * (x - s + o)^(-1)) / d + 10
   *   ```
   *   - If `s = 0`, `o = 0`, and `d = 1`, then:
   *     - `f(1) = 15`
   *     - `f(2) = 12.5`
   *     - `f(3) = 11.67` (Emissions **shrink but never hit zero**)
   *
   * ## **3️⃣ `a < 0`, `m > 0` (Inverted Growth → Decreasing Over Time)**
   * - **Behavior**: Emissions **start large but decrease faster over time**.
   * - **Use Case**: Suitable for cases where high initial incentives quickly drop off (e.g., limited early rewards).
   * - **Example**:
   *   ```text
   *   f(x) = (-3 * (x - s + o)^2) / d + 50
   *   ```
   *   - If `s = 0`, `o = 0`, and `d = 1`, then:
   *     - `f(1) = 47`
   *     - `f(2) = 38`
   *     - `f(3) = 23` (Emissions **fall sharply**)
   *
   * ## **4️⃣ `a < 0`, `m < 0` (Inverted Decay → Slowing Increase)**
   * - **Behavior**: Emissions **start low, rise gradually, and then flatten out**.
   * - **Use Case**: Useful for controlled inflation where rewards increase over time but approach a stable maximum.
   * - **Example**:
   *   ```text
   *   f(x) = (-10 * (x - s + o)^(-2)) / d + 50
   *   ```
   *   - If `s = 0`, `o = 0`, and `d = 1`, then:
   *     - `f(1) = 40`
   *     - `f(2) = 47.5`
   *     - `f(3) = 48.89` (Growth **slows as it approaches 50**)
   *
   * # Summary
   * - **Positive `a` means increasing emissions**, while **negative `a` means decreasing emissions**.
   * - **Positive `m` leads to growth**, while **negative `m` leads to decay**.
   * - The combination of `a` and `m` defines whether emissions accelerate, decay, or remain stable.
   */
  const Polynomial: (data: {
    a: number,
    d: number,
    m: number,
    n: number,
    o: number,
    start_moment?: number,
    b: TokenAmount,
    min_value?: number,
    max_value?: number,
  }) => DistributionFunction.Polynomial;
  interface Polynomial extends DistributionFunction {
    a: number;
    d: number;
    m: number;
    n: number;
    o: number;
    start_moment?: number;
    b: TokenAmount;
    min_value?: number;
    max_value?: number;
  }
  /**
   * Emits tokens following an exponential function.
   *
   * # Formula
   * The emission at period `x` is given by:
   *
   * ```text
   * f(x) = (a * e^(m * (x - s) / n)) / d + c
   * ```
   *
   * # Parameters
   * - `a`: The scaling factor.
   * - `m` and `n`: Define the exponent rate (with `m > 0` for growth and `m < 0` for decay).
   * - `d`: A divisor used to scale the exponential term.
   * - `s`: Optional start period offset. If not set, the contract creation start is assumed.
   * - `o`: An offset for the exp function, this is useful if s is in None.
   * - `c`: An offset added to the result.
   * - `min_value` / `max_value`: Optional constraints on the emitted tokens.
   *
   * # Use Cases
   * ## **Exponential Growth (`m > 0`):**
   * - **Incentivized Spending**: Higher emissions over time increase the circulating supply, encouraging users to spend tokens.
   * - **Progressive Emission Models**: Useful for models where early emissions are low but increase significantly over time.
   * - **Early-Stage Adoption Strategies**: Helps drive later participation by offering increasing rewards as time progresses.
   *
   * ## **Exponential Decay (`m < 0`):**
   * - **Deflationary Reward Models**: Reduces emissions over time, ensuring token scarcity.
   * - **Early Participation Incentives**: Encourages early users by distributing more tokens initially and gradually decreasing rewards.
   * - **Sustainable Emission Models**: Helps manage token supply while preventing runaway inflation.
   *
   * # Examples
   * ## **Example 1: Exponential Growth (`m > 0`)**
   * - **Use Case**: A staking model where rewards increase over time to encourage long-term participation.
   * - **Parameters**: `a = 100`, `m = 2`, `n = 50`, `d = 10`, `c = 5`
   * - **Formula**:
   *   ```text
   *   f(x) = (100 * e^(2 * (x - s) / 50)) / 10 + 5
   *   ```
   * - **Effect**: Emissions start small but **increase exponentially** over time, rewarding late stakers more than early ones.
   *
   * ## **Example 2: Exponential Decay (`m < 0`)**
   * - **Use Case**: A deflationary model where emissions start high and gradually decrease to ensure scarcity.
   * - **Parameters**: `a = 500`, `m = -3`, `n = 100`, `d = 20`, `c = 10`
   * - **Formula**:
   *   ```text
   *   f(x) = (500 * e^(-3 * (x - s) / 100)) / 20 + 10
   *   ```
   * - **Effect**: Emissions start **high and decay exponentially**, ensuring early participants get larger rewards.
   */
  const Exponential: (data: {
    a: number,
    d: number,
    m: number,
    n: number,
    o: number,
    start_moment?: number,
    c: TokenAmount,
    min_value?: number,
    max_value?: number,
  }) => DistributionFunction.Exponential;
  interface Exponential extends DistributionFunction {
    a: number;
    d: number;
    m: number;
    n: number;
    o: number;
    start_moment?: number;
    c: TokenAmount;
    min_value?: number;
    max_value?: number;
  }
  /**
   * Emits tokens following a logarithmic function.
   *
   * # Formula
   * The emission at period `x` is computed as:
   *
   * ```text
   * f(x) = (a * log(m * (x - s + o) / n)) / d + b
   * ```
   *
   * # Parameters
   * - `a`: Scaling factor for the logarithmic term.
   * - `d`: A divisor for scaling.
   * - `m` and `n`: Adjust the input to the logarithm function.
   * - `s`: Optional start period offset. If not provided, the contract creation start is used.
   * - `o`: An offset for the log function, this is useful if s is in None.
   * - `b`: An offset added to the result.
   * - `min_value` / `max_value`: Optional bounds to ensure the emission remains within limits.
   *
   * # Use Case
   * - **Gradual Growth with a Slowing Rate**: Suitable for reward schedules where the emission
   *   starts at a lower rate, increases quickly at first, but then slows down over time.
   * - **Predictable Emission Scaling**: Ensures a growing but controlled emission curve that
   *   does not escalate too quickly.
   * - **Sustainability and Inflation Control**: Helps prevent runaway token supply growth
   *   by ensuring rewards increase at a decreasing rate.
   *
   * # Example
   * - Suppose we want token emissions to start at a low value and grow over time, but at a
   *   **decreasing rate**, ensuring controlled long-term growth.
   *
   * - Given the formula:
   *   ```text
   *   f(x) = (a * log(m * (x - s + o) / n)) / d + b
   *   ```
   *
   * - Let’s assume the following parameters:
   *   - `a = 100`: Scaling factor.
   *   - `d = 10`: Divisor to control overall scaling.
   *   - `m = 2`, `n = 1`: Adjust the logarithmic input.
   *   - `s = 0`, `o = 1`: Starting conditions.
   *   - `b = 50`: Base amount added.
   *
   * - This results in:
   *   ```text
   *   f(x) = (100 * log(2 * (x + 1) / 1)) / 10 + 50
   *   ```
   *
   * - **Expected Behavior:**
   *   - At `x = 1`, emission = `f(1) = (100 * log(4)) / 10 + 50 ≈ 82`
   *   - At `x = 10`, emission = `f(10) = (100 * log(22)) / 10 + 50 ≈ 106`
   *   - At `x = 100`, emission = `f(100) = (100 * log(202)) / 10 + 50 ≈ 130`
   *
   * - **Observations:**
   *   - The emission **increases** over time, but at a **slowing rate**.
   *   - Early increases are more pronounced, but as `x` grows, the additional reward per
   *     period gets smaller.
   *   - This makes it ideal for long-term, controlled emission models.
   */
  const Logarithmic: (data: {
    a: number,
    d: number,
    m: number,
    n: number,
    o: number,
    start_moment?: number,
    b: TokenAmount,
    min_value?: number,
    max_value?: number,
  }) => DistributionFunction.Logarithmic;
  interface Logarithmic extends DistributionFunction {
    a: number;
    d: number;
    m: number;
    n: number;
    o: number;
    start_moment?: number;
    b: TokenAmount;
    min_value?: number;
    max_value?: number;
  }
  /**
   * Emits tokens following an inverted logarithmic function.
   *
   * # Formula
   * The emission at period `x` is given by:
   *
   * ```text
   * f(x) = (a * log( n / (m * (x - s + o)) )) / d + b
   * ```
   *
   * # Parameters
   * - `a`: Scaling factor.
   * - `d`: Divisor for scaling.
   * - `m` and `n`: Together control the logarithm argument inversion.
   * - `o`: Offset applied inside the logarithm.
   * - `s`: Optional start period offset.
   * - `b`: Offset added to the computed value.
   * - `min_value` / `max_value`: Optional boundaries for the emission.
   *
   * # Use Case
   * - **Gradual Decay of Rewards**: Suitable when early adopters should receive higher rewards,
   *   but later participants should receive smaller but still meaningful amounts.
   * - **Resource Draining / Controlled Burn**: Used when token emissions should drop significantly
   *   at first but slow down over time to preserve capital.
   * - **Airdrop or Grant System**: Ensures early claimants receive larger distributions, but later
   *   claimants receive diminishing rewards.
   *
   * # Example
   * - Suppose a system starts with **500 tokens per period** and gradually reduces over time:
   *
   *   ```text
   *   f(x) = (1000 * log(5000 / (5 * (x - 1000)))) / 10 + 10
   *   ```
   *
   *   Example values:
   *
   *   | Period (x) | Emission (f(x)) |
   *   |------------|----------------|
   *   | 1000       | 500 tokens      |
   *   | 1500       | 230 tokens      |
   *   | 2000       | 150 tokens      |
   *   | 5000       | 50 tokens       |
   *   | 10,000     | 20 tokens       |
   *   | 50,000     | 10 tokens       |
   *
   *   - The emission **starts high** and **gradually decreases**, ensuring early adopters receive
   *     more tokens while later participants still get rewards.
   *   - The function **slows down the rate of decrease** over time, preventing emissions from
   *     hitting zero too quickly.
   */
  const InvertedLogarithmic: (data: {
    a: number,
    d: number,
    m: number,
    n: number,
    o: number,
    start_moment?: number,
    b: TokenAmount,
    min_value?: number,
    max_value?: number,
  }) => DistributionFunction.InvertedLogarithmic;
  interface InvertedLogarithmic extends DistributionFunction {
    a: number;
    d: number;
    m: number;
    n: number;
    o: number;
    start_moment?: number;
    b: TokenAmount;
    min_value?: number;
    max_value?: number;
  }
}

export abstract class DocumentBaseTransition {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: DocumentBaseTransition): void;
  static decode(bc: BinCode): DocumentBaseTransition;
}
namespace DocumentBaseTransition {
  const V0: (f0: DocumentBaseTransitionV0) => DocumentBaseTransition.V0;
  interface V0 extends DocumentBaseTransition {
    [0]: DocumentBaseTransitionV0;
  }
}

const DocumentBaseTransitionV0 : BinCodeable<DocumentBaseTransitionV0> & ((data: {
    /**
     * The document ID
     */
  id: Identifier,
  identity_contract_nonce: IdentityNonce,
    /**
     * Name of document type found int the data contract associated with the `data_contract_id`
     */
  document_type_name: string,
    /**
     * Data contract ID generated from the data contract's `owner_id` and `entropy`
     */
  data_contract_id: Identifier,
}) => DocumentBaseTransitionV0);
interface DocumentBaseTransitionV0 {
  /**
   * The document ID
   */
  id: Identifier;
  identity_contract_nonce: IdentityNonce;
  /**
   * Name of document type found int the data contract associated with the `data_contract_id`
   */
  document_type_name: string;
  /**
   * Data contract ID generated from the data contract's `owner_id` and `entropy`
   */
  data_contract_id: Identifier;
}

export abstract class DocumentCreateTransition {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: DocumentCreateTransition): void;
  static decode(bc: BinCode): DocumentCreateTransition;
}
namespace DocumentCreateTransition {
  const V0: (f0: DocumentCreateTransitionV0) => DocumentCreateTransition.V0;
  interface V0 extends DocumentCreateTransition {
    [0]: DocumentCreateTransitionV0;
  }
}

const DocumentCreateTransitionV0 : BinCodeable<DocumentCreateTransitionV0> & ((data: {
    /**
     * Document Base Transition
     */
  base: DocumentBaseTransition,
    /**
     * Entropy used to create a Document ID.
     */
  entropy: FixedBytes<32>,
  data: Map<string, Value>,
    /**
     * Pre funded balance (for unique index conflict resolution voting - the identity will put money
     * aside that will be used by voters to vote)
     * This is a map of index names to the amount we want to prefund them for
     * Since index conflict resolution is not a common feature most often nothing should be added here.
     */
  prefunded_voting_balance?: [string, Credits],
}) => DocumentCreateTransitionV0);
interface DocumentCreateTransitionV0 {
  /**
   * Document Base Transition
   */
  base: DocumentBaseTransition;
  /**
   * Entropy used to create a Document ID.
   */
  entropy: FixedBytes<32>;
  data: Map<string, Value>;
  /**
   * Pre funded balance (for unique index conflict resolution voting - the identity will put money
   * aside that will be used by voters to vote)
   * This is a map of index names to the amount we want to prefund them for
   * Since index conflict resolution is not a common feature most often nothing should be added here.
   */
  prefunded_voting_balance?: [string, Credits];
}

export abstract class DocumentDeleteTransition {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: DocumentDeleteTransition): void;
  static decode(bc: BinCode): DocumentDeleteTransition;
}
namespace DocumentDeleteTransition {
  const V0: (f0: DocumentDeleteTransitionV0) => DocumentDeleteTransition.V0;
  interface V0 extends DocumentDeleteTransition {
    [0]: DocumentDeleteTransitionV0;
  }
}

const DocumentDeleteTransitionV0 : BinCodeable<DocumentDeleteTransitionV0> & ((data: {
  base: DocumentBaseTransition,
}) => DocumentDeleteTransitionV0);
interface DocumentDeleteTransitionV0 {
  base: DocumentBaseTransition;
}

export type DocumentName = string;

export abstract class DocumentPurchaseTransition {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: DocumentPurchaseTransition): void;
  static decode(bc: BinCode): DocumentPurchaseTransition;
}
namespace DocumentPurchaseTransition {
  const V0: (f0: DocumentPurchaseTransitionV0) => DocumentPurchaseTransition.V0;
  interface V0 extends DocumentPurchaseTransition {
    [0]: DocumentPurchaseTransitionV0;
  }
}

const DocumentPurchaseTransitionV0 : BinCodeable<DocumentPurchaseTransitionV0> & ((data: {
  base: DocumentBaseTransition,
  revision: Revision,
  price: Credits,
}) => DocumentPurchaseTransitionV0);
interface DocumentPurchaseTransitionV0 {
  base: DocumentBaseTransition;
  revision: Revision;
  price: Credits;
}

export abstract class DocumentReplaceTransition {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: DocumentReplaceTransition): void;
  static decode(bc: BinCode): DocumentReplaceTransition;
}
namespace DocumentReplaceTransition {
  const V0: (f0: DocumentReplaceTransitionV0) => DocumentReplaceTransition.V0;
  interface V0 extends DocumentReplaceTransition {
    [0]: DocumentReplaceTransitionV0;
  }
}

const DocumentReplaceTransitionV0 : BinCodeable<DocumentReplaceTransitionV0> & ((data: {
  base: DocumentBaseTransition,
  revision: Revision,
  data: Map<string, Value>,
}) => DocumentReplaceTransitionV0);
interface DocumentReplaceTransitionV0 {
  base: DocumentBaseTransition;
  revision: Revision;
  data: Map<string, Value>;
}

export abstract class DocumentTransferTransition {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: DocumentTransferTransition): void;
  static decode(bc: BinCode): DocumentTransferTransition;
}
namespace DocumentTransferTransition {
  const V0: (f0: DocumentTransferTransitionV0) => DocumentTransferTransition.V0;
  interface V0 extends DocumentTransferTransition {
    [0]: DocumentTransferTransitionV0;
  }
}

const DocumentTransferTransitionV0 : BinCodeable<DocumentTransferTransitionV0> & ((data: {
  base: DocumentBaseTransition,
  revision: Revision,
  recipient_owner_id: Identifier,
}) => DocumentTransferTransitionV0);
interface DocumentTransferTransitionV0 {
  base: DocumentBaseTransition;
  revision: Revision;
  recipient_owner_id: Identifier;
}

export abstract class DocumentTransition {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: DocumentTransition): void;
  static decode(bc: BinCode): DocumentTransition;
}
namespace DocumentTransition {
  const Create: (f0: DocumentCreateTransition) => DocumentTransition.Create;
  interface Create extends DocumentTransition {
    [0]: DocumentCreateTransition;
  }
  const Replace: (f0: DocumentReplaceTransition) => DocumentTransition.Replace;
  interface Replace extends DocumentTransition {
    [0]: DocumentReplaceTransition;
  }
  const Delete: (f0: DocumentDeleteTransition) => DocumentTransition.Delete;
  interface Delete extends DocumentTransition {
    [0]: DocumentDeleteTransition;
  }
  const Transfer: (f0: DocumentTransferTransition) => DocumentTransition.Transfer;
  interface Transfer extends DocumentTransition {
    [0]: DocumentTransferTransition;
  }
  const UpdatePrice: (f0: DocumentUpdatePriceTransition) => DocumentTransition.UpdatePrice;
  interface UpdatePrice extends DocumentTransition {
    [0]: DocumentUpdatePriceTransition;
  }
  const Purchase: (f0: DocumentPurchaseTransition) => DocumentTransition.Purchase;
  interface Purchase extends DocumentTransition {
    [0]: DocumentPurchaseTransition;
  }
}

export abstract class DocumentUpdatePriceTransition {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: DocumentUpdatePriceTransition): void;
  static decode(bc: BinCode): DocumentUpdatePriceTransition;
}
namespace DocumentUpdatePriceTransition {
  const V0: (f0: DocumentUpdatePriceTransitionV0) => DocumentUpdatePriceTransition.V0;
  interface V0 extends DocumentUpdatePriceTransition {
    [0]: DocumentUpdatePriceTransitionV0;
  }
}

const DocumentUpdatePriceTransitionV0 : BinCodeable<DocumentUpdatePriceTransitionV0> & ((data: {
  base: DocumentBaseTransition,
  revision: Revision,
  price: Credits,
}) => DocumentUpdatePriceTransitionV0);
interface DocumentUpdatePriceTransitionV0 {
  base: DocumentBaseTransition;
  revision: Revision;
  price: Credits;
}

export type EpochIndex = number;

export type EpochInterval = number;

export abstract class Group {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: Group): void;
  static decode(bc: BinCode): Group;
}
namespace Group {
  const V0: (f0: GroupV0) => Group.V0;
  interface V0 extends Group {
    [0]: GroupV0;
  }
}

export type GroupContractPosition = number;

export type GroupMemberPower = number;

export type GroupRequiredPower = number;

const GroupStateTransitionInfo : BinCodeable<GroupStateTransitionInfo> & ((data: {
  group_contract_position: GroupContractPosition,
  action_id: Identifier,
    /**
     * This is true if we are the proposer, otherwise we are just voting on a previous action.
     */
  action_is_proposer: boolean,
}) => GroupStateTransitionInfo);
interface GroupStateTransitionInfo {
  group_contract_position: GroupContractPosition;
  action_id: Identifier;
  /**
   * This is true if we are the proposer, otherwise we are just voting on a previous action.
   */
  action_is_proposer: boolean;
}

const GroupV0 : BinCodeable<GroupV0> & ((data: {
  members: Map<Identifier, GroupMemberPower>,
  required_power: GroupRequiredPower,
}) => GroupV0);
interface GroupV0 {
  members: Map<Identifier, GroupMemberPower>;
  required_power: GroupRequiredPower;
}

export type Hash256 = FixedBytes<32>;

const Identifier : BinCodeable<Identifier> & ((
    f0: IdentifierBytes32,
) => Identifier);
interface Identifier {
  [0]: IdentifierBytes32;
}

const IdentifierBytes32 : BinCodeable<IdentifierBytes32> & ((
    f0: FixedBytes<32>,
) => IdentifierBytes32);
interface IdentifierBytes32 {
  [0]: FixedBytes<32>;
}

// platform_version_path_bounds "dpp.state_transition_serialization_versions.identity_create_state_transition"
export abstract class IdentityCreateTransition {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: IdentityCreateTransition): void;
  static decode(bc: BinCode): IdentityCreateTransition;
}
namespace IdentityCreateTransition {
  const V0: (f0: IdentityCreateTransitionV0) => IdentityCreateTransition.V0;
  interface V0 extends IdentityCreateTransition {
    [0]: IdentityCreateTransitionV0;
  }
}

// platform_signable derive_bincode_with_borrowed_vec
const IdentityCreateTransitionV0 : BinCodeable<IdentityCreateTransitionV0> & ((data: {
    // platform_signable into = "Vec<IdentityPublicKeyInCreationSignable>"
  public_keys: IdentityPublicKeyInCreation[],
  asset_lock_proof: AssetLockProof,
  user_fee_increase: UserFeeIncrease,
    // platform_signable exclude_from_sig_hash
  signature: BinaryData,
    // platform_signable exclude_from_sig_hash
  identity_id: Identifier,
}) => IdentityCreateTransitionV0);
interface IdentityCreateTransitionV0 {
  // platform_signable into = "Vec<IdentityPublicKeyInCreationSignable>"
  public_keys: IdentityPublicKeyInCreation[];
  asset_lock_proof: AssetLockProof;
  user_fee_increase: UserFeeIncrease;
  // platform_signable exclude_from_sig_hash
  signature: BinaryData;
  // platform_signable exclude_from_sig_hash
  identity_id: Identifier;
}

// platform_version_path_bounds "dpp.state_transition_serialization_versions.identity_credit_transfer_state_transition"
export abstract class IdentityCreditTransferTransition {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: IdentityCreditTransferTransition): void;
  static decode(bc: BinCode): IdentityCreditTransferTransition;
}
namespace IdentityCreditTransferTransition {
  const V0: (f0: IdentityCreditTransferTransitionV0) => IdentityCreditTransferTransition.V0;
  interface V0 extends IdentityCreditTransferTransition {
    [0]: IdentityCreditTransferTransitionV0;
  }
}

const IdentityCreditTransferTransitionV0 : BinCodeable<IdentityCreditTransferTransitionV0> & ((data: {
  identity_id: Identifier,
  recipient_id: Identifier,
  amount: number,
  nonce: IdentityNonce,
  user_fee_increase: UserFeeIncrease,
    // platform_signable exclude_from_sig_hash
  signature_public_key_id: KeyID,
    // platform_signable exclude_from_sig_hash
  signature: BinaryData,
}) => IdentityCreditTransferTransitionV0);
interface IdentityCreditTransferTransitionV0 {
  identity_id: Identifier;
  recipient_id: Identifier;
  amount: number;
  nonce: IdentityNonce;
  user_fee_increase: UserFeeIncrease;
  // platform_signable exclude_from_sig_hash
  signature_public_key_id: KeyID;
  // platform_signable exclude_from_sig_hash
  signature: BinaryData;
}

// platform_version_path "dpp.state_transition_serialization_versions.identity_credit_withdrawal_state_transition"
export abstract class IdentityCreditWithdrawalTransition {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: IdentityCreditWithdrawalTransition): void;
  static decode(bc: BinCode): IdentityCreditWithdrawalTransition;
}
namespace IdentityCreditWithdrawalTransition {
  const V0: (f0: IdentityCreditWithdrawalTransitionV0) => IdentityCreditWithdrawalTransition.V0;
  interface V0 extends IdentityCreditWithdrawalTransition {
    [0]: IdentityCreditWithdrawalTransitionV0;
  }
  const V1: (f0: IdentityCreditWithdrawalTransitionV1) => IdentityCreditWithdrawalTransition.V1;
  interface V1 extends IdentityCreditWithdrawalTransition {
    [0]: IdentityCreditWithdrawalTransitionV1;
  }
}

const IdentityCreditWithdrawalTransitionV0 : BinCodeable<IdentityCreditWithdrawalTransitionV0> & ((data: {
  identity_id: Identifier,
  amount: number,
  core_fee_per_byte: number,
  pooling: Pooling,
  output_script: CoreScript,
  nonce: IdentityNonce,
  user_fee_increase: UserFeeIncrease,
    // platform_signable exclude_from_sig_hash
  signature_public_key_id: KeyID,
    // platform_signable exclude_from_sig_hash
  signature: BinaryData,
}) => IdentityCreditWithdrawalTransitionV0);
interface IdentityCreditWithdrawalTransitionV0 {
  identity_id: Identifier;
  amount: number;
  core_fee_per_byte: number;
  pooling: Pooling;
  output_script: CoreScript;
  nonce: IdentityNonce;
  user_fee_increase: UserFeeIncrease;
  // platform_signable exclude_from_sig_hash
  signature_public_key_id: KeyID;
  // platform_signable exclude_from_sig_hash
  signature: BinaryData;
}

const IdentityCreditWithdrawalTransitionV1 : BinCodeable<IdentityCreditWithdrawalTransitionV1> & ((data: {
  identity_id: Identifier,
  amount: number,
  core_fee_per_byte: number,
  pooling: Pooling,
    /**
     * If the send to output script is None, then we send the withdrawal to the address set by core
     */
  output_script?: CoreScript,
  nonce: IdentityNonce,
  user_fee_increase: UserFeeIncrease,
    // platform_signable exclude_from_sig_hash
  signature_public_key_id: KeyID,
    // platform_signable exclude_from_sig_hash
  signature: BinaryData,
}) => IdentityCreditWithdrawalTransitionV1);
interface IdentityCreditWithdrawalTransitionV1 {
  identity_id: Identifier;
  amount: number;
  core_fee_per_byte: number;
  pooling: Pooling;
  /**
   * If the send to output script is None, then we send the withdrawal to the address set by core
   */
  output_script?: CoreScript;
  nonce: IdentityNonce;
  user_fee_increase: UserFeeIncrease;
  // platform_signable exclude_from_sig_hash
  signature_public_key_id: KeyID;
  // platform_signable exclude_from_sig_hash
  signature: BinaryData;
}

export type IdentityNonce = number;

// platform_signable derive_into
export abstract class IdentityPublicKeyInCreation {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: IdentityPublicKeyInCreation): void;
  static decode(bc: BinCode): IdentityPublicKeyInCreation;
}
namespace IdentityPublicKeyInCreation {
  const V0: (f0: IdentityPublicKeyInCreationV0) => IdentityPublicKeyInCreation.V0;
  interface V0 extends IdentityPublicKeyInCreation {
    [0]: IdentityPublicKeyInCreationV0;
  }
}

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
    // platform_signable exclude_from_sig_hash
     */
  signature: BinaryData,
}) => IdentityPublicKeyInCreationV0);
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
  // platform_signable exclude_from_sig_hash
   */
  signature: BinaryData;
}

// platform_version_path_bounds "dpp.state_transition_serialization_versions.identity_top_up_state_transition"
export abstract class IdentityTopUpTransition {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: IdentityTopUpTransition): void;
  static decode(bc: BinCode): IdentityTopUpTransition;
}
namespace IdentityTopUpTransition {
  const V0: (f0: IdentityTopUpTransitionV0) => IdentityTopUpTransition.V0;
  interface V0 extends IdentityTopUpTransition {
    [0]: IdentityTopUpTransitionV0;
  }
}

const IdentityTopUpTransitionV0 : BinCodeable<IdentityTopUpTransitionV0> & ((data: {
  asset_lock_proof: AssetLockProof,
  identity_id: Identifier,
  user_fee_increase: UserFeeIncrease,
    // platform_signable exclude_from_sig_hash
  signature: BinaryData,
}) => IdentityTopUpTransitionV0);
interface IdentityTopUpTransitionV0 {
  asset_lock_proof: AssetLockProof;
  identity_id: Identifier;
  user_fee_increase: UserFeeIncrease;
  // platform_signable exclude_from_sig_hash
  signature: BinaryData;
}

// platform_version_path_bounds "dpp.state_transition_serialization_versions.identity_update_state_transition"
export abstract class IdentityUpdateTransition {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: IdentityUpdateTransition): void;
  static decode(bc: BinCode): IdentityUpdateTransition;
}
namespace IdentityUpdateTransition {
  const V0: (f0: IdentityUpdateTransitionV0) => IdentityUpdateTransition.V0;
  interface V0 extends IdentityUpdateTransition {
    [0]: IdentityUpdateTransitionV0;
  }
}

// platform_signable derive_bincode_with_borrowed_vec
const IdentityUpdateTransitionV0 : BinCodeable<IdentityUpdateTransitionV0> & ((data: {
    /**
     * Unique identifier of the identity to be updated
     */
  identity_id: Identifier,
    /**
     * The revision of the identity after update
     */
  revision: Revision,
    /**
     * Identity nonce for this transition to prevent replay attacks
     */
  nonce: IdentityNonce,
    /**
     * Public Keys to add to the Identity
     * we want to skip serialization of transitions, as we does it manually in `to_object()`  and `to_json()`
    // platform_signable into = "Vec<IdentityPublicKeyInCreationSignable>"
     */
  add_public_keys: IdentityPublicKeyInCreation[],
    /**
     * Identity Public Keys ID's to disable for the Identity
     */
  disable_public_keys: KeyID[],
    /**
     * The fee multiplier
     */
  user_fee_increase: UserFeeIncrease,
    /**
     * The ID of the public key used to sing the State Transition
    // platform_signable exclude_from_sig_hash
     */
  signature_public_key_id: KeyID,
    /**
     * Cryptographic signature of the State Transition
    // platform_signable exclude_from_sig_hash
     */
  signature: BinaryData,
}) => IdentityUpdateTransitionV0);
interface IdentityUpdateTransitionV0 {
  /**
   * Unique identifier of the identity to be updated
   */
  identity_id: Identifier;
  /**
   * The revision of the identity after update
   */
  revision: Revision;
  /**
   * Identity nonce for this transition to prevent replay attacks
   */
  nonce: IdentityNonce;
  /**
   * Public Keys to add to the Identity
   * we want to skip serialization of transitions, as we does it manually in `to_object()`  and `to_json()`
  // platform_signable into = "Vec<IdentityPublicKeyInCreationSignable>"
   */
  add_public_keys: IdentityPublicKeyInCreation[];
  /**
   * Identity Public Keys ID's to disable for the Identity
   */
  disable_public_keys: KeyID[];
  /**
   * The fee multiplier
   */
  user_fee_increase: UserFeeIncrease;
  /**
   * The ID of the public key used to sing the State Transition
  // platform_signable exclude_from_sig_hash
   */
  signature_public_key_id: KeyID;
  /**
   * Cryptographic signature of the State Transition
  // platform_signable exclude_from_sig_hash
   */
  signature: BinaryData;
}

export type InstantAssetLockProof = RawInstantLockProof;

export type KeyID = number;

// allow non_camel_case_types
// repr u8
export abstract class KeyType {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: KeyType): void;
  static decode(bc: BinCode): KeyType;
}
namespace KeyType {
  // default
}

// platform_version_path_bounds "dpp.state_transition_serialization_versions.masternode_vote_state_transition"
export abstract class MasternodeVoteTransition {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: MasternodeVoteTransition): void;
  static decode(bc: BinCode): MasternodeVoteTransition;
}
namespace MasternodeVoteTransition {
  const V0: (f0: MasternodeVoteTransitionV0) => MasternodeVoteTransition.V0;
  interface V0 extends MasternodeVoteTransition {
    [0]: MasternodeVoteTransitionV0;
  }
}

const MasternodeVoteTransitionV0 : BinCodeable<MasternodeVoteTransitionV0> & ((data: {
  pro_tx_hash: Identifier,
  voter_identity_id: Identifier,
  vote: Vote,
  nonce: IdentityNonce,
    // platform_signable exclude_from_sig_hash
  signature_public_key_id: KeyID,
    // platform_signable exclude_from_sig_hash
  signature: BinaryData,
}) => MasternodeVoteTransitionV0);
interface MasternodeVoteTransitionV0 {
  pro_tx_hash: Identifier;
  voter_identity_id: Identifier;
  vote: Vote;
  nonce: IdentityNonce;
  // platform_signable exclude_from_sig_hash
  signature_public_key_id: KeyID;
  // platform_signable exclude_from_sig_hash
  signature: BinaryData;
}

/**
 * A reference to a transaction output.
 */
const OutPoint : BinCodeable<OutPoint> & ((data: {
    /**
     * The referenced transaction's txid.
     */
  txid: Txid,
    /**
     * The index of the referenced output in its transaction's vout.
     */
  vout: number,
}) => OutPoint);
interface OutPoint {
  /**
   * The referenced transaction's txid.
   */
  txid: Txid;
  /**
   * The index of the referenced output in its transaction's vout.
   */
  vout: number;
}

// repr u8
export abstract class Pooling {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: Pooling): void;
  static decode(bc: BinCode): Pooling;
}
namespace Pooling {
  // default
}

export type PrivateEncryptedNote = [RootEncryptionKeyIndex, DerivationEncryptionKeyIndex, Uint8Array];

// repr u8
export abstract class Purpose {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: Purpose): void;
  static decode(bc: BinCode): Purpose;
}
namespace Purpose {
  /**
   * at least one authentication key must be registered for all security levels
  // default
   */
  /**
   * this key cannot be used for signing documents
   */
  /**
   * this key cannot be used for signing documents
   */
  /**
   * this key is used to sign credit transfer and withdrawal state transitions
   */
  /**
   * this key cannot be used for signing documents
   */
  /**
   * this key cannot be used for signing documents
   */
  /**
   * this key is used to prove ownership of a masternode or evonode
   */
}

/**
 * A representation of a dynamic value that can handled dynamically
// non_exhaustive
 */
export abstract class Value {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: Value): void;
  static decode(bc: BinCode): Value;
}
namespace Value {
  /**
   * A u128 integer
   */
  const U128: (f0: number) => Value.U128;
  interface U128 extends Value {
    [0]: number;
  }
  /**
   * A i128 integer
   */
  const I128: (f0: number) => Value.I128;
  interface I128 extends Value {
    [0]: number;
  }
  /**
   * A u64 integer
   */
  const U64: (f0: number) => Value.U64;
  interface U64 extends Value {
    [0]: number;
  }
  /**
   * A i64 integer
   */
  const I64: (f0: number) => Value.I64;
  interface I64 extends Value {
    [0]: number;
  }
  /**
   * A u32 integer
   */
  const U32: (f0: number) => Value.U32;
  interface U32 extends Value {
    [0]: number;
  }
  /**
   * A i32 integer
   */
  const I32: (f0: number) => Value.I32;
  interface I32 extends Value {
    [0]: number;
  }
  /**
   * A u16 integer
   */
  const U16: (f0: number) => Value.U16;
  interface U16 extends Value {
    [0]: number;
  }
  /**
   * A i16 integer
   */
  const I16: (f0: number) => Value.I16;
  interface I16 extends Value {
    [0]: number;
  }
  /**
   * A u8 integer
   */
  const U8: (f0: number) => Value.U8;
  interface U8 extends Value {
    [0]: number;
  }
  /**
   * A i8 integer
   */
  const I8: (f0: number) => Value.I8;
  interface I8 extends Value {
    [0]: number;
  }
  /**
   * Bytes
   */
  const Bytes: (f0: Uint8Array) => Value.Bytes;
  interface Bytes extends Value {
    [0]: Uint8Array;
  }
  /**
   * Bytes 20
   */
  const Bytes20: (f0: FixedBytes<20>) => Value.Bytes20;
  interface Bytes20 extends Value {
    [0]: FixedBytes<20>;
  }
  /**
   * Bytes 32
   */
  const Bytes32: (f0: FixedBytes<32>) => Value.Bytes32;
  interface Bytes32 extends Value {
    [0]: FixedBytes<32>;
  }
  /**
   * Bytes 36 : Useful for outpoints
   */
  const Bytes36: (f0: FixedBytes<36>) => Value.Bytes36;
  interface Bytes36 extends Value {
    [0]: FixedBytes<36>;
  }
  /**
   * An enumeration of u8
   */
  const EnumU8: (f0: Uint8Array) => Value.EnumU8;
  interface EnumU8 extends Value {
    [0]: Uint8Array;
  }
  /**
   * An enumeration of strings
   */
  const EnumString: (f0: string[]) => Value.EnumString;
  interface EnumString extends Value {
    [0]: string[];
  }
  /**
   * Identifier
   * The identifier is very similar to bytes, however it is serialized to Base58 when converted
   * to a JSON Value
   */
  const Identifier: (f0: Hash256) => Value.Identifier;
  interface Identifier extends Value {
    [0]: Hash256;
  }
  /**
   * A float
   */
  const Float: (f0: number) => Value.Float;
  interface Float extends Value {
    [0]: number;
  }
  /**
   * A string
   */
  const Text: (f0: string) => Value.Text;
  interface Text extends Value {
    [0]: string;
  }
  /**
   * A boolean
   */
  const Bool: (f0: boolean) => Value.Bool;
  interface Bool extends Value {
    [0]: boolean;
  }
  /**
   * Null
   */
  /**
   * An array
   */
  const Array: (f0: Value[]) => Value.Array;
  interface Array extends Value {
    [0]: Value[];
  }
  /**
   * A map
   */
  const Map: (f0: ValueMap) => Value.Map;
  interface Map extends Value {
    [0]: ValueMap;
  }
}

/**
 * "Raw" instant lock for serialization
 */
const RawInstantLockProof : BinCodeable<RawInstantLockProof> & ((data: {
  instant_lock: BinaryData,
  transaction: BinaryData,
  output_index: number,
}) => RawInstantLockProof);
interface RawInstantLockProof {
  instant_lock: BinaryData;
  transaction: BinaryData;
  output_index: number;
}

export type RecipientKeyIndex = number;

export abstract class ResourceVote {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: ResourceVote): void;
  static decode(bc: BinCode): ResourceVote;
}
namespace ResourceVote {
  const V0: (f0: ResourceVoteV0) => ResourceVote.V0;
  interface V0 extends ResourceVote {
    [0]: ResourceVoteV0;
  }
}

/**
 * A resource votes is a votes determining what we should do with a contested resource.
 * For example Alice and Bob both want the username "Malaka"
 * Some would vote for Alice to get it by putting in her Identifier.
 * Some would vote for Bob to get it by putting in Bob's Identifier.
 * Let's say someone voted, but is now not quite sure of their votes, they can abstain.
 * Lock is there to signal that the shared resource should be given to no one.
 * In this case Malaka might have a bad connotation in Greek, hence some might votes to Lock
 * the name.
 *
 */
export abstract class ResourceVoteChoice {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: ResourceVoteChoice): void;
  static decode(bc: BinCode): ResourceVoteChoice;
}
namespace ResourceVoteChoice {
  const TowardsIdentity: (f0: Identifier) => ResourceVoteChoice.TowardsIdentity;
  interface TowardsIdentity extends ResourceVoteChoice {
    [0]: Identifier;
  }
  // default
}

const ResourceVoteV0 : BinCodeable<ResourceVoteV0> & ((data: {
  vote_poll: VotePoll,
  resource_vote_choice: ResourceVoteChoice,
}) => ResourceVoteV0);
interface ResourceVoteV0 {
  vote_poll: VotePoll;
  resource_vote_choice: ResourceVoteChoice;
}

export type Revision = number;

export abstract class RewardDistributionType {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: RewardDistributionType): void;
  static decode(bc: BinCode): RewardDistributionType;
}
namespace RewardDistributionType {
  /**
   * An amount of tokens is emitted every n blocks.
   * The start and end are included if set.
   * If start is not set then it will start at the height of the block when the data contract
   * is registered.
   */
  const BlockBasedDistribution: (data: {
    interval: BlockHeightInterval,
    function: DistributionFunction,
  }) => RewardDistributionType.BlockBasedDistribution;
  interface BlockBasedDistribution extends RewardDistributionType {
    interval: BlockHeightInterval;
    function: DistributionFunction;
  }
  /**
   * An amount of tokens is emitted every amount of time given.
   * The start and end are included if set.
   * If start is not set then it will start at the time of the block when the data contract
   * is registered.
   */
  const TimeBasedDistribution: (data: {
    interval: TimestampMillisInterval,
    function: DistributionFunction,
  }) => RewardDistributionType.TimeBasedDistribution;
  interface TimeBasedDistribution extends RewardDistributionType {
    interval: TimestampMillisInterval;
    function: DistributionFunction;
  }
  /**
   * An amount of tokens is emitted every amount of epochs.
   * The start and end are included if set.
   * If start is not set then it will start at the epoch of the block when the data contract
   * is registered. A distribution would happen at the start of the following epoch, even if it
   * is just 1 block later.
   */
  const EpochBasedDistribution: (data: {
    interval: EpochInterval,
    function: DistributionFunction,
  }) => RewardDistributionType.EpochBasedDistribution;
  interface EpochBasedDistribution extends RewardDistributionType {
    interval: EpochInterval;
    function: DistributionFunction;
  }
}

export type RootEncryptionKeyIndex = number;

/**
 * An owned, growable script.
 *
 * `ScriptBuf` is the most common script type that has the ownership over the contents of the
 * script. It has a close relationship with its borrowed counterpart, [`Script`].
 *
 * Just as other similar types, this implements [`Deref`], so [deref coercions] apply. Also note
 * that all the safety/validity restrictions that apply to [`Script`] apply to `ScriptBuf` as well.
 *
 * [deref coercions]: https://doc.rust-lang.org/std/ops/trait.Deref.html#more-on-deref-coercion
 */
const ScriptBuf : BinCodeable<ScriptBuf> & ((
    f0: Uint8Array,
) => ScriptBuf);
interface ScriptBuf {
  [0]: Uint8Array;
}

// repr u8
export abstract class SecurityLevel {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: SecurityLevel): void;
  static decode(bc: BinCode): SecurityLevel;
}
namespace SecurityLevel {
  // default
}

export type SenderKeyIndex = number;

export type SharedEncryptedNote = [SenderKeyIndex, RecipientKeyIndex, Uint8Array];

export abstract class StateTransition {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: StateTransition): void;
  static decode(bc: BinCode): StateTransition;
}
namespace StateTransition {
  const DataContractCreate: (f0: DataContractCreateTransition) => StateTransition.DataContractCreate;
  interface DataContractCreate extends StateTransition {
    [0]: DataContractCreateTransition;
  }
  const DataContractUpdate: (f0: DataContractUpdateTransition) => StateTransition.DataContractUpdate;
  interface DataContractUpdate extends StateTransition {
    [0]: DataContractUpdateTransition;
  }
  const Batch: (f0: BatchTransition) => StateTransition.Batch;
  interface Batch extends StateTransition {
    [0]: BatchTransition;
  }
  const IdentityCreate: (f0: IdentityCreateTransition) => StateTransition.IdentityCreate;
  interface IdentityCreate extends StateTransition {
    [0]: IdentityCreateTransition;
  }
  const IdentityTopUp: (f0: IdentityTopUpTransition) => StateTransition.IdentityTopUp;
  interface IdentityTopUp extends StateTransition {
    [0]: IdentityTopUpTransition;
  }
  const IdentityCreditWithdrawal: (f0: IdentityCreditWithdrawalTransition) => StateTransition.IdentityCreditWithdrawal;
  interface IdentityCreditWithdrawal extends StateTransition {
    [0]: IdentityCreditWithdrawalTransition;
  }
  const IdentityUpdate: (f0: IdentityUpdateTransition) => StateTransition.IdentityUpdate;
  interface IdentityUpdate extends StateTransition {
    [0]: IdentityUpdateTransition;
  }
  const IdentityCreditTransfer: (f0: IdentityCreditTransferTransition) => StateTransition.IdentityCreditTransfer;
  interface IdentityCreditTransfer extends StateTransition {
    [0]: IdentityCreditTransferTransition;
  }
  const MasternodeVote: (f0: MasternodeVoteTransition) => StateTransition.MasternodeVote;
  interface MasternodeVote extends StateTransition {
    [0]: MasternodeVoteTransition;
  }
}

/**
 * The Storage Key requirements
// repr u8
 */
export abstract class StorageKeyRequirements {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: StorageKeyRequirements): void;
  static decode(bc: BinCode): StorageKeyRequirements;
}
namespace StorageKeyRequirements {
}

export type TimestampMillis = number;

export type TimestampMillisInterval = number;

export type TokenAmount = number;

export abstract class TokenBaseTransition {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: TokenBaseTransition): void;
  static decode(bc: BinCode): TokenBaseTransition;
}
namespace TokenBaseTransition {
  const V0: (f0: TokenBaseTransitionV0) => TokenBaseTransition.V0;
  interface V0 extends TokenBaseTransition {
    [0]: TokenBaseTransitionV0;
  }
}

const TokenBaseTransitionV0 : BinCodeable<TokenBaseTransitionV0> & ((data: {
  identity_contract_nonce: IdentityNonce,
    /**
     * ID of the token within the contract
     */
  token_contract_position: number,
    /**
     * Data contract ID generated from the data contract's `owner_id` and `entropy`
     */
  data_contract_id: Identifier,
    /**
     * Token ID generated from the data contract ID and the token position
     */
  token_id: Identifier,
    /**
     * Using group multi party rules for authentication
     */
  using_group_info?: GroupStateTransitionInfo,
}) => TokenBaseTransitionV0);
interface TokenBaseTransitionV0 {
  identity_contract_nonce: IdentityNonce;
  /**
   * ID of the token within the contract
   */
  token_contract_position: number;
  /**
   * Data contract ID generated from the data contract's `owner_id` and `entropy`
   */
  data_contract_id: Identifier;
  /**
   * Token ID generated from the data contract ID and the token position
   */
  token_id: Identifier;
  /**
   * Using group multi party rules for authentication
   */
  using_group_info?: GroupStateTransitionInfo;
}

export abstract class TokenBurnTransition {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: TokenBurnTransition): void;
  static decode(bc: BinCode): TokenBurnTransition;
}
namespace TokenBurnTransition {
  const V0: (f0: TokenBurnTransitionV0) => TokenBurnTransition.V0;
  interface V0 extends TokenBurnTransition {
    [0]: TokenBurnTransitionV0;
  }
}

const TokenBurnTransitionV0 : BinCodeable<TokenBurnTransitionV0> & ((data: {
    /**
     * Document Base Transition
     */
  base: TokenBaseTransition,
    /**
     * How much should we burn
     */
  burn_amount: number,
    /**
     * The public note
     */
  public_note?: string,
}) => TokenBurnTransitionV0);
interface TokenBurnTransitionV0 {
  /**
   * Document Base Transition
   */
  base: TokenBaseTransition;
  /**
   * How much should we burn
   */
  burn_amount: number;
  /**
   * The public note
   */
  public_note?: string;
}

export abstract class TokenClaimTransition {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: TokenClaimTransition): void;
  static decode(bc: BinCode): TokenClaimTransition;
}
namespace TokenClaimTransition {
  const V0: (f0: TokenClaimTransitionV0) => TokenClaimTransition.V0;
  interface V0 extends TokenClaimTransition {
    [0]: TokenClaimTransitionV0;
  }
}

const TokenClaimTransitionV0 : BinCodeable<TokenClaimTransitionV0> & ((data: {
    /**
     * Document Base Transition
     */
  base: TokenBaseTransition,
    /**
     * The type of distribution we are targeting
     */
  distribution_type: TokenDistributionType,
    /**
     * A public note, this will only get saved to the state if we are using a historical contract
     */
  public_note?: string,
}) => TokenClaimTransitionV0);
interface TokenClaimTransitionV0 {
  /**
   * Document Base Transition
   */
  base: TokenBaseTransition;
  /**
   * The type of distribution we are targeting
   */
  distribution_type: TokenDistributionType;
  /**
   * A public note, this will only get saved to the state if we are using a historical contract
   */
  public_note?: string;
}

export abstract class TokenConfigUpdateTransition {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: TokenConfigUpdateTransition): void;
  static decode(bc: BinCode): TokenConfigUpdateTransition;
}
namespace TokenConfigUpdateTransition {
  const V0: (f0: TokenConfigUpdateTransitionV0) => TokenConfigUpdateTransition.V0;
  interface V0 extends TokenConfigUpdateTransition {
    [0]: TokenConfigUpdateTransitionV0;
  }
}

const TokenConfigUpdateTransitionV0 : BinCodeable<TokenConfigUpdateTransitionV0> & ((data: {
    /**
     * Document Base Transition
     */
  base: TokenBaseTransition,
    /**
     * Updated token configuration item
     */
  update_token_configuration_item: TokenConfigurationChangeItem,
    /**
     * The public note
     */
  public_note?: string,
}) => TokenConfigUpdateTransitionV0);
interface TokenConfigUpdateTransitionV0 {
  /**
   * Document Base Transition
   */
  base: TokenBaseTransition;
  /**
   * Updated token configuration item
   */
  update_token_configuration_item: TokenConfigurationChangeItem;
  /**
   * The public note
   */
  public_note?: string;
}

export abstract class TokenConfiguration {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: TokenConfiguration): void;
  static decode(bc: BinCode): TokenConfiguration;
}
namespace TokenConfiguration {
  const V0: (f0: TokenConfigurationV0) => TokenConfiguration.V0;
  interface V0 extends TokenConfiguration {
    [0]: TokenConfigurationV0;
  }
}

export abstract class TokenConfigurationChangeItem {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: TokenConfigurationChangeItem): void;
  static decode(bc: BinCode): TokenConfigurationChangeItem;
}
namespace TokenConfigurationChangeItem {
  // default
  const Conventions: (f0: TokenConfigurationConvention) => TokenConfigurationChangeItem.Conventions;
  interface Conventions extends TokenConfigurationChangeItem {
    [0]: TokenConfigurationConvention;
  }
  const ConventionsControlGroup: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.ConventionsControlGroup;
  interface ConventionsControlGroup extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  const ConventionsAdminGroup: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.ConventionsAdminGroup;
  interface ConventionsAdminGroup extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  const MaxSupply: (f0: Option<TokenAmount>) => TokenConfigurationChangeItem.MaxSupply;
  interface MaxSupply extends TokenConfigurationChangeItem {
    [0]: Option<TokenAmount>;
  }
  const MaxSupplyControlGroup: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.MaxSupplyControlGroup;
  interface MaxSupplyControlGroup extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  const MaxSupplyAdminGroup: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.MaxSupplyAdminGroup;
  interface MaxSupplyAdminGroup extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  const PerpetualDistribution: (f0: Option<TokenPerpetualDistribution>) => TokenConfigurationChangeItem.PerpetualDistribution;
  interface PerpetualDistribution extends TokenConfigurationChangeItem {
    [0]: Option<TokenPerpetualDistribution>;
  }
  const PerpetualDistributionControlGroup: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.PerpetualDistributionControlGroup;
  interface PerpetualDistributionControlGroup extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  const PerpetualDistributionAdminGroup: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.PerpetualDistributionAdminGroup;
  interface PerpetualDistributionAdminGroup extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  const NewTokensDestinationIdentity: (f0: Option<Identifier>) => TokenConfigurationChangeItem.NewTokensDestinationIdentity;
  interface NewTokensDestinationIdentity extends TokenConfigurationChangeItem {
    [0]: Option<Identifier>;
  }
  const NewTokensDestinationIdentityControlGroup: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.NewTokensDestinationIdentityControlGroup;
  interface NewTokensDestinationIdentityControlGroup extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  const NewTokensDestinationIdentityAdminGroup: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.NewTokensDestinationIdentityAdminGroup;
  interface NewTokensDestinationIdentityAdminGroup extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  const MintingAllowChoosingDestination: (f0: boolean) => TokenConfigurationChangeItem.MintingAllowChoosingDestination;
  interface MintingAllowChoosingDestination extends TokenConfigurationChangeItem {
    [0]: boolean;
  }
  const MintingAllowChoosingDestinationControlGroup: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.MintingAllowChoosingDestinationControlGroup;
  interface MintingAllowChoosingDestinationControlGroup extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  const MintingAllowChoosingDestinationAdminGroup: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.MintingAllowChoosingDestinationAdminGroup;
  interface MintingAllowChoosingDestinationAdminGroup extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  const ManualMinting: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.ManualMinting;
  interface ManualMinting extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  const ManualMintingAdminGroup: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.ManualMintingAdminGroup;
  interface ManualMintingAdminGroup extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  const ManualBurning: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.ManualBurning;
  interface ManualBurning extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  const ManualBurningAdminGroup: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.ManualBurningAdminGroup;
  interface ManualBurningAdminGroup extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  const Freeze: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.Freeze;
  interface Freeze extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  const FreezeAdminGroup: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.FreezeAdminGroup;
  interface FreezeAdminGroup extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  const Unfreeze: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.Unfreeze;
  interface Unfreeze extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  const UnfreezeAdminGroup: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.UnfreezeAdminGroup;
  interface UnfreezeAdminGroup extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  const DestroyFrozenFunds: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.DestroyFrozenFunds;
  interface DestroyFrozenFunds extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  const DestroyFrozenFundsAdminGroup: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.DestroyFrozenFundsAdminGroup;
  interface DestroyFrozenFundsAdminGroup extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  const EmergencyAction: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.EmergencyAction;
  interface EmergencyAction extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  const EmergencyActionAdminGroup: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.EmergencyActionAdminGroup;
  interface EmergencyActionAdminGroup extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  const MainControlGroup: (f0: Option<GroupContractPosition>) => TokenConfigurationChangeItem.MainControlGroup;
  interface MainControlGroup extends TokenConfigurationChangeItem {
    [0]: Option<GroupContractPosition>;
  }
}

export abstract class TokenConfigurationConvention {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: TokenConfigurationConvention): void;
  static decode(bc: BinCode): TokenConfigurationConvention;
}
namespace TokenConfigurationConvention {
  const V0: (f0: TokenConfigurationConventionV0) => TokenConfigurationConvention.V0;
  interface V0 extends TokenConfigurationConvention {
    [0]: TokenConfigurationConventionV0;
  }
}

const TokenConfigurationConventionV0 : BinCodeable<TokenConfigurationConventionV0> & ((data: {
    /**
     * Localizations for the token name.
     * The key must be a ISO 639 2-chars language code
     */
  localizations: Map<string, TokenConfigurationLocalization>,
  decimals: number,
}) => TokenConfigurationConventionV0);
interface TokenConfigurationConventionV0 {
  /**
   * Localizations for the token name.
   * The key must be a ISO 639 2-chars language code
   */
  localizations: Map<string, TokenConfigurationLocalization>;
  decimals: number;
}

export abstract class TokenConfigurationLocalization {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: TokenConfigurationLocalization): void;
  static decode(bc: BinCode): TokenConfigurationLocalization;
}
namespace TokenConfigurationLocalization {
  const V0: (f0: TokenConfigurationLocalizationV0) => TokenConfigurationLocalization.V0;
  interface V0 extends TokenConfigurationLocalization {
    [0]: TokenConfigurationLocalizationV0;
  }
}

const TokenConfigurationLocalizationV0 : BinCodeable<TokenConfigurationLocalizationV0> & ((data: {
  should_capitalize: boolean,
  singular_form: string,
  plural_form: string,
}) => TokenConfigurationLocalizationV0);
interface TokenConfigurationLocalizationV0 {
  should_capitalize: boolean;
  singular_form: string;
  plural_form: string;
}

const TokenConfigurationV0 : BinCodeable<TokenConfigurationV0> & ((data: {
  conventions: TokenConfigurationConvention,
    /**
     * Who can change the conventions
     */
  conventions_change_rules: ChangeControlRules,
    /**
     * The supply at the creation of the token
     */
  base_supply: TokenAmount,
    /**
     * The maximum supply the token can ever have
     */
  max_supply?: TokenAmount,
    /**
     * The rules for keeping history.
     */
  keeps_history: TokenKeepsHistoryRules,
    /**
     * Do we start off as paused, meaning that we can not transfer till we unpause.
     */
  start_as_paused: boolean,
    /**
     * Who can change the max supply
     * Even if set no one can ever change this under the base supply
     */
  max_supply_change_rules: ChangeControlRules,
    /**
     * The distribution rules for the token
     */
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
interface TokenConfigurationV0 {
  conventions: TokenConfigurationConvention;
  /**
   * Who can change the conventions
   */
  conventions_change_rules: ChangeControlRules;
  /**
   * The supply at the creation of the token
   */
  base_supply: TokenAmount;
  /**
   * The maximum supply the token can ever have
   */
  max_supply?: TokenAmount;
  /**
   * The rules for keeping history.
   */
  keeps_history: TokenKeepsHistoryRules;
  /**
   * Do we start off as paused, meaning that we can not transfer till we unpause.
   */
  start_as_paused: boolean;
  /**
   * Who can change the max supply
   * Even if set no one can ever change this under the base supply
   */
  max_supply_change_rules: ChangeControlRules;
  /**
   * The distribution rules for the token
   */
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

export type TokenContractPosition = number;

export abstract class TokenDestroyFrozenFundsTransition {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: TokenDestroyFrozenFundsTransition): void;
  static decode(bc: BinCode): TokenDestroyFrozenFundsTransition;
}
namespace TokenDestroyFrozenFundsTransition {
  const V0: (f0: TokenDestroyFrozenFundsTransitionV0) => TokenDestroyFrozenFundsTransition.V0;
  interface V0 extends TokenDestroyFrozenFundsTransition {
    [0]: TokenDestroyFrozenFundsTransitionV0;
  }
}

const TokenDestroyFrozenFundsTransitionV0 : BinCodeable<TokenDestroyFrozenFundsTransitionV0> & ((data: {
    /**
     * Document Base Transition
     */
  base: TokenBaseTransition,
    /**
     * The identity id of the account whose balance should be destroyed
     */
  frozen_identity_id: Identifier,
    /**
     * The public note
     */
  public_note?: string,
}) => TokenDestroyFrozenFundsTransitionV0);
interface TokenDestroyFrozenFundsTransitionV0 {
  /**
   * Document Base Transition
   */
  base: TokenBaseTransition;
  /**
   * The identity id of the account whose balance should be destroyed
   */
  frozen_identity_id: Identifier;
  /**
   * The public note
   */
  public_note?: string;
}

export abstract class TokenDistributionRecipient {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: TokenDistributionRecipient): void;
  static decode(bc: BinCode): TokenDistributionRecipient;
}
namespace TokenDistributionRecipient {
  /**
   * Distribute to the contract Owner
  // default
   */
  /**
   * Distribute to a single identity
   */
  const Identity: (f0: Identifier) => TokenDistributionRecipient.Identity;
  interface Identity extends TokenDistributionRecipient {
    [0]: Identifier;
  }
  /**
   * Distribute tokens by participation
   * This distribution can only happen when choosing epoch based distribution
   */
}

export abstract class TokenDistributionRules {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: TokenDistributionRules): void;
  static decode(bc: BinCode): TokenDistributionRules;
}
namespace TokenDistributionRules {
  const V0: (f0: TokenDistributionRulesV0) => TokenDistributionRules.V0;
  interface V0 extends TokenDistributionRules {
    [0]: TokenDistributionRulesV0;
  }
}

const TokenDistributionRulesV0 : BinCodeable<TokenDistributionRulesV0> & ((data: {
  perpetual_distribution?: TokenPerpetualDistribution,
  perpetual_distribution_rules: ChangeControlRules,
  pre_programmed_distribution?: TokenPreProgrammedDistribution,
  new_tokens_destination_identity?: Identifier,
  new_tokens_destination_identity_rules: ChangeControlRules,
  minting_allow_choosing_destination: boolean,
  minting_allow_choosing_destination_rules: ChangeControlRules,
}) => TokenDistributionRulesV0);
interface TokenDistributionRulesV0 {
  perpetual_distribution?: TokenPerpetualDistribution;
  perpetual_distribution_rules: ChangeControlRules;
  pre_programmed_distribution?: TokenPreProgrammedDistribution;
  new_tokens_destination_identity?: Identifier;
  new_tokens_destination_identity_rules: ChangeControlRules;
  minting_allow_choosing_destination: boolean;
  minting_allow_choosing_destination_rules: ChangeControlRules;
}

/**
 * Represents the type of token distribution.
 *
 * - `PreProgrammed`: A scheduled distribution with predefined rules.
 * - `Perpetual`: A continuous or recurring distribution.
 */
export abstract class TokenDistributionType {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: TokenDistributionType): void;
  static decode(bc: BinCode): TokenDistributionType;
}
namespace TokenDistributionType {
  /**
   * A pre-programmed distribution scheduled for a specific time.
  // default
   */
  /**
   * A perpetual distribution that occurs at regular intervals.
   */
}

export abstract class TokenEmergencyAction {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: TokenEmergencyAction): void;
  static decode(bc: BinCode): TokenEmergencyAction;
}
namespace TokenEmergencyAction {
  // default
}

export abstract class TokenEmergencyActionTransition {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: TokenEmergencyActionTransition): void;
  static decode(bc: BinCode): TokenEmergencyActionTransition;
}
namespace TokenEmergencyActionTransition {
  const V0: (f0: TokenEmergencyActionTransitionV0) => TokenEmergencyActionTransition.V0;
  interface V0 extends TokenEmergencyActionTransition {
    [0]: TokenEmergencyActionTransitionV0;
  }
}

const TokenEmergencyActionTransitionV0 : BinCodeable<TokenEmergencyActionTransitionV0> & ((data: {
    /**
     * Document Base Transition
     */
  base: TokenBaseTransition,
    /**
     * The emergency action
     */
  emergency_action: TokenEmergencyAction,
    /**
     * The public note
     */
  public_note?: string,
}) => TokenEmergencyActionTransitionV0);
interface TokenEmergencyActionTransitionV0 {
  /**
   * Document Base Transition
   */
  base: TokenBaseTransition;
  /**
   * The emergency action
   */
  emergency_action: TokenEmergencyAction;
  /**
   * The public note
   */
  public_note?: string;
}

export abstract class TokenFreezeTransition {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: TokenFreezeTransition): void;
  static decode(bc: BinCode): TokenFreezeTransition;
}
namespace TokenFreezeTransition {
  const V0: (f0: TokenFreezeTransitionV0) => TokenFreezeTransition.V0;
  interface V0 extends TokenFreezeTransition {
    [0]: TokenFreezeTransitionV0;
  }
}

const TokenFreezeTransitionV0 : BinCodeable<TokenFreezeTransitionV0> & ((data: {
    /**
     * Document Base Transition
     */
  base: TokenBaseTransition,
    /**
     * The identity that we are freezing
     */
  identity_to_freeze_id: Identifier,
    /**
     * The public note
     */
  public_note?: string,
}) => TokenFreezeTransitionV0);
interface TokenFreezeTransitionV0 {
  /**
   * Document Base Transition
   */
  base: TokenBaseTransition;
  /**
   * The identity that we are freezing
   */
  identity_to_freeze_id: Identifier;
  /**
   * The public note
   */
  public_note?: string;
}

export abstract class TokenKeepsHistoryRules {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: TokenKeepsHistoryRules): void;
  static decode(bc: BinCode): TokenKeepsHistoryRules;
}
namespace TokenKeepsHistoryRules {
  const V0: (f0: TokenKeepsHistoryRulesV0) => TokenKeepsHistoryRules.V0;
  interface V0 extends TokenKeepsHistoryRules {
    [0]: TokenKeepsHistoryRulesV0;
  }
}

/**
 * The rules for keeping a ledger as documents of token events.
 * Config update, Destroying Frozen Funds, Emergency Action,
 * Pre Programmed Token Release always require an entry to the ledger
 */
const TokenKeepsHistoryRulesV0 : BinCodeable<TokenKeepsHistoryRulesV0> & ((data: {
    /**
     * Whether transfer history is recorded.
     */
  keeps_transfer_history: boolean,
    /**
     * Whether freezing history is recorded.
     */
  keeps_freezing_history: boolean,
    /**
     * Whether minting history is recorded.
     */
  keeps_minting_history: boolean,
    /**
     * Whether burning history is recorded.
     */
  keeps_burning_history: boolean,
}) => TokenKeepsHistoryRulesV0);
interface TokenKeepsHistoryRulesV0 {
  /**
   * Whether transfer history is recorded.
   */
  keeps_transfer_history: boolean;
  /**
   * Whether freezing history is recorded.
   */
  keeps_freezing_history: boolean;
  /**
   * Whether minting history is recorded.
   */
  keeps_minting_history: boolean;
  /**
   * Whether burning history is recorded.
   */
  keeps_burning_history: boolean;
}

export abstract class TokenMintTransition {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: TokenMintTransition): void;
  static decode(bc: BinCode): TokenMintTransition;
}
namespace TokenMintTransition {
  const V0: (f0: TokenMintTransitionV0) => TokenMintTransition.V0;
  interface V0 extends TokenMintTransition {
    [0]: TokenMintTransitionV0;
  }
}

const TokenMintTransitionV0 : BinCodeable<TokenMintTransitionV0> & ((data: {
    /**
     * Document Base Transition
     */
  base: TokenBaseTransition,
    /**
     * Who should we issue the token to? If this is not set then we issue to the identity set in
     * contract settings. If such an operation is allowed.
     */
  issued_to_identity_id?: Identifier,
    /**
     * How much should we issue
     */
  amount: number,
    /**
     * The public note
     */
  public_note?: string,
}) => TokenMintTransitionV0);
interface TokenMintTransitionV0 {
  /**
   * Document Base Transition
   */
  base: TokenBaseTransition;
  /**
   * Who should we issue the token to? If this is not set then we issue to the identity set in
   * contract settings. If such an operation is allowed.
   */
  issued_to_identity_id?: Identifier;
  /**
   * How much should we issue
   */
  amount: number;
  /**
   * The public note
   */
  public_note?: string;
}

export abstract class TokenPerpetualDistribution {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: TokenPerpetualDistribution): void;
  static decode(bc: BinCode): TokenPerpetualDistribution;
}
namespace TokenPerpetualDistribution {
  const V0: (f0: TokenPerpetualDistributionV0) => TokenPerpetualDistribution.V0;
  interface V0 extends TokenPerpetualDistribution {
    [0]: TokenPerpetualDistributionV0;
  }
}

const TokenPerpetualDistributionV0 : BinCodeable<TokenPerpetualDistributionV0> & ((data: {
    /**
     * The distribution type that the token will use
     */
  distribution_type: RewardDistributionType,
    /**
     * The recipient type
     */
  distribution_recipient: TokenDistributionRecipient,
}) => TokenPerpetualDistributionV0);
interface TokenPerpetualDistributionV0 {
  /**
   * The distribution type that the token will use
   */
  distribution_type: RewardDistributionType;
  /**
   * The recipient type
   */
  distribution_recipient: TokenDistributionRecipient;
}

export abstract class TokenPreProgrammedDistribution {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: TokenPreProgrammedDistribution): void;
  static decode(bc: BinCode): TokenPreProgrammedDistribution;
}
namespace TokenPreProgrammedDistribution {
  const V0: (f0: TokenPreProgrammedDistributionV0) => TokenPreProgrammedDistribution.V0;
  interface V0 extends TokenPreProgrammedDistribution {
    [0]: TokenPreProgrammedDistributionV0;
  }
}

const TokenPreProgrammedDistributionV0 : BinCodeable<TokenPreProgrammedDistributionV0> & ((data: {
  distributions: Map<TimestampMillis, Map<Identifier, TokenAmount>>,
}) => TokenPreProgrammedDistributionV0);
interface TokenPreProgrammedDistributionV0 {
  distributions: Map<TimestampMillis, Map<Identifier, TokenAmount>>;
}

export abstract class TokenTransferTransition {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: TokenTransferTransition): void;
  static decode(bc: BinCode): TokenTransferTransition;
}
namespace TokenTransferTransition {
  const V0: (f0: TokenTransferTransitionV0) => TokenTransferTransition.V0;
  interface V0 extends TokenTransferTransition {
    [0]: TokenTransferTransitionV0;
  }
}

const TokenTransferTransitionV0 : BinCodeable<TokenTransferTransitionV0> & ((data: {
  base: TokenBaseTransition,
  amount: number,
  recipient_id: Identifier,
    /**
     * The public note
     */
  public_note?: string,
    /**
     * An optional shared encrypted note
     */
  shared_encrypted_note?: SharedEncryptedNote,
    /**
     * An optional private encrypted note
     */
  private_encrypted_note?: PrivateEncryptedNote,
}) => TokenTransferTransitionV0);
interface TokenTransferTransitionV0 {
  base: TokenBaseTransition;
  amount: number;
  recipient_id: Identifier;
  /**
   * The public note
   */
  public_note?: string;
  /**
   * An optional shared encrypted note
   */
  shared_encrypted_note?: SharedEncryptedNote;
  /**
   * An optional private encrypted note
   */
  private_encrypted_note?: PrivateEncryptedNote;
}

export abstract class TokenTransition {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: TokenTransition): void;
  static decode(bc: BinCode): TokenTransition;
}
namespace TokenTransition {
  const Burn: (f0: TokenBurnTransition) => TokenTransition.Burn;
  interface Burn extends TokenTransition {
    [0]: TokenBurnTransition;
  }
  const Mint: (f0: TokenMintTransition) => TokenTransition.Mint;
  interface Mint extends TokenTransition {
    [0]: TokenMintTransition;
  }
  const Transfer: (f0: TokenTransferTransition) => TokenTransition.Transfer;
  interface Transfer extends TokenTransition {
    [0]: TokenTransferTransition;
  }
  const Freeze: (f0: TokenFreezeTransition) => TokenTransition.Freeze;
  interface Freeze extends TokenTransition {
    [0]: TokenFreezeTransition;
  }
  const Unfreeze: (f0: TokenUnfreezeTransition) => TokenTransition.Unfreeze;
  interface Unfreeze extends TokenTransition {
    [0]: TokenUnfreezeTransition;
  }
  const DestroyFrozenFunds: (f0: TokenDestroyFrozenFundsTransition) => TokenTransition.DestroyFrozenFunds;
  interface DestroyFrozenFunds extends TokenTransition {
    [0]: TokenDestroyFrozenFundsTransition;
  }
  const Claim: (f0: TokenClaimTransition) => TokenTransition.Claim;
  interface Claim extends TokenTransition {
    [0]: TokenClaimTransition;
  }
  const EmergencyAction: (f0: TokenEmergencyActionTransition) => TokenTransition.EmergencyAction;
  interface EmergencyAction extends TokenTransition {
    [0]: TokenEmergencyActionTransition;
  }
  const ConfigUpdate: (f0: TokenConfigUpdateTransition) => TokenTransition.ConfigUpdate;
  interface ConfigUpdate extends TokenTransition {
    [0]: TokenConfigUpdateTransition;
  }
}

export abstract class TokenUnfreezeTransition {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: TokenUnfreezeTransition): void;
  static decode(bc: BinCode): TokenUnfreezeTransition;
}
namespace TokenUnfreezeTransition {
  const V0: (f0: TokenUnfreezeTransitionV0) => TokenUnfreezeTransition.V0;
  interface V0 extends TokenUnfreezeTransition {
    [0]: TokenUnfreezeTransitionV0;
  }
}

const TokenUnfreezeTransitionV0 : BinCodeable<TokenUnfreezeTransitionV0> & ((data: {
    /**
     * Document Base Transition
     */
  base: TokenBaseTransition,
    /**
     * The identity that we are freezing
     */
  frozen_identity_id: Identifier,
    /**
     * The public note
     */
  public_note?: string,
}) => TokenUnfreezeTransitionV0);
interface TokenUnfreezeTransitionV0 {
  /**
   * Document Base Transition
   */
  base: TokenBaseTransition;
  /**
   * The identity that we are freezing
   */
  frozen_identity_id: Identifier;
  /**
   * The public note
   */
  public_note?: string;
}

/**
 * A transaction output, which defines new coins to be created from old ones.
 */
const TxOut : BinCodeable<TxOut> & ((data: {
    /**
     * The value of the output, in satoshis.
     */
  value: number,
    /**
     * The script which must be satisfied for the output to be spent.
     */
  script_pubkey: ScriptBuf,
}) => TxOut);
interface TxOut {
  /**
   * The value of the output, in satoshis.
   */
  value: number;
  /**
   * The script which must be satisfied for the output to be spent.
   */
  script_pubkey: ScriptBuf;
}

/**
 * A dash transaction hash/transaction ID.
 */
const Txid : BinCodeable<Txid> & ((
    f0: Hash,
) => Txid);
interface Txid {
  [0]: Hash;
}

export type UserFeeIncrease = number;

export type ValueMap = [Value, Value][];

export abstract class Vote {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: Vote): void;
  static decode(bc: BinCode): Vote;
}
namespace Vote {
  const ResourceVote: (f0: ResourceVote) => Vote.ResourceVote;
  interface ResourceVote extends Vote {
    [0]: ResourceVote;
  }
}

export abstract class VotePoll {
  #private;
  static name: string;
  static isValid(v: unknown): boolean;
  static encode(bc: BinCode, v: VotePoll): void;
  static decode(bc: BinCode): VotePoll;
}
namespace VotePoll {
  const ContestedDocumentResourceVotePoll: (f0: ContestedDocumentResourceVotePoll) => VotePoll.ContestedDocumentResourceVotePoll;
  interface ContestedDocumentResourceVotePoll extends VotePoll {
    [0]: ContestedDocumentResourceVotePoll;
  }
}


}
