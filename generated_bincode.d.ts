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
   * A fixed amount of tokens is emitted for each period in the reward distribution type.
   *
   * # Formula
   * - `f(x) = n`
   *
   * # Use Case
   * - Simplicity
   * - Stable reward emissions
   *
   * # Example
   * - If we emit 5 tokens per block, and 3 blocks have passed, the `Release` call will release 15 tokens.
   */
  const FixedAmount: (data: {
    n: TokenAmount,
  }) => DistributionFunction.FixedAmount;
  interface FixedAmount extends DistributionFunction {
    n: TokenAmount;
  }
  /**
   * The amount of tokens decreases in predefined steps at fixed intervals.
   *
   * # Formula
   * - `f(x) = n * (1 - decrease_per_interval)^(x / step_count)`
   *
   * # Use Case
   * - Mimics Bitcoin and Dash Core emission models
   * - Encourages early participation by providing higher rewards initially
   *
   * # Example
   * - Bitcoin: A 50% decrease every 210,000 blocks (~4 years)
   * - Dash: A ~7% decrease every 210,000 blocks (~1 year)
   */
  const StepDecreasingAmount: (data: {
    step_count: number,
    decrease_per_interval: number,
    n: TokenAmount,
  }) => DistributionFunction.StepDecreasingAmount;
  interface StepDecreasingAmount extends DistributionFunction {
    step_count: number;
    decrease_per_interval: number;
    n: TokenAmount;
  }
  /**
   * A linear function emits tokens in increasing or decreasing amounts over time (integer precision).
   *
   * # Formula
   * - `f(x) = a * x + b`
   * - Where `a` is the slope (rate of change) and `b` is the initial value.
   *
   * # Description
   * - `a > 0`: Tokens increase over time.
   * - `a < 0`: Tokens decrease over time.
   * - `b` is the starting emission value.
   *
   * # Use Case
   * - Incentivize early adopters with higher rewards (`a < 0`).
   * - Gradually increase emissions to match ecosystem growth (`a > 0`).
   *
   * # Example
   * - Start with 50 tokens and increase by 10 tokens per epoch: `f(x) = 10x + 50`.
   */
  const LinearInteger: (data: {
    a: number,
    b: SignedTokenAmount,
  }) => DistributionFunction.LinearInteger;
  interface LinearInteger extends DistributionFunction {
    a: number;
    b: SignedTokenAmount;
  }
  /**
   * A linear function emits tokens in increasing or decreasing amounts over time (floating-point precision).
   *
   * # Formula
   * - `f(x) = a * x + b`
   * - Where `a` is the slope (rate of change) and `b` is the initial value.
   *
   * # Description
   * - `a > 0`: Tokens increase over time.
   * - `a < 0`: Tokens decrease over time.
   * - `b` is the starting emission value.
   *
   * # Use Case
   * - Similar to `LinearInteger`, but supports fractional rates of change.
   *
   * # Example
   * - Start with 50 tokens and increase by 0.5 tokens per epoch: `f(x) = 0.5x + 50`.
   */
  const LinearFloat: (data: {
    a: number,
    b: SignedTokenAmount,
  }) => DistributionFunction.LinearFloat;
  interface LinearFloat extends DistributionFunction {
    a: number;
    b: SignedTokenAmount;
  }
  /**
   * A polynomial function emits tokens according to a quadratic or cubic curve (integer precision).
   *
   * # Formula
   * - `f(x) = a * x^n + b`
   * - Where `n` is the degree of the polynomial, `a` is the scaling factor, and `b` is the base amount.
   *
   * # Description
   * - Higher-degree polynomials allow for flexible emission curves.
   * - Use for growth or decay patterns that aren't linear.
   *
   * # Use Case
   * - Reward systems with diminishing returns as time progresses.
   *
   * # Example
   * - Emit rewards based on a quadratic curve: `f(x) = 2x^2 + 20`.
   */
  const PolynomialInteger: (data: {
    a: number,
    n: number,
    b: SignedTokenAmount,
  }) => DistributionFunction.PolynomialInteger;
  interface PolynomialInteger extends DistributionFunction {
    a: number;
    n: number;
    b: SignedTokenAmount;
  }
  /**
   * A polynomial function emits tokens according to a quadratic or cubic curve (floating-point precision).
   *
   * # Formula
   * - `f(x) = a * x^n + b`
   * - Where `n` is the degree of the polynomial, `a` is the scaling factor, and `b` is the base amount.
   *
   * # Description
   * - Similar to `PolynomialInteger`, but supports fractional scaling and degrees.
   *
   * # Example
   * - Emit rewards based on a cubic curve with fractional growth: `f(x) = 0.5x^3 + 20`.
   */
  const PolynomialFloat: (data: {
    a: number,
    n: number,
    b: SignedTokenAmount,
  }) => DistributionFunction.PolynomialFloat;
  interface PolynomialFloat extends DistributionFunction {
    a: number;
    n: number;
    b: SignedTokenAmount;
  }
  /**
   * An exponential function emits tokens based on exponential growth or decay.
   *
   * # Formula
   * - `f(x) = a * e^(b * x) + c`
   * - Where `a` is the scaling factor, `b` controls the growth/decay rate, and `c` is an offset.
   *
   * # Description
   * - Exponential growth: `b > 0`, emissions increase rapidly.
   * - Exponential decay: `b < 0`, emissions decrease rapidly.
   * - Useful for early incentivization or ecosystem maturity.
   *
   * # Use Case
   * - Reward mechanisms where early contributors get larger rewards.
   *
   * # Example
   * - Start with 100 tokens and halve emissions every interval, with a minimum of 5 tokens: `f(x) = 100 * e^(-0.693 * x) + 5`.
   */
  const Exponential: (data: {
    a: number,
    b: number,
    c: SignedTokenAmount,
  }) => DistributionFunction.Exponential;
  interface Exponential extends DistributionFunction {
    a: number;
    b: number;
    c: SignedTokenAmount;
  }
  /**
   * A logarithmic function emits tokens based on logarithmic growth.
   *
   * # Formula
   * - `f(x) = a * log_b(x) + c`
   * - Where `a` is the scaling factor, `b` is the logarithm base, and `c` is an offset.
   *
   * # Description
   * - Growth starts quickly but slows as `x` increases.
   * - Suitable for sustainable emissions over long periods.
   *
   * # Use Case
   * - Gradual emissions tapering to balance supply and demand.
   *
   * # Example
   * - Emit rewards using a log base-2 curve: `f(x) = 20 * log_2(x) + 5`.
   */
  const Logarithmic: (data: {
    a: number,
    b: number,
    c: SignedTokenAmount,
  }) => DistributionFunction.Logarithmic;
  interface Logarithmic extends DistributionFunction {
    a: number;
    b: number;
    c: SignedTokenAmount;
  }
  /**
   * A stepwise function emits tokens in fixed amounts for predefined intervals.
   *
   * # Description
   * - Emissions remain constant within each step.
   * - Steps define specific time intervals or milestones.
   *
   * # Use Case
   * - Adjust rewards at specific milestones.
   *
   * # Example
   * - Emit 100 tokens per block for the first 1000 blocks, then 50 tokens thereafter.
   */
  const Stepwise: (f0: [number, TokenAmount][]) => DistributionFunction.Stepwise;
  interface Stepwise extends DistributionFunction {
    [0]: [number, TokenAmount][];
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
   * An amount of tokens is emitted every n blocks
   */
  const BlockBasedDistribution: (f0: BlockHeightInterval, f1: TokenAmount, f2: DistributionFunction) => RewardDistributionType.BlockBasedDistribution;
  interface BlockBasedDistribution extends RewardDistributionType {
    [0]: BlockHeightInterval;
    [1]: TokenAmount;
    [2]: DistributionFunction;
  }
  /**
   * An amount of tokens is emitted every amount of time given
   */
  const TimeBasedDistribution: (f0: TimestampMillisInterval, f1: TokenAmount, f2: DistributionFunction) => RewardDistributionType.TimeBasedDistribution;
  interface TimeBasedDistribution extends RewardDistributionType {
    [0]: TimestampMillisInterval;
    [1]: TokenAmount;
    [2]: DistributionFunction;
  }
  /**
   * An amount of tokens is emitted every amount of epochs
   */
  const EpochBasedDistribution: (f0: EpochInterval, f1: TokenAmount, f2: DistributionFunction) => RewardDistributionType.EpochBasedDistribution;
  interface EpochBasedDistribution extends RewardDistributionType {
    [0]: EpochInterval;
    [1]: TokenAmount;
    [2]: DistributionFunction;
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

export type SignedTokenAmount = number;

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
  localizations: Map<string, TokenConfigurationLocalizationsV0>,
  decimals: number,
}) => TokenConfigurationConventionV0);
interface TokenConfigurationConventionV0 {
  localizations: Map<string, TokenConfigurationLocalizationsV0>;
  decimals: number;
}

const TokenConfigurationLocalizationsV0 : BinCodeable<TokenConfigurationLocalizationsV0> & ((data: {
  should_capitalize: boolean,
  singular_form: string,
  plural_form: string,
}) => TokenConfigurationLocalizationsV0);
interface TokenConfigurationLocalizationsV0 {
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
     * Do we keep history, default is true.
     */
  keeps_history: boolean,
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
   * Do we keep history, default is true.
   */
  keeps_history: boolean;
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
