import { BinCode, BinCodeable, VARIANTS } from "../src/bincode.ts";
import { Option, FixedBytes, Hash, SocketAddr, Transaction } from "../src/bincode_types.ts";
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

/** allow clippy :: large_enum_variant */
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
  /** @ignore @internal */
  [VARIANTS]: typeof AssetLockProof.variants;
  /** @ignore */
  static variants: {
    Instant: typeof AssetLockProof.Instant,
    Chain: typeof AssetLockProof.Chain,
  };
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

/**
 * An Asset Unlock Base payload. This is the base payload of the Asset Unlock. In order to make
 *  it a full payload the request info should be added.
 */
interface AssetUnlockBasePayload {
  /** The payload protocol version, is currently expected to be 0. */
  version: number;
  /** The index of the unlock transaction. It gets bumped on each transaction */
  index: bigint;
  /** The fee used in Duffs (Satoshis) */
  fee: number;
}
/** @ignore */
const AssetUnlockBasePayload : BinCodeable<AssetUnlockBasePayload> & ((data: {
  /** The payload protocol version, is currently expected to be 0. */
  version: number,
  /** The index of the unlock transaction. It gets bumped on each transaction */
  index: bigint,
  /** The fee used in Duffs (Satoshis) */
  fee: number,
}) => AssetUnlockBasePayload);

/**
 * A Credit Withdrawal payload. This is contained as the payload of a credit withdrawal special
 *  transaction.
 *  The Credit Withdrawal Special transaction and this payload is described in the Asset Lock DIP2X
 *  (todo:update this).
 *  The Credit Withdrawal Payload is signed by a quorum.
 * 
 *  Transaction using it have no inputs. Hence the proof of validity lies solely on the BLS signature.
 */
interface AssetUnlockPayload {
  /**
   * The base information about the asset unlock. This base information is the information that
   *  should be put into a queue.
   */
  base: AssetUnlockBasePayload;
  /**
   * The request information. This should be added to the unlock transaction as it is being sent
   *  to be signed.
   */
  request_info: AssetUnlockRequestInfo;
  /** The threshold signature. This should be returned by the consensus engine. */
  quorum_sig: BLSSignature;
}
/** @ignore */
const AssetUnlockPayload : BinCodeable<AssetUnlockPayload> & ((data: {
  /**
   * The base information about the asset unlock. This base information is the information that
   *  should be put into a queue.
   */
  base: AssetUnlockBasePayload,
  /**
   * The request information. This should be added to the unlock transaction as it is being sent
   *  to be signed.
   */
  request_info: AssetUnlockRequestInfo,
  /** The threshold signature. This should be returned by the consensus engine. */
  quorum_sig: BLSSignature,
}) => AssetUnlockPayload);

/**
 * An asset unlock request info
 *  This is the information about the signing quorum
 *  The request height should be the height at which the specified quorum is active on core.
 */
interface AssetUnlockRequestInfo {
  /**
   * The core request height of the transaction. This should match a period where the quorum_hash
   *  is still active
   */
  request_height: number;
  /** The quorum hash. This is the block hash when the quorum was created. */
  quorum_hash: QuorumHash;
}
/** @ignore */
const AssetUnlockRequestInfo : BinCodeable<AssetUnlockRequestInfo> & ((data: {
  /**
   * The core request height of the transaction. This should match a period where the quorum_hash
   *  is still active
   */
  request_height: number,
  /** The quorum hash. This is the block hash when the quorum was created. */
  quorum_hash: QuorumHash,
}) => AssetUnlockRequestInfo);

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
  /** @ignore @internal */
  [VARIANTS]: typeof AuthorizedActionTakers.variants;
  /** @ignore */
  static variants: {
    NoOne: typeof AuthorizedActionTakers.NoOne,
    ContractOwner: typeof AuthorizedActionTakers.ContractOwner,
    Identity: typeof AuthorizedActionTakers.Identity,
    MainGroup: typeof AuthorizedActionTakers.MainGroup,
    Group: typeof AuthorizedActionTakers.Group,
  };
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

/**
 * A BLS Public key is 48 bytes in the scheme used for Dash Core
 * attr since (1.48) , derive (PartialEq , Eq , Ord , PartialOrd , Hash)
 */
interface BLSPublicKey {
  [0]: FixedBytes<48>;
}
/** @ignore */
const BLSPublicKey : BinCodeable<BLSPublicKey> & ((
    f0: FixedBytes<48>,
) => BLSPublicKey);

/**
 * A BLS Signature is 96 bytes in the scheme used for Dash Core
 * attr since (1.48) , derive (PartialEq , Eq , Ord , PartialOrd , Hash)
 */
interface BLSSignature {
  [0]: FixedBytes<96>;
}
/** @ignore */
const BLSSignature : BinCodeable<BLSSignature> & ((
    f0: FixedBytes<96>,
) => BLSSignature);

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
  /** @ignore @internal */
  [VARIANTS]: typeof BatchTransition.variants;
  /** @ignore */
  static variants: {
    V0: typeof BatchTransition.V0,
    V1: typeof BatchTransition.V1,
  };
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
  /** @ignore @internal */
  [VARIANTS]: typeof BatchedTransition.variants;
  /** @ignore */
  static variants: {
    Document: typeof BatchedTransition.Document,
    Token: typeof BatchedTransition.Token,
  };
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

/** A dash block hash. */
interface BlockHash {
  [0]: Hash;
}
/** @ignore */
const BlockHash : BinCodeable<BlockHash> & ((
    f0: Hash,
) => BlockHash);

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
  /** @ignore @internal */
  [VARIANTS]: typeof ChangeControlRules.variants;
  /** @ignore */
  static variants: {
    V0: typeof ChangeControlRules.V0,
  };
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

/**
 * A Coinbase payload. This is contained as the payload of a coinbase special transaction.
 *  The Coinbase payload is described in DIP4.
 */
interface CoinbasePayload {
  version: number;
  height: number;
  merkle_root_masternode_list: MerkleRootMasternodeList;
  merkle_root_quorums: MerkleRootQuorums;
  best_cl_height?: number;
  best_cl_signature?: BLSSignature;
  asset_locked_amount?: bigint;
}
/** @ignore */
const CoinbasePayload : BinCodeable<CoinbasePayload> & ((data: {
  version: number,
  height: number,
  merkle_root_masternode_list: MerkleRootMasternodeList,
  merkle_root_quorums: MerkleRootQuorums,
  best_cl_height?: number,
  best_cl_signature?: BLSSignature,
  asset_locked_amount?: bigint,
}) => CoinbasePayload);

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
  /** @ignore @internal */
  [VARIANTS]: typeof ContractBounds.variants;
  /** @ignore */
  static variants: {
    SingleContract: typeof ContractBounds.SingleContract,
    SingleContractDocumentType: typeof ContractBounds.SingleContractDocumentType,
  };
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
  /** @ignore @internal */
  [VARIANTS]: typeof DataContractConfig.variants;
  /** @ignore */
  static variants: {
    V0: typeof DataContractConfig.V0,
    V1: typeof DataContractConfig.V1,
  };
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
  /** @ignore @internal */
  [VARIANTS]: typeof DataContractCreateTransition.variants;
  /** @ignore */
  static variants: {
    V0: typeof DataContractCreateTransition.V0,
  };
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
  /** @ignore @internal */
  [VARIANTS]: typeof DataContractInSerializationFormat.variants;
  /** @ignore */
  static variants: {
    V0: typeof DataContractInSerializationFormat.V0,
    V1: typeof DataContractInSerializationFormat.V1,
  };
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
  /** The contract's keywords for searching */
  keywords: string[];
  /** The contract's description */
  description?: string;
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
  /** The contract's keywords for searching */
  keywords: string[],
  /** The contract's description */
  description?: string,
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
  /** @ignore @internal */
  [VARIANTS]: typeof DataContractUpdateTransition.variants;
  /** @ignore */
  static variants: {
    V0: typeof DataContractUpdateTransition.V0,
  };
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
  /** @ignore @internal */
  [VARIANTS]: typeof DistributionFunction.variants;
  /** @ignore */
  static variants: {
    FixedAmount: typeof DistributionFunction.FixedAmount,
    Random: typeof DistributionFunction.Random,
    StepDecreasingAmount: typeof DistributionFunction.StepDecreasingAmount,
    Stepwise: typeof DistributionFunction.Stepwise,
    Linear: typeof DistributionFunction.Linear,
    Polynomial: typeof DistributionFunction.Polynomial,
    Exponential: typeof DistributionFunction.Exponential,
    Logarithmic: typeof DistributionFunction.Logarithmic,
    InvertedLogarithmic: typeof DistributionFunction.InvertedLogarithmic,
  };
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
   *  For `x <= s`, `f(x) = n`
   * 
   *  # Parameters
   *  - `step_count`: The number of periods between each step.
   *  - `decrease_per_interval_numerator` and `decrease_per_interval_denominator`: Define the reduction factor per step.
   *  - `start_decreasing_offset`: Optional start period offset (e.g., start block or time). If not provided, the contract creation start is used.
   *      If this is provided before this number we give out the distribution start amount every interval.
   *  - `max_interval_count`: The maximum amount of intervals there can be. Can be up to 1024.
   *      !!!Very important!!! -> This will default to 128 is default if not set.
   *      This means that after 128 cycles we will be distributing trailing_distribution_interval_amount per interval.
   *  - `distribution_start_amount`: The initial token emission.
   *  - `trailing_distribution_interval_amount`: The token emission after all decreasing intervals.
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
    start_decreasing_offset?: bigint;
    max_interval_count?: number;
    distribution_start_amount: TokenAmount;
    trailing_distribution_interval_amount: TokenAmount;
    min_value?: bigint;
  }
  const StepDecreasingAmount: (data: {
    step_count: number,
    decrease_per_interval_numerator: number,
    decrease_per_interval_denominator: number,
    start_decreasing_offset?: bigint,
    max_interval_count?: number,
    distribution_start_amount: TokenAmount,
    trailing_distribution_interval_amount: TokenAmount,
    min_value?: bigint,
  }) => DistributionFunction.StepDecreasingAmount;
  /**
   * Emits tokens in fixed amounts for predefined intervals (steps).
   * 
   *  # Details
   *  - Within each step, the emission remains constant.
   *  - The keys in the `BTreeMap` represent the starting period for each interval,
   *    and the corresponding values are the fixed token amounts to emit during that interval.
   *  - VERY IMPORTANT: the steps are the amount of intervals, not the time or the block count.
   *    So if you have step 5 with interval 10 using blocks that's 50 blocks.
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
   *  f(x) = (a * (x - start_step) / d) + starting_amount
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
   *  f(x) = (a * e^(m * (x - s + o) / n)) / d + b
   *  ```
   * 
   *  # Parameters
   *  - `a`: The scaling factor.
   *  - `m` and `n`: Define the exponent rate (with `m > 0` for growth and `m < 0` for decay).
   *  - `d`: A divisor used to scale the exponential term.
   *  - `s`: Optional start period offset. If not set, the contract creation start is assumed.
   *  - `o`: An offset for the exp function, this is useful if s is in None.
   *  - `b`: An offset added to the result.
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
   *  - **Parameters**: `a = 500`, `m = -3`, `n = 100`, `d = 20`, `b = 10`
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
    b: TokenAmount;
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
    b: TokenAmount,
    min_value?: bigint,
    max_value?: bigint,
  }) => DistributionFunction.Exponential;
  /**
   * Emits tokens following a natural logarithmic (ln) function.
   * 
   *  # Formula
   *  The emission at period `x` is computed as:
   * 
   *  ```text
   *  f(x) = (a * ln(m * (x - s + o) / n)) / d + b
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
   *    f(x) = (a * ln(m * (x - s + o) / n)) / d + b
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
   *    f(x) = (100 * ln(2 * (x + 1) / 1)) / 10 + 50
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
   * Emits tokens following an inverted natural logarithmic function.
   * 
   *  # Formula
   *  The emission at period `x` is given by:
   * 
   *  ```text
   *  f(x) = (a * ln( n / (m * (x - s + o)) )) / d + b
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
   *    ```text
   *    f(x) = 10000 * ln(5000 / x)
   *    ```
   *  - Values: a = 10000 n = 5000 m = 1 o = 0 b = 0 d = 0
   *            y
   *            ↑
   *           10000 |*
   *            9000 | *
   *            8000 |  *
   *            7000 |   *
   *            6000 |    *
   *            5000 |     *
   *            4000 |       *
   *            3000 |         *
   *            2000 |           *
   *            1000 |              *
   *               0 +-------------------*----------→ x
   *                   0     2000   4000   6000   8000
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
  /** @ignore @internal */
  [VARIANTS]: typeof DocumentBaseTransition.variants;
  /** @ignore */
  static variants: {
    V0: typeof DocumentBaseTransition.V0,
    V1: typeof DocumentBaseTransition.V1,
  };
}
namespace DocumentBaseTransition {
  /** @function */
  interface V0 extends DocumentBaseTransition {
    [0]: DocumentBaseTransitionV0;
  }
  /** @ignore */
  const V0: (f0: DocumentBaseTransitionV0) => DocumentBaseTransition.V0;
  /** @function */
  interface V1 extends DocumentBaseTransition {
    [0]: DocumentBaseTransitionV1;
  }
  /** @ignore */
  const V1: (f0: DocumentBaseTransitionV1) => DocumentBaseTransition.V1;
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

interface DocumentBaseTransitionV1 {
  /** The document ID */
  id: Identifier;
  identity_contract_nonce: IdentityNonce;
  /** Name of document type found int the data contract associated with the `data_contract_id` */
  document_type_name: string;
  /** Data contract ID generated from the data contract's `owner_id` and `entropy` */
  data_contract_id: Identifier;
  /** An optional Token Payment Info */
  token_payment_info?: TokenPaymentInfo;
}
/** @ignore */
const DocumentBaseTransitionV1 : BinCodeable<DocumentBaseTransitionV1> & ((data: {
  /** The document ID */
  id: Identifier,
  identity_contract_nonce: IdentityNonce,
  /** Name of document type found int the data contract associated with the `data_contract_id` */
  document_type_name: string,
  /** Data contract ID generated from the data contract's `owner_id` and `entropy` */
  data_contract_id: Identifier,
  /** An optional Token Payment Info */
  token_payment_info?: TokenPaymentInfo,
}) => DocumentBaseTransitionV1);

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
  /** @ignore @internal */
  [VARIANTS]: typeof DocumentCreateTransition.variants;
  /** @ignore */
  static variants: {
    V0: typeof DocumentCreateTransition.V0,
  };
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
  /** @ignore @internal */
  [VARIANTS]: typeof DocumentDeleteTransition.variants;
  /** @ignore */
  static variants: {
    V0: typeof DocumentDeleteTransition.V0,
  };
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
  /** @ignore @internal */
  [VARIANTS]: typeof DocumentPurchaseTransition.variants;
  /** @ignore */
  static variants: {
    V0: typeof DocumentPurchaseTransition.V0,
  };
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
  /** @ignore @internal */
  [VARIANTS]: typeof DocumentReplaceTransition.variants;
  /** @ignore */
  static variants: {
    V0: typeof DocumentReplaceTransition.V0,
  };
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
  /** @ignore @internal */
  [VARIANTS]: typeof DocumentTransferTransition.variants;
  /** @ignore */
  static variants: {
    V0: typeof DocumentTransferTransition.V0,
  };
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
  /** @ignore @internal */
  [VARIANTS]: typeof DocumentTransition.variants;
  /** @ignore */
  static variants: {
    Create: typeof DocumentTransition.Create,
    Replace: typeof DocumentTransition.Replace,
    Delete: typeof DocumentTransition.Delete,
    Transfer: typeof DocumentTransition.Transfer,
    UpdatePrice: typeof DocumentTransition.UpdatePrice,
    Purchase: typeof DocumentTransition.Purchase,
  };
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
  /** @ignore @internal */
  [VARIANTS]: typeof DocumentUpdatePriceTransition.variants;
  /** @ignore */
  static variants: {
    V0: typeof DocumentUpdatePriceTransition.V0,
  };
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
export abstract class GasFeesPaidBy {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: GasFeesPaidBy): void;
  /** @ignore */
  static decode(bc: BinCode): GasFeesPaidBy;
  /** @ignore @internal */
  [VARIANTS]: typeof GasFeesPaidBy.variants;
  /** @ignore */
  static variants: {
    DocumentOwner: typeof GasFeesPaidBy.DocumentOwner,
    ContractOwner: typeof GasFeesPaidBy.ContractOwner,
    PreferContractOwner: typeof GasFeesPaidBy.PreferContractOwner,
  };
}
namespace GasFeesPaidBy {
  /**
   * The user pays the gas fees
   * default
   */
  const DocumentOwner: () => GasFeesPaidBy;
  /** The contract owner pays the gas fees */
  const ContractOwner: () => GasFeesPaidBy;
  /**
   * The user is stating his willingness to pay the gas fee if the Contract owner's balance is
   *  insufficient.
   */
  const PreferContractOwner: () => GasFeesPaidBy;
}

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
  /** @ignore @internal */
  [VARIANTS]: typeof Group.variants;
  /** @ignore */
  static variants: {
    V0: typeof Group.V0,
  };
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

/**
 * The identity is not stored inside of drive, because of this, the serialization is mainly for
 *  transport, the serialization of the identity will include the version, so no passthrough or
 *  untagged is needed here
 */
/** @ignore */
export abstract class Identity {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: Identity): void;
  /** @ignore */
  static decode(bc: BinCode): Identity;
  /** @ignore @internal */
  [VARIANTS]: typeof Identity.variants;
  /** @ignore */
  static variants: {
    V0: typeof Identity.V0,
  };
}
namespace Identity {
  /** @function */
  interface V0 extends Identity {
    [0]: IdentityV0;
  }
  /** @ignore */
  const V0: (f0: IdentityV0) => Identity.V0;
}

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
  /** @ignore @internal */
  [VARIANTS]: typeof IdentityCreateTransition.variants;
  /** @ignore */
  static variants: {
    V0: typeof IdentityCreateTransition.V0,
  };
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
  /** @ignore @internal */
  [VARIANTS]: typeof IdentityCreditTransferTransition.variants;
  /** @ignore */
  static variants: {
    V0: typeof IdentityCreditTransferTransition.V0,
  };
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
  /** @ignore @internal */
  [VARIANTS]: typeof IdentityCreditWithdrawalTransition.variants;
  /** @ignore */
  static variants: {
    V0: typeof IdentityCreditWithdrawalTransition.V0,
    V1: typeof IdentityCreditWithdrawalTransition.V1,
  };
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
  /** @ignore @internal */
  [VARIANTS]: typeof IdentityPublicKey.variants;
  /** @ignore */
  static variants: {
    V0: typeof IdentityPublicKey.V0,
  };
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
  /** @ignore @internal */
  [VARIANTS]: typeof IdentityPublicKeyInCreation.variants;
  /** @ignore */
  static variants: {
    V0: typeof IdentityPublicKeyInCreation.V0,
  };
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
  /** @ignore @internal */
  [VARIANTS]: typeof IdentityTopUpTransition.variants;
  /** @ignore */
  static variants: {
    V0: typeof IdentityTopUpTransition.V0,
  };
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
  /** @ignore @internal */
  [VARIANTS]: typeof IdentityUpdateTransition.variants;
  /** @ignore */
  static variants: {
    V0: typeof IdentityUpdateTransition.V0,
  };
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

/**
 * Implement the Identity. Identity is a low-level construct that provides the foundation
 *  for user-facing functionality on the platform
 */
interface IdentityV0 {
  id: Identifier;
  public_keys: Map<KeyID, IdentityPublicKey>;
  balance: bigint;
  revision: Revision;
}
/** @ignore */
const IdentityV0 : BinCodeable<IdentityV0> & ((data: {
  id: Identifier,
  public_keys: Map<KeyID, IdentityPublicKey>,
  balance: bigint,
  revision: Revision,
}) => IdentityV0);

/** A hash of all transaction inputs */
interface InputsHash {
  [0]: Hash;
}
/** @ignore */
const InputsHash : BinCodeable<InputsHash> & ((
    f0: Hash,
) => InputsHash);

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
  /** @ignore @internal */
  [VARIANTS]: typeof KeyType.variants;
  /** @ignore */
  static variants: {
    ECDSA_SECP256K1: typeof KeyType.ECDSA_SECP256K1,
    BLS12_381: typeof KeyType.BLS12_381,
    ECDSA_HASH160: typeof KeyType.ECDSA_HASH160,
    BIP13_SCRIPT_HASH: typeof KeyType.BIP13_SCRIPT_HASH,
    EDDSA_25519_HASH160: typeof KeyType.EDDSA_25519_HASH160,
  };
}
namespace KeyType {
  /** default */
  const ECDSA_SECP256K1: () => KeyType;
  const BLS12_381: () => KeyType;
  const ECDSA_HASH160: () => KeyType;
  const BIP13_SCRIPT_HASH: () => KeyType;
  const EDDSA_25519_HASH160: () => KeyType;
}

/** @ignore */
export abstract class LLMQType {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: LLMQType): void;
  /** @ignore */
  static decode(bc: BinCode): LLMQType;
  /** @ignore @internal */
  [VARIANTS]: typeof LLMQType.variants;
  /** @ignore */
  static variants: {
    LlmqtypeUnknown: typeof LLMQType.LlmqtypeUnknown,
    Llmqtype50_60: typeof LLMQType.Llmqtype50_60,
    Llmqtype400_60: typeof LLMQType.Llmqtype400_60,
    Llmqtype400_85: typeof LLMQType.Llmqtype400_85,
    Llmqtype100_67: typeof LLMQType.Llmqtype100_67,
    Llmqtype60_75: typeof LLMQType.Llmqtype60_75,
    Llmqtype25_67: typeof LLMQType.Llmqtype25_67,
    LlmqtypeTest: typeof LLMQType.LlmqtypeTest,
    LlmqtypeDevnet: typeof LLMQType.LlmqtypeDevnet,
    LlmqtypeTestV17: typeof LLMQType.LlmqtypeTestV17,
    LlmqtypeTestDIP0024: typeof LLMQType.LlmqtypeTestDIP0024,
    LlmqtypeTestInstantSend: typeof LLMQType.LlmqtypeTestInstantSend,
    LlmqtypeDevnetDIP0024: typeof LLMQType.LlmqtypeDevnetDIP0024,
    LlmqtypeTestnetPlatform: typeof LLMQType.LlmqtypeTestnetPlatform,
    LlmqtypeDevnetPlatform: typeof LLMQType.LlmqtypeDevnetPlatform,
  };
}
namespace LLMQType {
  const LlmqtypeUnknown: () => LLMQType;
  const Llmqtype50_60: () => LLMQType;
  const Llmqtype400_60: () => LLMQType;
  const Llmqtype400_85: () => LLMQType;
  const Llmqtype100_67: () => LLMQType;
  const Llmqtype60_75: () => LLMQType;
  const Llmqtype25_67: () => LLMQType;
  const LlmqtypeTest: () => LLMQType;
  const LlmqtypeDevnet: () => LLMQType;
  const LlmqtypeTestV17: () => LLMQType;
  const LlmqtypeTestDIP0024: () => LLMQType;
  const LlmqtypeTestInstantSend: () => LLMQType;
  const LlmqtypeDevnetDIP0024: () => LLMQType;
  const LlmqtypeTestnetPlatform: () => LLMQType;
  const LlmqtypeDevnetPlatform: () => LLMQType;
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
  /** @ignore @internal */
  [VARIANTS]: typeof MasternodeVoteTransition.variants;
  /** @ignore */
  static variants: {
    V0: typeof MasternodeVoteTransition.V0,
  };
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

/**
 * Dash Additions
 * 
 *  The merkle root of the masternode list
 * hash_newtype forward
 */
interface MerkleRootMasternodeList {
  [0]: Hash;
}
/** @ignore */
const MerkleRootMasternodeList : BinCodeable<MerkleRootMasternodeList> & ((
    f0: Hash,
) => MerkleRootMasternodeList);

/**
 * The merkle root of the quorums
 * hash_newtype forward
 */
interface MerkleRootQuorums {
  [0]: Hash;
}
/** @ignore */
const MerkleRootQuorums : BinCodeable<MerkleRootQuorums> & ((
    f0: Hash,
) => MerkleRootQuorums);

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
  /** @ignore @internal */
  [VARIANTS]: typeof Pooling.variants;
  /** @ignore */
  static variants: {
    Never: typeof Pooling.Never,
    IfAvailable: typeof Pooling.IfAvailable,
    Standard: typeof Pooling.Standard,
  };
}
namespace Pooling {
  /** default */
  const Never: () => Pooling;
  const IfAvailable: () => Pooling;
  const Standard: () => Pooling;
}

export type PrivateEncryptedNote = [RootEncryptionKeyIndex, DerivationEncryptionKeyIndex, Uint8Array];

/** @ignore */
export abstract class ProviderMasternodeType {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: ProviderMasternodeType): void;
  /** @ignore */
  static decode(bc: BinCode): ProviderMasternodeType;
  /** @ignore @internal */
  [VARIANTS]: typeof ProviderMasternodeType.variants;
  /** @ignore */
  static variants: {
    Regular: typeof ProviderMasternodeType.Regular,
    HighPerformance: typeof ProviderMasternodeType.HighPerformance,
  };
}
namespace ProviderMasternodeType {
  const Regular: () => ProviderMasternodeType;
  const HighPerformance: () => ProviderMasternodeType;
}

/**
 * A Provider Registration Payload used in a Provider Registration Special Transaction.
 *  This is used to register a Masternode on the network.
 *  The current version is 0.
 *  Interesting Fields:
 *  *Provider type refers to the type of Masternode. Currently only valid value is 0.
 *  *Provider mode refers to the mode of the Masternode. Currently only valid value is 0.
 *  *The collateral outpoint links to a transaction with a 1000 Dash unspent (at registration)
 *  outpoint.
 *  *The operator reward defines the ratio when divided by 10000 of the amount going to the operator.
 *  The max value for the operator reward is 10000.
 *  *The script payout is the script to which one wants to have the masternode pay out.
 *  *The inputs hash is used to guarantee the uniqueness of the payload sig.
 */
interface ProviderRegistrationPayload {
  version: number;
  masternode_type: ProviderMasternodeType;
  masternode_mode: number;
  collateral_outpoint: OutPoint;
  service_address: SocketAddr;
  owner_key_hash: PubkeyHash;
  operator_public_key: BLSPublicKey;
  voting_key_hash: PubkeyHash;
  operator_reward: number;
  script_payout: ScriptBuf;
  inputs_hash: InputsHash;
  signature: Uint8Array;
  platform_node_id?: PubkeyHash;
  platform_p2p_port?: number;
  platform_http_port?: number;
}
/** @ignore */
const ProviderRegistrationPayload : BinCodeable<ProviderRegistrationPayload> & ((data: {
  version: number,
  masternode_type: ProviderMasternodeType,
  masternode_mode: number,
  collateral_outpoint: OutPoint,
  service_address: SocketAddr,
  owner_key_hash: PubkeyHash,
  operator_public_key: BLSPublicKey,
  voting_key_hash: PubkeyHash,
  operator_reward: number,
  script_payout: ScriptBuf,
  inputs_hash: InputsHash,
  signature: Uint8Array,
  platform_node_id?: PubkeyHash,
  platform_p2p_port?: number,
  platform_http_port?: number,
}) => ProviderRegistrationPayload);

/**
 * A Provider Update Registrar Payload used in a Provider Update Registrar Special Transaction.
 *  This is used to update the base aspects a Masternode on the network.
 *  It must be signed by the owner's key that was set at registration.
 */
interface ProviderUpdateRegistrarPayload {
  version: number;
  pro_tx_hash: Txid;
  provider_mode: number;
  operator_public_key: BLSPublicKey;
  voting_key_hash: PubkeyHash;
  script_payout: ScriptBuf;
  inputs_hash: InputsHash;
  payload_sig: Uint8Array;
}
/** @ignore */
const ProviderUpdateRegistrarPayload : BinCodeable<ProviderUpdateRegistrarPayload> & ((data: {
  version: number,
  pro_tx_hash: Txid,
  provider_mode: number,
  operator_public_key: BLSPublicKey,
  voting_key_hash: PubkeyHash,
  script_payout: ScriptBuf,
  inputs_hash: InputsHash,
  payload_sig: Uint8Array,
}) => ProviderUpdateRegistrarPayload);

/**
 * A Provider Update Revocation Payload used in a Provider Update Revocation Special Transaction.
 *  This is used to signal and stop a Masternode from the operator.
 *  It must be signed by the operator's key that was set at registration or registrar update.
 */
interface ProviderUpdateRevocationPayload {
  version: number;
  pro_tx_hash: Txid;
  reason: number;
  inputs_hash: InputsHash;
  payload_sig: BLSSignature;
}
/** @ignore */
const ProviderUpdateRevocationPayload : BinCodeable<ProviderUpdateRevocationPayload> & ((data: {
  version: number,
  pro_tx_hash: Txid,
  reason: number,
  inputs_hash: InputsHash,
  payload_sig: BLSSignature,
}) => ProviderUpdateRevocationPayload);

/**
 * A Provider Update Service Payload used in a Provider Update Service Special Transaction.
 *  This is used to update the operational aspects a Masternode on the network.
 *  It must be signed by the operator's key that was set either at registration or by the last
 *  registrar update of the masternode.
 */
interface ProviderUpdateServicePayload {
  version: number;
  pro_tx_hash: Txid;
  ip_address: bigint;
  port: number;
  script_payout: ScriptBuf;
  inputs_hash: InputsHash;
  payload_sig: BLSSignature;
}
/** @ignore */
const ProviderUpdateServicePayload : BinCodeable<ProviderUpdateServicePayload> & ((data: {
  version: number,
  pro_tx_hash: Txid,
  ip_address: bigint,
  port: number,
  script_payout: ScriptBuf,
  inputs_hash: InputsHash,
  payload_sig: BLSSignature,
}) => ProviderUpdateServicePayload);

/** A hash of a public key. */
interface PubkeyHash {
  [0]: Hash;
}
/** @ignore */
const PubkeyHash : BinCodeable<PubkeyHash> & ((
    f0: Hash,
) => PubkeyHash);

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
  /** @ignore @internal */
  [VARIANTS]: typeof Purpose.variants;
  /** @ignore */
  static variants: {
    AUTHENTICATION: typeof Purpose.AUTHENTICATION,
    ENCRYPTION: typeof Purpose.ENCRYPTION,
    DECRYPTION: typeof Purpose.DECRYPTION,
    TRANSFER: typeof Purpose.TRANSFER,
    SYSTEM: typeof Purpose.SYSTEM,
    VOTING: typeof Purpose.VOTING,
    OWNER: typeof Purpose.OWNER,
  };
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
  /**
   * this key is used to sign credit transfer and withdrawal state transitions
   *  this key can also be used by identities for claims and transfers of tokens
   */
  const TRANSFER: () => Purpose;
  /** this key cannot be used for signing documents */
  const SYSTEM: () => Purpose;
  /** this key cannot be used for signing documents */
  const VOTING: () => Purpose;
  /** this key is used to prove ownership of a masternode or evonode */
  const OWNER: () => Purpose;
}

/**
 * A Quorum Commitment Payload used in a Quorum Commitment Special Transaction.
 *  This is used in the mining phase as described in DIP 6:
 *  [dip-0006.md#7-mining-phase](https://github.com/dashpay/dips/blob/master/dip-0006.md#7-mining-phase).
 * 
 *  Miners take the best final commitment for a DKG session and mine it into a block.
 */
interface QuorumCommitmentPayload {
  version: number;
  height: number;
  finalization_commitment: QuorumEntry;
}
/** @ignore */
const QuorumCommitmentPayload : BinCodeable<QuorumCommitmentPayload> & ((data: {
  version: number,
  height: number,
  finalization_commitment: QuorumEntry,
}) => QuorumCommitmentPayload);

/**
 * A Quorum Finalization Commitment. It is described in the finalization section of DIP6:
 *  [dip-0006.md#6-finalization-phase](https://github.com/dashpay/dips/blob/master/dip-0006.md#6-finalization-phase)
 */
interface QuorumEntry {
  version: number;
  llmq_type: LLMQType;
  quorum_hash: QuorumHash;
  quorum_index?: number;
  signers: boolean[];
  valid_members: boolean[];
  quorum_public_key: BLSPublicKey;
  quorum_vvec_hash: QuorumVVecHash;
  threshold_sig: BLSSignature;
  all_commitment_aggregated_signature: BLSSignature;
}
/** @ignore */
const QuorumEntry : BinCodeable<QuorumEntry> & ((data: {
  version: number,
  llmq_type: LLMQType,
  quorum_hash: QuorumHash,
  quorum_index?: number,
  signers: boolean[],
  valid_members: boolean[],
  quorum_public_key: BLSPublicKey,
  quorum_vvec_hash: QuorumVVecHash,
  threshold_sig: BLSSignature,
  all_commitment_aggregated_signature: BLSSignature,
}) => QuorumEntry);

export type QuorumHash = BlockHash;

/** A hash of a quorum verification vector */
interface QuorumVVecHash {
  [0]: Hash;
}
/** @ignore */
const QuorumVVecHash : BinCodeable<QuorumVVecHash> & ((
    f0: Hash,
) => QuorumVVecHash);

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
  /** @ignore @internal */
  [VARIANTS]: typeof Value.variants;
  /** @ignore */
  static variants: {
    U128: typeof Value.U128,
    I128: typeof Value.I128,
    U64: typeof Value.U64,
    I64: typeof Value.I64,
    U32: typeof Value.U32,
    I32: typeof Value.I32,
    U16: typeof Value.U16,
    I16: typeof Value.I16,
    U8: typeof Value.U8,
    I8: typeof Value.I8,
    Bytes: typeof Value.Bytes,
    Bytes20: typeof Value.Bytes20,
    Bytes32: typeof Value.Bytes32,
    Bytes36: typeof Value.Bytes36,
    EnumU8: typeof Value.EnumU8,
    EnumString: typeof Value.EnumString,
    Identifier: typeof Value.Identifier,
    Float: typeof Value.Float,
    Text: typeof Value.Text,
    Bool: typeof Value.Bool,
    Null: typeof Value.Null,
    Array: typeof Value.Array,
    Map: typeof Value.Map,
  };
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
  /** @ignore @internal */
  [VARIANTS]: typeof ResourceVote.variants;
  /** @ignore */
  static variants: {
    V0: typeof ResourceVote.V0,
  };
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
  /** @ignore @internal */
  [VARIANTS]: typeof ResourceVoteChoice.variants;
  /** @ignore */
  static variants: {
    TowardsIdentity: typeof ResourceVoteChoice.TowardsIdentity,
    Abstain: typeof ResourceVoteChoice.Abstain,
    Lock: typeof ResourceVoteChoice.Lock,
  };
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
  /** @ignore @internal */
  [VARIANTS]: typeof RewardDistributionType.variants;
  /** @ignore */
  static variants: {
    BlockBasedDistribution: typeof RewardDistributionType.BlockBasedDistribution,
    TimeBasedDistribution: typeof RewardDistributionType.TimeBasedDistribution,
    EpochBasedDistribution: typeof RewardDistributionType.EpochBasedDistribution,
  };
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
  /** @ignore @internal */
  [VARIANTS]: typeof SecurityLevel.variants;
  /** @ignore */
  static variants: {
    MASTER: typeof SecurityLevel.MASTER,
    CRITICAL: typeof SecurityLevel.CRITICAL,
    HIGH: typeof SecurityLevel.HIGH,
    MEDIUM: typeof SecurityLevel.MEDIUM,
  };
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
  /** @ignore @internal */
  [VARIANTS]: typeof StateTransition.variants;
  /** @ignore */
  static variants: {
    DataContractCreate: typeof StateTransition.DataContractCreate,
    DataContractUpdate: typeof StateTransition.DataContractUpdate,
    Batch: typeof StateTransition.Batch,
    IdentityCreate: typeof StateTransition.IdentityCreate,
    IdentityTopUp: typeof StateTransition.IdentityTopUp,
    IdentityCreditWithdrawal: typeof StateTransition.IdentityCreditWithdrawal,
    IdentityUpdate: typeof StateTransition.IdentityUpdate,
    IdentityCreditTransfer: typeof StateTransition.IdentityCreditTransfer,
    MasternodeVote: typeof StateTransition.MasternodeVote,
  };
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
  /** @ignore @internal */
  [VARIANTS]: typeof StorageKeyRequirements.variants;
  /** @ignore */
  static variants: {
    Unique: typeof StorageKeyRequirements.Unique,
    Multiple: typeof StorageKeyRequirements.Multiple,
    MultipleReferenceToLatest: typeof StorageKeyRequirements.MultipleReferenceToLatest,
  };
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
  /** @ignore @internal */
  [VARIANTS]: typeof TokenBaseTransition.variants;
  /** @ignore */
  static variants: {
    V0: typeof TokenBaseTransition.V0,
  };
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
  /** @ignore @internal */
  [VARIANTS]: typeof TokenBurnTransition.variants;
  /** @ignore */
  static variants: {
    V0: typeof TokenBurnTransition.V0,
  };
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
  /** @ignore @internal */
  [VARIANTS]: typeof TokenClaimTransition.variants;
  /** @ignore */
  static variants: {
    V0: typeof TokenClaimTransition.V0,
  };
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
  /** @ignore @internal */
  [VARIANTS]: typeof TokenConfigUpdateTransition.variants;
  /** @ignore */
  static variants: {
    V0: typeof TokenConfigUpdateTransition.V0,
  };
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
  /** @ignore @internal */
  [VARIANTS]: typeof TokenConfiguration.variants;
  /** @ignore */
  static variants: {
    V0: typeof TokenConfiguration.V0,
  };
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
  /** @ignore @internal */
  [VARIANTS]: typeof TokenConfigurationChangeItem.variants;
  /** @ignore */
  static variants: {
    TokenConfigurationNoChange: typeof TokenConfigurationChangeItem.TokenConfigurationNoChange,
    Conventions: typeof TokenConfigurationChangeItem.Conventions,
    ConventionsControlGroup: typeof TokenConfigurationChangeItem.ConventionsControlGroup,
    ConventionsAdminGroup: typeof TokenConfigurationChangeItem.ConventionsAdminGroup,
    MaxSupply: typeof TokenConfigurationChangeItem.MaxSupply,
    MaxSupplyControlGroup: typeof TokenConfigurationChangeItem.MaxSupplyControlGroup,
    MaxSupplyAdminGroup: typeof TokenConfigurationChangeItem.MaxSupplyAdminGroup,
    PerpetualDistribution: typeof TokenConfigurationChangeItem.PerpetualDistribution,
    PerpetualDistributionControlGroup: typeof TokenConfigurationChangeItem.PerpetualDistributionControlGroup,
    PerpetualDistributionAdminGroup: typeof TokenConfigurationChangeItem.PerpetualDistributionAdminGroup,
    NewTokensDestinationIdentity: typeof TokenConfigurationChangeItem.NewTokensDestinationIdentity,
    NewTokensDestinationIdentityControlGroup: typeof TokenConfigurationChangeItem.NewTokensDestinationIdentityControlGroup,
    NewTokensDestinationIdentityAdminGroup: typeof TokenConfigurationChangeItem.NewTokensDestinationIdentityAdminGroup,
    MintingAllowChoosingDestination: typeof TokenConfigurationChangeItem.MintingAllowChoosingDestination,
    MintingAllowChoosingDestinationControlGroup: typeof TokenConfigurationChangeItem.MintingAllowChoosingDestinationControlGroup,
    MintingAllowChoosingDestinationAdminGroup: typeof TokenConfigurationChangeItem.MintingAllowChoosingDestinationAdminGroup,
    ManualMinting: typeof TokenConfigurationChangeItem.ManualMinting,
    ManualMintingAdminGroup: typeof TokenConfigurationChangeItem.ManualMintingAdminGroup,
    ManualBurning: typeof TokenConfigurationChangeItem.ManualBurning,
    ManualBurningAdminGroup: typeof TokenConfigurationChangeItem.ManualBurningAdminGroup,
    Freeze: typeof TokenConfigurationChangeItem.Freeze,
    FreezeAdminGroup: typeof TokenConfigurationChangeItem.FreezeAdminGroup,
    Unfreeze: typeof TokenConfigurationChangeItem.Unfreeze,
    UnfreezeAdminGroup: typeof TokenConfigurationChangeItem.UnfreezeAdminGroup,
    DestroyFrozenFunds: typeof TokenConfigurationChangeItem.DestroyFrozenFunds,
    DestroyFrozenFundsAdminGroup: typeof TokenConfigurationChangeItem.DestroyFrozenFundsAdminGroup,
    EmergencyAction: typeof TokenConfigurationChangeItem.EmergencyAction,
    EmergencyActionAdminGroup: typeof TokenConfigurationChangeItem.EmergencyActionAdminGroup,
    MarketplaceTradeMode: typeof TokenConfigurationChangeItem.MarketplaceTradeMode,
    MarketplaceTradeModeControlGroup: typeof TokenConfigurationChangeItem.MarketplaceTradeModeControlGroup,
    MarketplaceTradeModeAdminGroup: typeof TokenConfigurationChangeItem.MarketplaceTradeModeAdminGroup,
    MainControlGroup: typeof TokenConfigurationChangeItem.MainControlGroup,
  };
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
  interface MarketplaceTradeMode extends TokenConfigurationChangeItem {
    [0]: TokenTradeMode;
  }
  /** @ignore */
  const MarketplaceTradeMode: (f0: TokenTradeMode) => TokenConfigurationChangeItem.MarketplaceTradeMode;
  /** @function */
  interface MarketplaceTradeModeControlGroup extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  /** @ignore */
  const MarketplaceTradeModeControlGroup: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.MarketplaceTradeModeControlGroup;
  /** @function */
  interface MarketplaceTradeModeAdminGroup extends TokenConfigurationChangeItem {
    [0]: AuthorizedActionTakers;
  }
  /** @ignore */
  const MarketplaceTradeModeAdminGroup: (f0: AuthorizedActionTakers) => TokenConfigurationChangeItem.MarketplaceTradeModeAdminGroup;
  /** @function */
  interface MainControlGroup extends TokenConfigurationChangeItem {
    [0]: Option<GroupContractPosition>;
  }
  /** @ignore */
  const MainControlGroup: (f0: Option<GroupContractPosition>) => TokenConfigurationChangeItem.MainControlGroup;
}

/**
 * Versioned wrapper for token display conventions.
 * 
 *  `TokenConfigurationConvention` provides a flexible, forward-compatible structure
 *  for representing human-readable metadata about a token, such as localized names
 *  and decimal formatting standards.
 * 
 *  This enum enables evolution of the convention schema over time without breaking
 *  compatibility with older tokens. Each variant defines a specific format version.
 */
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
  /** @ignore @internal */
  [VARIANTS]: typeof TokenConfigurationConvention.variants;
  /** @ignore */
  static variants: {
    V0: typeof TokenConfigurationConvention.V0,
  };
}
namespace TokenConfigurationConvention {
  /**
   * Version 0 of the token convention schema.
   * 
   *  Defines localized names (by ISO 639 language codes) and the number of decimal places
   *  used for displaying token amounts.
   * 
   * @function
   */
  interface V0 extends TokenConfigurationConvention {
    [0]: TokenConfigurationConventionV0;
  }
  /** @ignore */
  const V0: (f0: TokenConfigurationConventionV0) => TokenConfigurationConvention.V0;
}

/**
 * Defines display conventions for a token, including name localization and decimal precision.
 * 
 *  `TokenConfigurationConventionV0` provides human-readable metadata to guide client applications
 *  in rendering token names and formatting token values. This structure is purely informative
 *  and does not affect consensus-critical logic or supply calculations.
 */
interface TokenConfigurationConventionV0 {
  /**
   * A mapping of ISO 639-1 language codes (2-letter lowercase strings) to localized
   *  token names and metadata.
   * 
   *  These localizations enable wallets and dApps to display token information in the
   *  user's preferred language. At least one localization (e.g., English) is strongly recommended.
   */
  localizations: Map<string, TokenConfigurationLocalization>;
  /**
   * The number of decimal places used to represent the token.
   * 
   *  For example, a value of `8` means that one full token is represented as `10^8` base units
   *  (similar to Bitcoin's satoshis or Dash's duffs).
   * 
   *  This value is used by clients to determine formatting and user interface display.
   */
  decimals: number;
}
/** @ignore */
const TokenConfigurationConventionV0 : BinCodeable<TokenConfigurationConventionV0> & ((data: {
  /**
   * A mapping of ISO 639-1 language codes (2-letter lowercase strings) to localized
   *  token names and metadata.
   * 
   *  These localizations enable wallets and dApps to display token information in the
   *  user's preferred language. At least one localization (e.g., English) is strongly recommended.
   */
  localizations: Map<string, TokenConfigurationLocalization>,
  /**
   * The number of decimal places used to represent the token.
   * 
   *  For example, a value of `8` means that one full token is represented as `10^8` base units
   *  (similar to Bitcoin's satoshis or Dash's duffs).
   * 
   *  This value is used by clients to determine formatting and user interface display.
   */
  decimals: number,
}) => TokenConfigurationConventionV0);

/**
 * Versioned wrapper for token name localization data.
 * 
 *  `TokenConfigurationLocalization` allows extensibility for future schema upgrades
 *  while preserving backward compatibility. Each variant represents a specific format
 *  version for localization information.
 * 
 *  This structure is used to map language codes to localized token names in a flexible,
 *  forward-compatible manner.
 */
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
  /** @ignore @internal */
  [VARIANTS]: typeof TokenConfigurationLocalization.variants;
  /** @ignore */
  static variants: {
    V0: typeof TokenConfigurationLocalization.V0,
  };
}
namespace TokenConfigurationLocalization {
  /**
   * Version 0 of the token localization schema.
   * 
   *  Defines basic capitalization preference, singular form, and plural form
   *  for displaying token names.
   * 
   * @function
   */
  interface V0 extends TokenConfigurationLocalization {
    [0]: TokenConfigurationLocalizationV0;
  }
  /** @ignore */
  const V0: (f0: TokenConfigurationLocalizationV0) => TokenConfigurationLocalization.V0;
}

/**
 * Defines the localized naming format for a token in a specific language.
 * 
 *  `TokenConfigurationLocalizationV0` enables tokens to present user-friendly names
 *  across different locales. This information is not used for validation or consensus
 *  but enhances UX by allowing consistent display in multilingual interfaces.
 */
interface TokenConfigurationLocalizationV0 {
  /**
   * Indicates whether the token name should be capitalized when displayed.
   * 
   *  This is a stylistic hint for clients (e.g., "Dash" vs. "dash") and is typically
   *  applied to both singular and plural forms unless overridden.
   */
  should_capitalize: boolean;
  /**
   * The singular form of the token name in the target language.
   * 
   *  Example: "Dash", "Dollar", or "Token".
   */
  singular_form: string;
  /**
   * The plural form of the token name in the target language.
   * 
   *  Example: "Dash", "Dollars", or "Tokens".
   */
  plural_form: string;
}
/** @ignore */
const TokenConfigurationLocalizationV0 : BinCodeable<TokenConfigurationLocalizationV0> & ((data: {
  /**
   * Indicates whether the token name should be capitalized when displayed.
   * 
   *  This is a stylistic hint for clients (e.g., "Dash" vs. "dash") and is typically
   *  applied to both singular and plural forms unless overridden.
   */
  should_capitalize: boolean,
  /**
   * The singular form of the token name in the target language.
   * 
   *  Example: "Dash", "Dollar", or "Token".
   */
  singular_form: string,
  /**
   * The plural form of the token name in the target language.
   * 
   *  Example: "Dash", "Dollars", or "Tokens".
   */
  plural_form: string,
}) => TokenConfigurationLocalizationV0);

/**
 * Defines the complete configuration for a version 0 token contract.
 * 
 *  `TokenConfigurationV0` encapsulates all metadata, control rules, supply settings,
 *  and governance constraints used to initialize and manage a token instance on Platform.
 *  This structure serves as the core representation of a token's logic, permissions,
 *  and capabilities.
 * 
 *  This configuration is designed to be deterministic and versioned for compatibility
 *  across protocol upgrades and validation environments.
 */
interface TokenConfigurationV0 {
  /** Metadata conventions, including decimals and localizations. */
  conventions: TokenConfigurationConvention;
  /** Change control rules governing who can modify the conventions field. */
  conventions_change_rules: ChangeControlRules;
  /** The initial token supply minted at creation. */
  base_supply: TokenAmount;
  /**
   * The maximum allowable supply of the token.
   * 
   *  If `None`, the supply is unbounded unless otherwise constrained by minting logic.
   */
  max_supply?: TokenAmount;
  /** Configuration governing which historical actions are recorded for this token. */
  keeps_history: TokenKeepsHistoryRules;
  /**
   * Indicates whether the token should start in a paused state.
   * 
   *  When `true`, transfers are disallowed until explicitly unpaused via an emergency action.
   */
  start_as_paused: boolean;
  /** Allows minting and transferring to frozen token balances if enabled. */
  allow_transfer_to_frozen_balance: boolean;
  /**
   * Change control rules for updating the `max_supply`.
   * 
   *  Note: The `max_supply` can never be reduced below the `base_supply`.
   */
  max_supply_change_rules: ChangeControlRules;
  /** Defines the token's distribution logic, including perpetual and pre-programmed distributions. */
  distribution_rules: TokenDistributionRules;
  /** Defines the token's marketplace logic. */
  marketplace_rules: TokenMarketplaceRules;
  /** Rules controlling who is authorized to perform manual minting of tokens. */
  manual_minting_rules: ChangeControlRules;
  /** Rules controlling who is authorized to perform manual burning of tokens. */
  manual_burning_rules: ChangeControlRules;
  /** Rules governing who may freeze token balances. */
  freeze_rules: ChangeControlRules;
  /** Rules governing who may unfreeze token balances. */
  unfreeze_rules: ChangeControlRules;
  /** Rules governing who may destroy frozen funds. */
  destroy_frozen_funds_rules: ChangeControlRules;
  /** Rules governing who may invoke emergency actions, such as pausing transfers. */
  emergency_action_rules: ChangeControlRules;
  /** Optional reference to the group assigned as the token's main control group. */
  main_control_group?: GroupContractPosition;
  /** Defines whether and how the main control group assignment may be modified. */
  main_control_group_can_be_modified: AuthorizedActionTakers;
  /** Optional textual description of the token's purpose, behavior, or metadata. */
  description?: string;
}
/** @ignore */
const TokenConfigurationV0 : BinCodeable<TokenConfigurationV0> & ((data: {
  /** Metadata conventions, including decimals and localizations. */
  conventions: TokenConfigurationConvention,
  /** Change control rules governing who can modify the conventions field. */
  conventions_change_rules: ChangeControlRules,
  /** The initial token supply minted at creation. */
  base_supply: TokenAmount,
  /**
   * The maximum allowable supply of the token.
   * 
   *  If `None`, the supply is unbounded unless otherwise constrained by minting logic.
   */
  max_supply?: TokenAmount,
  /** Configuration governing which historical actions are recorded for this token. */
  keeps_history: TokenKeepsHistoryRules,
  /**
   * Indicates whether the token should start in a paused state.
   * 
   *  When `true`, transfers are disallowed until explicitly unpaused via an emergency action.
   */
  start_as_paused: boolean,
  /** Allows minting and transferring to frozen token balances if enabled. */
  allow_transfer_to_frozen_balance: boolean,
  /**
   * Change control rules for updating the `max_supply`.
   * 
   *  Note: The `max_supply` can never be reduced below the `base_supply`.
   */
  max_supply_change_rules: ChangeControlRules,
  /** Defines the token's distribution logic, including perpetual and pre-programmed distributions. */
  distribution_rules: TokenDistributionRules,
  /** Defines the token's marketplace logic. */
  marketplace_rules: TokenMarketplaceRules,
  /** Rules controlling who is authorized to perform manual minting of tokens. */
  manual_minting_rules: ChangeControlRules,
  /** Rules controlling who is authorized to perform manual burning of tokens. */
  manual_burning_rules: ChangeControlRules,
  /** Rules governing who may freeze token balances. */
  freeze_rules: ChangeControlRules,
  /** Rules governing who may unfreeze token balances. */
  unfreeze_rules: ChangeControlRules,
  /** Rules governing who may destroy frozen funds. */
  destroy_frozen_funds_rules: ChangeControlRules,
  /** Rules governing who may invoke emergency actions, such as pausing transfers. */
  emergency_action_rules: ChangeControlRules,
  /** Optional reference to the group assigned as the token's main control group. */
  main_control_group?: GroupContractPosition,
  /** Defines whether and how the main control group assignment may be modified. */
  main_control_group_can_be_modified: AuthorizedActionTakers,
  /** Optional textual description of the token's purpose, behavior, or metadata. */
  description?: string,
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
  /** @ignore @internal */
  [VARIANTS]: typeof TokenDestroyFrozenFundsTransition.variants;
  /** @ignore */
  static variants: {
    V0: typeof TokenDestroyFrozenFundsTransition.V0,
  };
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

/**
 * Represents a versioned transition for direct token purchases.
 * 
 *  This enum allows for forward-compatible support of different versions
 *  of the `TokenDirectPurchaseTransition` structure. Each variant corresponds
 *  to a specific version of the transition logic and structure.
 * 
 *  This transition type is used when a user intends to directly purchase tokens
 *  by specifying the desired amount and the maximum total price they are willing to pay.
 */
/** @ignore */
export abstract class TokenDirectPurchaseTransition {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: TokenDirectPurchaseTransition): void;
  /** @ignore */
  static decode(bc: BinCode): TokenDirectPurchaseTransition;
  /** @ignore @internal */
  [VARIANTS]: typeof TokenDirectPurchaseTransition.variants;
  /** @ignore */
  static variants: {
    V0: typeof TokenDirectPurchaseTransition.V0,
  };
}
namespace TokenDirectPurchaseTransition {
  /**
   * Version 0 of the token direct purchase transition.
   * 
   *  This version includes the base document transition, the number of tokens
   *  to purchase, and the maximum total price the user agrees to pay.
   *  If the price in the contract is lower than the agreed price, the lower
   *  price is used.
   * 
   * @function
   */
  interface V0 extends TokenDirectPurchaseTransition {
    [0]: TokenDirectPurchaseTransitionV0;
  }
  /** @ignore */
  const V0: (f0: TokenDirectPurchaseTransitionV0) => TokenDirectPurchaseTransition.V0;
}

interface TokenDirectPurchaseTransitionV0 {
  /** Document Base Transition */
  base: TokenBaseTransition;
  /** How many tokens should we buy. */
  token_count: TokenAmount;
  /**
   * Price that the user is willing to pay for all the tokens.
   *  The user will pay up to this amount.
   *  If the actual cost of the token per the contract is less than the agreed price that the user is willing to pay
   *  Then we take the actual cost per the contract.
   */
  total_agreed_price: Credits;
}
/** @ignore */
const TokenDirectPurchaseTransitionV0 : BinCodeable<TokenDirectPurchaseTransitionV0> & ((data: {
  /** Document Base Transition */
  base: TokenBaseTransition,
  /** How many tokens should we buy. */
  token_count: TokenAmount,
  /**
   * Price that the user is willing to pay for all the tokens.
   *  The user will pay up to this amount.
   *  If the actual cost of the token per the contract is less than the agreed price that the user is willing to pay
   *  Then we take the actual cost per the contract.
   */
  total_agreed_price: Credits,
}) => TokenDirectPurchaseTransitionV0);

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
  /** @ignore @internal */
  [VARIANTS]: typeof TokenDistributionRecipient.variants;
  /** @ignore */
  static variants: {
    ContractOwner: typeof TokenDistributionRecipient.ContractOwner,
    Identity: typeof TokenDistributionRecipient.Identity,
    EvonodesByParticipation: typeof TokenDistributionRecipient.EvonodesByParticipation,
  };
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
  /** @ignore @internal */
  [VARIANTS]: typeof TokenDistributionRules.variants;
  /** @ignore */
  static variants: {
    V0: typeof TokenDistributionRules.V0,
  };
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
  change_direct_purchase_pricing_rules: ChangeControlRules;
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
  change_direct_purchase_pricing_rules: ChangeControlRules,
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
  /** @ignore @internal */
  [VARIANTS]: typeof TokenDistributionType.variants;
  /** @ignore */
  static variants: {
    PreProgrammed: typeof TokenDistributionType.PreProgrammed,
    Perpetual: typeof TokenDistributionType.Perpetual,
  };
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
  /** @ignore @internal */
  [VARIANTS]: typeof TokenEmergencyAction.variants;
  /** @ignore */
  static variants: {
    Pause: typeof TokenEmergencyAction.Pause,
    Resume: typeof TokenEmergencyAction.Resume,
  };
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
  /** @ignore @internal */
  [VARIANTS]: typeof TokenEmergencyActionTransition.variants;
  /** @ignore */
  static variants: {
    V0: typeof TokenEmergencyActionTransition.V0,
  };
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
  /** @ignore @internal */
  [VARIANTS]: typeof TokenFreezeTransition.variants;
  /** @ignore */
  static variants: {
    V0: typeof TokenFreezeTransition.V0,
  };
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
  /** @ignore @internal */
  [VARIANTS]: typeof TokenKeepsHistoryRules.variants;
  /** @ignore */
  static variants: {
    V0: typeof TokenKeepsHistoryRules.V0,
  };
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
  /** Whether direct pricing history is recorded. */
  keeps_direct_pricing_history: boolean;
  /** Whether direct purchase history is recorded. */
  keeps_direct_purchase_history: boolean;
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
  /** Whether direct pricing history is recorded. */
  keeps_direct_pricing_history: boolean,
  /** Whether direct purchase history is recorded. */
  keeps_direct_purchase_history: boolean,
}) => TokenKeepsHistoryRulesV0);

/** @ignore */
export abstract class TokenMarketplaceRules {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: TokenMarketplaceRules): void;
  /** @ignore */
  static decode(bc: BinCode): TokenMarketplaceRules;
  /** @ignore @internal */
  [VARIANTS]: typeof TokenMarketplaceRules.variants;
  /** @ignore */
  static variants: {
    V0: typeof TokenMarketplaceRules.V0,
  };
}
namespace TokenMarketplaceRules {
  /** @function */
  interface V0 extends TokenMarketplaceRules {
    [0]: TokenMarketplaceRulesV0;
  }
  /** @ignore */
  const V0: (f0: TokenMarketplaceRulesV0) => TokenMarketplaceRules.V0;
}

interface TokenMarketplaceRulesV0 {
  trade_mode: TokenTradeMode;
  trade_mode_change_rules: ChangeControlRules;
}
/** @ignore */
const TokenMarketplaceRulesV0 : BinCodeable<TokenMarketplaceRulesV0> & ((data: {
  trade_mode: TokenTradeMode,
  trade_mode_change_rules: ChangeControlRules,
}) => TokenMarketplaceRulesV0);

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
  /** @ignore @internal */
  [VARIANTS]: typeof TokenMintTransition.variants;
  /** @ignore */
  static variants: {
    V0: typeof TokenMintTransition.V0,
  };
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
export abstract class TokenPaymentInfo {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: TokenPaymentInfo): void;
  /** @ignore */
  static decode(bc: BinCode): TokenPaymentInfo;
  /** @ignore @internal */
  [VARIANTS]: typeof TokenPaymentInfo.variants;
  /** @ignore */
  static variants: {
    V0: typeof TokenPaymentInfo.V0,
  };
}
namespace TokenPaymentInfo {
  /** @function */
  interface V0 extends TokenPaymentInfo {
    [0]: TokenPaymentInfoV0;
  }
  /** @ignore */
  const V0: (f0: TokenPaymentInfoV0) => TokenPaymentInfo.V0;
}

interface TokenPaymentInfoV0 {
  /**
   * By default, we use a token in the same contract, this field must be set if the document
   *  requires payment using another contracts token.
   */
  payment_token_contract_id?: Identifier;
  /**
   * If we are expecting to pay with a token in a contract, which token are we expecting
   *  to pay with?
   *  We have this set so contract owners can't switch out to more valuable token.
   *  For example if my Data contract
   */
  token_contract_position: TokenContractPosition;
  /** Minimum token cost, this most often should not be set */
  minimum_token_cost?: TokenAmount;
  /**
   * Maximum token cost, this most often should be set
   *  If:
   *  - a client does not have this set
   *  - and the data contract allows the price of NFTs to be changed by the data contract's owner or allowed party.
   *    Then:
   *  - The user could see the cost changed on them
   */
  maximum_token_cost?: TokenAmount;
  /** Who pays the gas fees, this needs to match what the contract allows */
  gas_fees_paid_by: GasFeesPaidBy;
}
/** @ignore */
const TokenPaymentInfoV0 : BinCodeable<TokenPaymentInfoV0> & ((data: {
  /**
   * By default, we use a token in the same contract, this field must be set if the document
   *  requires payment using another contracts token.
   */
  payment_token_contract_id?: Identifier,
  /**
   * If we are expecting to pay with a token in a contract, which token are we expecting
   *  to pay with?
   *  We have this set so contract owners can't switch out to more valuable token.
   *  For example if my Data contract
   */
  token_contract_position: TokenContractPosition,
  /** Minimum token cost, this most often should not be set */
  minimum_token_cost?: TokenAmount,
  /**
   * Maximum token cost, this most often should be set
   *  If:
   *  - a client does not have this set
   *  - and the data contract allows the price of NFTs to be changed by the data contract's owner or allowed party.
   *    Then:
   *  - The user could see the cost changed on them
   */
  maximum_token_cost?: TokenAmount,
  /** Who pays the gas fees, this needs to match what the contract allows */
  gas_fees_paid_by: GasFeesPaidBy,
}) => TokenPaymentInfoV0);

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
  /** @ignore @internal */
  [VARIANTS]: typeof TokenPerpetualDistribution.variants;
  /** @ignore */
  static variants: {
    V0: typeof TokenPerpetualDistribution.V0,
  };
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
  /** @ignore @internal */
  [VARIANTS]: typeof TokenPreProgrammedDistribution.variants;
  /** @ignore */
  static variants: {
    V0: typeof TokenPreProgrammedDistribution.V0,
  };
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

/**
 * Defines the pricing schedule for tokens in terms of credits.
 * 
 *  A pricing schedule can either be a single, flat price applied to all
 *  token amounts, or a tiered pricing model where specific amounts
 *  correspond to specific credit values.
 */
/** @ignore */
export abstract class TokenPricingSchedule {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: TokenPricingSchedule): void;
  /** @ignore */
  static decode(bc: BinCode): TokenPricingSchedule;
  /** @ignore @internal */
  [VARIANTS]: typeof TokenPricingSchedule.variants;
  /** @ignore */
  static variants: {
    SinglePrice: typeof TokenPricingSchedule.SinglePrice,
    SetPrices: typeof TokenPricingSchedule.SetPrices,
  };
}
namespace TokenPricingSchedule {
  /**
   * A single flat price in credits for all token amounts.
   * 
   *  This variant is used when the pricing does not depend on
   *  the number of tokens being purchased or processed.
   * 
   * @function
   */
  interface SinglePrice extends TokenPricingSchedule {
    [0]: Credits;
  }
  /** @ignore */
  const SinglePrice: (f0: Credits) => TokenPricingSchedule.SinglePrice;
  /**
   * A tiered pricing model where specific token amounts map to credit prices.
   * 
   *  This allows for more complex pricing structures, such as
   *  volume discounts or progressive pricing. The map keys
   *  represent token amount thresholds, and the values are the
   *  corresponding credit prices.
   *  If the first token amount is greater than 1 this means that the user can only
   *  purchase that amount as a minimum at a time.
   * 
   * @function
   */
  interface SetPrices extends TokenPricingSchedule {
    [0]: Map<TokenAmount, Credits>;
  }
  /** @ignore */
  const SetPrices: (f0: Map<TokenAmount, Credits>) => TokenPricingSchedule.SetPrices;
}

/**
 * Represents a versioned transition for setting or updating the price of a token
 *  available for direct purchase.
 * 
 *  This transition allows a token owner or controlling group to define or remove a pricing
 *  schedule for direct purchases. Setting the price to `None` disables further purchases
 *  of the token.
 * 
 *  This transition type supports **group actions**, meaning it can require **multi-signature
 *  (multisig) authorization**. In such cases, multiple identities must agree and sign
 *  the transition for it to be considered valid and executable.
 * 
 *  Versioning enables forward compatibility by allowing future enhancements or changes
 *  without breaking existing clients.
 */
/** @ignore */
export abstract class TokenSetPriceForDirectPurchaseTransition {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: TokenSetPriceForDirectPurchaseTransition): void;
  /** @ignore */
  static decode(bc: BinCode): TokenSetPriceForDirectPurchaseTransition;
  /** @ignore @internal */
  [VARIANTS]: typeof TokenSetPriceForDirectPurchaseTransition.variants;
  /** @ignore */
  static variants: {
    V0: typeof TokenSetPriceForDirectPurchaseTransition.V0,
  };
}
namespace TokenSetPriceForDirectPurchaseTransition {
  /**
   * Version 0 of the token set price for direct purchase transition.
   * 
   *  This version includes:
   *  - A base document transition.
   *  - An optional pricing schedule: `Some(...)` to set the token's price, or `None` to make it non-purchasable.
   *  - An optional public note.
   * 
   *  Group actions with multisig are supported in this version,
   *  enabling shared control over token pricing among multiple authorized identities.
   * 
   * @function
   */
  interface V0 extends TokenSetPriceForDirectPurchaseTransition {
    [0]: TokenSetPriceForDirectPurchaseTransitionV0;
  }
  /** @ignore */
  const V0: (f0: TokenSetPriceForDirectPurchaseTransitionV0) => TokenSetPriceForDirectPurchaseTransition.V0;
}

interface TokenSetPriceForDirectPurchaseTransitionV0 {
  /** Document Base Transition */
  base: TokenBaseTransition;
  /**
   * What should be the price for a single token
   *  Setting this to None makes it no longer purchasable
   */
  price?: TokenPricingSchedule;
  /** The public note */
  public_note?: string;
}
/** @ignore */
const TokenSetPriceForDirectPurchaseTransitionV0 : BinCodeable<TokenSetPriceForDirectPurchaseTransitionV0> & ((data: {
  /** Document Base Transition */
  base: TokenBaseTransition,
  /**
   * What should be the price for a single token
   *  Setting this to None makes it no longer purchasable
   */
  price?: TokenPricingSchedule,
  /** The public note */
  public_note?: string,
}) => TokenSetPriceForDirectPurchaseTransitionV0);

/** @ignore */
export abstract class TokenTradeMode {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: TokenTradeMode): void;
  /** @ignore */
  static decode(bc: BinCode): TokenTradeMode;
  /** @ignore @internal */
  [VARIANTS]: typeof TokenTradeMode.variants;
  /** @ignore */
  static variants: {
    NotTradeable: typeof TokenTradeMode.NotTradeable,
  };
}
namespace TokenTradeMode {
  /** default */
  const NotTradeable: () => TokenTradeMode;
}

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
  /** @ignore @internal */
  [VARIANTS]: typeof TokenTransferTransition.variants;
  /** @ignore */
  static variants: {
    V0: typeof TokenTransferTransition.V0,
  };
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
  /** @ignore @internal */
  [VARIANTS]: typeof TokenTransition.variants;
  /** @ignore */
  static variants: {
    Burn: typeof TokenTransition.Burn,
    Mint: typeof TokenTransition.Mint,
    Transfer: typeof TokenTransition.Transfer,
    Freeze: typeof TokenTransition.Freeze,
    Unfreeze: typeof TokenTransition.Unfreeze,
    DestroyFrozenFunds: typeof TokenTransition.DestroyFrozenFunds,
    Claim: typeof TokenTransition.Claim,
    EmergencyAction: typeof TokenTransition.EmergencyAction,
    ConfigUpdate: typeof TokenTransition.ConfigUpdate,
    DirectPurchase: typeof TokenTransition.DirectPurchase,
    SetPriceForDirectPurchase: typeof TokenTransition.SetPriceForDirectPurchase,
  };
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
  /** @function */
  interface DirectPurchase extends TokenTransition {
    [0]: TokenDirectPurchaseTransition;
  }
  /** @ignore */
  const DirectPurchase: (f0: TokenDirectPurchaseTransition) => TokenTransition.DirectPurchase;
  /** @function */
  interface SetPriceForDirectPurchase extends TokenTransition {
    [0]: TokenSetPriceForDirectPurchaseTransition;
  }
  /** @ignore */
  const SetPriceForDirectPurchase: (f0: TokenSetPriceForDirectPurchaseTransition) => TokenTransition.SetPriceForDirectPurchase;
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
  /** @ignore @internal */
  [VARIANTS]: typeof TokenUnfreezeTransition.variants;
  /** @ignore */
  static variants: {
    V0: typeof TokenUnfreezeTransition.V0,
  };
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

/**
 * An enum wrapper around various special transaction payloads.
 *  Special transactions are defined in DIP 2.
 */
/** @ignore */
export abstract class TransactionPayload {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: TransactionPayload): void;
  /** @ignore */
  static decode(bc: BinCode): TransactionPayload;
  /** @ignore @internal */
  [VARIANTS]: typeof TransactionPayload.variants;
  /** @ignore */
  static variants: {
    ProviderRegistrationPayloadType: typeof TransactionPayload.ProviderRegistrationPayloadType,
    ProviderUpdateServicePayloadType: typeof TransactionPayload.ProviderUpdateServicePayloadType,
    ProviderUpdateRegistrarPayloadType: typeof TransactionPayload.ProviderUpdateRegistrarPayloadType,
    ProviderUpdateRevocationPayloadType: typeof TransactionPayload.ProviderUpdateRevocationPayloadType,
    CoinbasePayloadType: typeof TransactionPayload.CoinbasePayloadType,
    QuorumCommitmentPayloadType: typeof TransactionPayload.QuorumCommitmentPayloadType,
    AssetLockPayloadType: typeof TransactionPayload.AssetLockPayloadType,
    AssetUnlockPayloadType: typeof TransactionPayload.AssetUnlockPayloadType,
  };
}
namespace TransactionPayload {
  /**
   * A wrapper for a Masternode Registration payload
   * 
   * @function
   */
  interface ProviderRegistrationPayloadType extends TransactionPayload {
    [0]: ProviderRegistrationPayload;
  }
  /** @ignore */
  const ProviderRegistrationPayloadType: (f0: ProviderRegistrationPayload) => TransactionPayload.ProviderRegistrationPayloadType;
  /**
   * A wrapper for a Masternode Update Service payload
   * 
   * @function
   */
  interface ProviderUpdateServicePayloadType extends TransactionPayload {
    [0]: ProviderUpdateServicePayload;
  }
  /** @ignore */
  const ProviderUpdateServicePayloadType: (f0: ProviderUpdateServicePayload) => TransactionPayload.ProviderUpdateServicePayloadType;
  /**
   * A wrapper for a Masternode Update Registrar payload
   * 
   * @function
   */
  interface ProviderUpdateRegistrarPayloadType extends TransactionPayload {
    [0]: ProviderUpdateRegistrarPayload;
  }
  /** @ignore */
  const ProviderUpdateRegistrarPayloadType: (f0: ProviderUpdateRegistrarPayload) => TransactionPayload.ProviderUpdateRegistrarPayloadType;
  /**
   * A wrapper for a Masternode Update Revocation payload
   * 
   * @function
   */
  interface ProviderUpdateRevocationPayloadType extends TransactionPayload {
    [0]: ProviderUpdateRevocationPayload;
  }
  /** @ignore */
  const ProviderUpdateRevocationPayloadType: (f0: ProviderUpdateRevocationPayload) => TransactionPayload.ProviderUpdateRevocationPayloadType;
  /**
   * A wrapper for a Coinbase payload
   * 
   * @function
   */
  interface CoinbasePayloadType extends TransactionPayload {
    [0]: CoinbasePayload;
  }
  /** @ignore */
  const CoinbasePayloadType: (f0: CoinbasePayload) => TransactionPayload.CoinbasePayloadType;
  /**
   * A wrapper for a Quorum Commitment payload
   * 
   * @function
   */
  interface QuorumCommitmentPayloadType extends TransactionPayload {
    [0]: QuorumCommitmentPayload;
  }
  /** @ignore */
  const QuorumCommitmentPayloadType: (f0: QuorumCommitmentPayload) => TransactionPayload.QuorumCommitmentPayloadType;
  /**
   * A wrapper for an Asset Lock payload
   * 
   * @function
   */
  interface AssetLockPayloadType extends TransactionPayload {
    [0]: AssetLockPayload;
  }
  /** @ignore */
  const AssetLockPayloadType: (f0: AssetLockPayload) => TransactionPayload.AssetLockPayloadType;
  /**
   * A wrapper for an Asset Unlock payload
   * 
   * @function
   */
  interface AssetUnlockPayloadType extends TransactionPayload {
    [0]: AssetUnlockPayload;
  }
  /** @ignore */
  const AssetUnlockPayloadType: (f0: AssetUnlockPayload) => TransactionPayload.AssetUnlockPayloadType;
}

/**
 * The transaction type. Special transactions were introduced in DIP2.
 *  Compared to Bitcoin the version field is split into two 16 bit integers.
 *  The first part for the version and the second part for the transaction
 *  type.
 * 
 * repr u16
 */
/** @ignore */
export abstract class TransactionType {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: TransactionType): void;
  /** @ignore */
  static decode(bc: BinCode): TransactionType;
  /** @ignore @internal */
  [VARIANTS]: typeof TransactionType.variants;
  /** @ignore */
  static variants: {
    Classic: typeof TransactionType.Classic,
    ProviderRegistration: typeof TransactionType.ProviderRegistration,
    ProviderUpdateService: typeof TransactionType.ProviderUpdateService,
    ProviderUpdateRegistrar: typeof TransactionType.ProviderUpdateRegistrar,
    ProviderUpdateRevocation: typeof TransactionType.ProviderUpdateRevocation,
    Coinbase: typeof TransactionType.Coinbase,
    QuorumCommitment: typeof TransactionType.QuorumCommitment,
    AssetLock: typeof TransactionType.AssetLock,
    AssetUnlock: typeof TransactionType.AssetUnlock,
  };
}
namespace TransactionType {
  /** A Classic transaction */
  const Classic: () => TransactionType;
  /** A Masternode Registration Transaction */
  const ProviderRegistration: () => TransactionType;
  /** A Masternode Update Service Transaction, used by the operator to signal changes to service */
  const ProviderUpdateService: () => TransactionType;
  /** A Masternode Update Registrar Transaction, used by the owner to signal base changes */
  const ProviderUpdateRegistrar: () => TransactionType;
  /** A Masternode Update Revocation Transaction, used by the operator to signal termination of service */
  const ProviderUpdateRevocation: () => TransactionType;
  /** A Coinbase Transaction, contained as the first transaction in each block */
  const Coinbase: () => TransactionType;
  /** A Quorum Commitment Transaction, used to save quorum information to the state */
  const QuorumCommitment: () => TransactionType;
  /** An Asset Lock Transaction, used to transfer credits to Dash Platform, by locking them until withdrawals occur */
  const AssetLock: () => TransactionType;
  /** An Asset Unlock Transaction, used to withdraw credits from Dash Platform, by unlocking them */
  const AssetUnlock: () => TransactionType;
}

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
  /** @ignore @internal */
  [VARIANTS]: typeof Vote.variants;
  /** @ignore */
  static variants: {
    ResourceVote: typeof Vote.ResourceVote,
  };
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
  /** @ignore @internal */
  [VARIANTS]: typeof VotePoll.variants;
  /** @ignore */
  static variants: {
    ContestedDocumentResourceVotePoll: typeof VotePoll.ContestedDocumentResourceVotePoll,
  };
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
