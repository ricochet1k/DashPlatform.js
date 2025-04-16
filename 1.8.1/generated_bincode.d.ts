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
  };
}
namespace DataContractConfig {
  /** @function */
  interface V0 extends DataContractConfig {
    [0]: DataContractConfigV0;
  }
  /** @ignore */
  const V0: (f0: DataContractConfigV0) => DataContractConfig.V0;
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
  };
}
namespace DataContractInSerializationFormat {
  /** @function */
  interface V0 extends DataContractInSerializationFormat {
    [0]: DataContractInSerializationFormatV0;
  }
  /** @ignore */
  const V0: (f0: DataContractInSerializationFormatV0) => DataContractInSerializationFormat.V0;
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
  };
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

/** platform_version_path_bounds "dpp.state_transition_serialization_versions.documents_batch_state_transition" */
/** @ignore */
export abstract class DocumentsBatchTransition {
  /** @ignore @internal */
  constructor();
  #private;
  /** @ignore */
  static name: string;
  /** @ignore */
  static isValid(v: unknown): boolean;
  /** @ignore */
  static encode(bc: BinCode, v: DocumentsBatchTransition): void;
  /** @ignore */
  static decode(bc: BinCode): DocumentsBatchTransition;
  /** @ignore @internal */
  [VARIANTS]: typeof DocumentsBatchTransition.variants;
  /** @ignore */
  static variants: {
    V0: typeof DocumentsBatchTransition.V0,
  };
}
namespace DocumentsBatchTransition {
  /** @function */
  interface V0 extends DocumentsBatchTransition {
    [0]: DocumentsBatchTransitionV0;
  }
  /** @ignore */
  const V0: (f0: DocumentsBatchTransitionV0) => DocumentsBatchTransition.V0;
}

interface DocumentsBatchTransitionV0 {
  owner_id: Identifier;
  transitions: DocumentTransition[];
  user_fee_increase: UserFeeIncrease;
  /** platform_signable exclude_from_sig_hash */
  signature_public_key_id: KeyID;
  /** platform_signable exclude_from_sig_hash */
  signature: BinaryData;
}
/** @ignore */
const DocumentsBatchTransitionV0 : BinCodeable<DocumentsBatchTransitionV0> & ((data: {
  owner_id: Identifier,
  transitions: DocumentTransition[],
  user_fee_increase: UserFeeIncrease,
  /** platform_signable exclude_from_sig_hash */
  signature_public_key_id: KeyID,
  /** platform_signable exclude_from_sig_hash */
  signature: BinaryData,
}) => DocumentsBatchTransitionV0);

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
    DocumentsBatch: typeof StateTransition.DocumentsBatch,
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
  interface DocumentsBatch extends StateTransition {
    [0]: DocumentsBatchTransition;
  }
  /** @ignore */
  const DocumentsBatch: (f0: DocumentsBatchTransition) => StateTransition.DocumentsBatch;
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
