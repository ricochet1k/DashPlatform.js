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

interface BinaryData {
  [0]: Uint8Array;
}
/** @ignore */
const BinaryData : BinCodeable<BinaryData> & ((
    f0: Uint8Array,
) => BinaryData);

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
}
namespace StorageKeyRequirements {
  const Unique: () => StorageKeyRequirements;
  const Multiple: () => StorageKeyRequirements;
  const MultipleReferenceToLatest: () => StorageKeyRequirements;
}

export type TimestampMillis = bigint;

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
