import { ServiceType } from "@protobuf-ts/runtime-rpc";
import { MessageType } from "@protobuf-ts/runtime";
import { BytesValue } from "../../google/protobuf/wrappers.ts";
import { UInt32Value } from "../../google/protobuf/wrappers.ts";
/**
 * Proof message includes cryptographic proofs for validating responses
 *
 * @generated from protobuf message org.dash.platform.dapi.v0.Proof
 */
export interface Proof {
    /**
     * @generated from protobuf field: bytes grovedb_proof = 1;
     */
    grovedbProof: Uint8Array;
    /**
     * @generated from protobuf field: bytes quorum_hash = 2;
     */
    quorumHash: Uint8Array;
    /**
     * @generated from protobuf field: bytes signature = 3;
     */
    signature: Uint8Array;
    /**
     * @generated from protobuf field: uint32 round = 4;
     */
    round: number;
    /**
     * @generated from protobuf field: bytes block_id_hash = 5;
     */
    blockIdHash: Uint8Array;
    /**
     * @generated from protobuf field: uint32 quorum_type = 6;
     */
    quorumType: number;
}
/**
 * ResponseMetadata provides metadata about the blockchain state at the time of response
 *
 * @generated from protobuf message org.dash.platform.dapi.v0.ResponseMetadata
 */
export interface ResponseMetadata {
    /**
     * @generated from protobuf field: uint64 height = 1 [jstype = JS_STRING];
     */
    height: string;
    /**
     * @generated from protobuf field: uint32 core_chain_locked_height = 2;
     */
    coreChainLockedHeight: number;
    /**
     * @generated from protobuf field: uint32 epoch = 3;
     */
    epoch: number;
    /**
     * @generated from protobuf field: uint64 time_ms = 4 [jstype = JS_STRING];
     */
    timeMs: string;
    /**
     * @generated from protobuf field: uint32 protocol_version = 5;
     */
    protocolVersion: number;
    /**
     * @generated from protobuf field: string chain_id = 6;
     */
    chainId: string;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.StateTransitionBroadcastError
 */
export interface StateTransitionBroadcastError {
    /**
     * @generated from protobuf field: uint32 code = 1;
     */
    code: number;
    /**
     * @generated from protobuf field: string message = 2;
     */
    message: string;
    /**
     * @generated from protobuf field: bytes data = 3;
     */
    data: Uint8Array;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.BroadcastStateTransitionRequest
 */
export interface BroadcastStateTransitionRequest {
    /**
     * @generated from protobuf field: bytes state_transition = 1;
     */
    stateTransition: Uint8Array;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.BroadcastStateTransitionResponse
 */
export interface BroadcastStateTransitionResponse {
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentityRequest
 */
export interface GetIdentityRequest {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetIdentityRequest.GetIdentityRequestV0 v0 = 1;
         */
        v0: GetIdentityRequest_GetIdentityRequestV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentityRequest.GetIdentityRequestV0
 */
export interface GetIdentityRequest_GetIdentityRequestV0 {
    /**
     * @generated from protobuf field: bytes id = 1;
     */
    id: Uint8Array;
    /**
     * @generated from protobuf field: bool prove = 2;
     */
    prove: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentityNonceRequest
 */
export interface GetIdentityNonceRequest {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetIdentityNonceRequest.GetIdentityNonceRequestV0 v0 = 1;
         */
        v0: GetIdentityNonceRequest_GetIdentityNonceRequestV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentityNonceRequest.GetIdentityNonceRequestV0
 */
export interface GetIdentityNonceRequest_GetIdentityNonceRequestV0 {
    /**
     * @generated from protobuf field: bytes identity_id = 1;
     */
    identityId: Uint8Array;
    /**
     * @generated from protobuf field: bool prove = 2;
     */
    prove: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentityContractNonceRequest
 */
export interface GetIdentityContractNonceRequest {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetIdentityContractNonceRequest.GetIdentityContractNonceRequestV0 v0 = 1;
         */
        v0: GetIdentityContractNonceRequest_GetIdentityContractNonceRequestV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentityContractNonceRequest.GetIdentityContractNonceRequestV0
 */
export interface GetIdentityContractNonceRequest_GetIdentityContractNonceRequestV0 {
    /**
     * @generated from protobuf field: bytes identity_id = 1;
     */
    identityId: Uint8Array;
    /**
     * @generated from protobuf field: bytes contract_id = 2;
     */
    contractId: Uint8Array;
    /**
     * @generated from protobuf field: bool prove = 3;
     */
    prove: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentityBalanceRequest
 */
export interface GetIdentityBalanceRequest {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetIdentityBalanceRequest.GetIdentityBalanceRequestV0 v0 = 1;
         */
        v0: GetIdentityBalanceRequest_GetIdentityBalanceRequestV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentityBalanceRequest.GetIdentityBalanceRequestV0
 */
export interface GetIdentityBalanceRequest_GetIdentityBalanceRequestV0 {
    /**
     * @generated from protobuf field: bytes id = 1;
     */
    id: Uint8Array;
    /**
     * @generated from protobuf field: bool prove = 2;
     */
    prove: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentityBalanceAndRevisionRequest
 */
export interface GetIdentityBalanceAndRevisionRequest {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetIdentityBalanceAndRevisionRequest.GetIdentityBalanceAndRevisionRequestV0 v0 = 1;
         */
        v0: GetIdentityBalanceAndRevisionRequest_GetIdentityBalanceAndRevisionRequestV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentityBalanceAndRevisionRequest.GetIdentityBalanceAndRevisionRequestV0
 */
export interface GetIdentityBalanceAndRevisionRequest_GetIdentityBalanceAndRevisionRequestV0 {
    /**
     * @generated from protobuf field: bytes id = 1;
     */
    id: Uint8Array;
    /**
     * @generated from protobuf field: bool prove = 2;
     */
    prove: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentityResponse
 */
export interface GetIdentityResponse {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetIdentityResponse.GetIdentityResponseV0 v0 = 1;
         */
        v0: GetIdentityResponse_GetIdentityResponseV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentityResponse.GetIdentityResponseV0
 */
export interface GetIdentityResponse_GetIdentityResponseV0 {
    /**
     * @generated from protobuf oneof: result
     */
    result: {
        oneofKind: "identity";
        /**
         * @generated from protobuf field: bytes identity = 1;
         */
        identity: Uint8Array;
    } | {
        oneofKind: "proof";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.Proof proof = 2;
         */
        proof: Proof;
    } | {
        oneofKind: undefined;
    };
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.ResponseMetadata metadata = 3;
     */
    metadata?: ResponseMetadata;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentityNonceResponse
 */
export interface GetIdentityNonceResponse {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetIdentityNonceResponse.GetIdentityNonceResponseV0 v0 = 1;
         */
        v0: GetIdentityNonceResponse_GetIdentityNonceResponseV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentityNonceResponse.GetIdentityNonceResponseV0
 */
export interface GetIdentityNonceResponse_GetIdentityNonceResponseV0 {
    /**
     * @generated from protobuf oneof: result
     */
    result: {
        oneofKind: "identityNonce";
        /**
         * @generated from protobuf field: uint64 identity_nonce = 1 [jstype = JS_STRING];
         */
        identityNonce: string;
    } | {
        oneofKind: "proof";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.Proof proof = 2;
         */
        proof: Proof;
    } | {
        oneofKind: undefined;
    };
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.ResponseMetadata metadata = 3;
     */
    metadata?: ResponseMetadata;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentityContractNonceResponse
 */
export interface GetIdentityContractNonceResponse {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetIdentityContractNonceResponse.GetIdentityContractNonceResponseV0 v0 = 1;
         */
        v0: GetIdentityContractNonceResponse_GetIdentityContractNonceResponseV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentityContractNonceResponse.GetIdentityContractNonceResponseV0
 */
export interface GetIdentityContractNonceResponse_GetIdentityContractNonceResponseV0 {
    /**
     * @generated from protobuf oneof: result
     */
    result: {
        oneofKind: "identityContractNonce";
        /**
         * @generated from protobuf field: uint64 identity_contract_nonce = 1 [jstype = JS_STRING];
         */
        identityContractNonce: string;
    } | {
        oneofKind: "proof";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.Proof proof = 2;
         */
        proof: Proof;
    } | {
        oneofKind: undefined;
    };
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.ResponseMetadata metadata = 3;
     */
    metadata?: ResponseMetadata;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentityBalanceResponse
 */
export interface GetIdentityBalanceResponse {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetIdentityBalanceResponse.GetIdentityBalanceResponseV0 v0 = 1;
         */
        v0: GetIdentityBalanceResponse_GetIdentityBalanceResponseV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentityBalanceResponse.GetIdentityBalanceResponseV0
 */
export interface GetIdentityBalanceResponse_GetIdentityBalanceResponseV0 {
    /**
     * @generated from protobuf oneof: result
     */
    result: {
        oneofKind: "balance";
        /**
         * @generated from protobuf field: uint64 balance = 1 [jstype = JS_STRING];
         */
        balance: string;
    } | {
        oneofKind: "proof";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.Proof proof = 2;
         */
        proof: Proof;
    } | {
        oneofKind: undefined;
    };
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.ResponseMetadata metadata = 3;
     */
    metadata?: ResponseMetadata;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentityBalanceAndRevisionResponse
 */
export interface GetIdentityBalanceAndRevisionResponse {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetIdentityBalanceAndRevisionResponse.GetIdentityBalanceAndRevisionResponseV0 v0 = 1;
         */
        v0: GetIdentityBalanceAndRevisionResponse_GetIdentityBalanceAndRevisionResponseV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentityBalanceAndRevisionResponse.GetIdentityBalanceAndRevisionResponseV0
 */
export interface GetIdentityBalanceAndRevisionResponse_GetIdentityBalanceAndRevisionResponseV0 {
    /**
     * @generated from protobuf oneof: result
     */
    result: {
        oneofKind: "balanceAndRevision";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetIdentityBalanceAndRevisionResponse.GetIdentityBalanceAndRevisionResponseV0.BalanceAndRevision balance_and_revision = 1;
         */
        balanceAndRevision: GetIdentityBalanceAndRevisionResponse_GetIdentityBalanceAndRevisionResponseV0_BalanceAndRevision;
    } | {
        oneofKind: "proof";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.Proof proof = 2;
         */
        proof: Proof;
    } | {
        oneofKind: undefined;
    };
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.ResponseMetadata metadata = 3;
     */
    metadata?: ResponseMetadata;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentityBalanceAndRevisionResponse.GetIdentityBalanceAndRevisionResponseV0.BalanceAndRevision
 */
export interface GetIdentityBalanceAndRevisionResponse_GetIdentityBalanceAndRevisionResponseV0_BalanceAndRevision {
    /**
     * @generated from protobuf field: uint64 balance = 1 [jstype = JS_STRING];
     */
    balance: string;
    /**
     * @generated from protobuf field: uint64 revision = 2 [jstype = JS_STRING];
     */
    revision: string;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.KeyRequestType
 */
export interface KeyRequestType {
    /**
     * @generated from protobuf oneof: request
     */
    request: {
        oneofKind: "allKeys";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.AllKeys all_keys = 1;
         */
        allKeys: AllKeys;
    } | {
        oneofKind: "specificKeys";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.SpecificKeys specific_keys = 2;
         */
        specificKeys: SpecificKeys;
    } | {
        oneofKind: "searchKey";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.SearchKey search_key = 3;
         */
        searchKey: SearchKey;
    } | {
        oneofKind: undefined;
    };
}
/**
 * AllKeys is an empty message used to signify a request for all keys
 *
 * @generated from protobuf message org.dash.platform.dapi.v0.AllKeys
 */
export interface AllKeys {
}
/**
 * SpecificKeys is used to request specific keys by their IDs
 *
 * @generated from protobuf message org.dash.platform.dapi.v0.SpecificKeys
 */
export interface SpecificKeys {
    /**
     * @generated from protobuf field: repeated uint32 key_ids = 1;
     */
    keyIds: number[];
}
/**
 * SearchKey represents a request to search for keys based on specific criteria
 *
 * @generated from protobuf message org.dash.platform.dapi.v0.SearchKey
 */
export interface SearchKey {
    /**
     * @generated from protobuf field: map<uint32, org.dash.platform.dapi.v0.SecurityLevelMap> purpose_map = 1;
     */
    purposeMap: {
        [key: number]: SecurityLevelMap;
    };
}
/**
 * SecurityLevelMap maps security levels to a request type for key retrieval
 *
 * @generated from protobuf message org.dash.platform.dapi.v0.SecurityLevelMap
 */
export interface SecurityLevelMap {
    /**
     * @generated from protobuf field: map<uint32, org.dash.platform.dapi.v0.SecurityLevelMap.KeyKindRequestType> security_level_map = 1;
     */
    securityLevelMap: {
        [key: number]: SecurityLevelMap_KeyKindRequestType;
    };
}
/**
 * @generated from protobuf enum org.dash.platform.dapi.v0.SecurityLevelMap.KeyKindRequestType
 */
export declare enum SecurityLevelMap_KeyKindRequestType {
    /**
     * Request the current key of a particular kind
     *
     * @generated from protobuf enum value: CURRENT_KEY_OF_KIND_REQUEST = 0;
     */
    CURRENT_KEY_OF_KIND_REQUEST = 0,
    /**
     * Request all keys of a particular kind
     *
     * @generated from protobuf enum value: ALL_KEYS_OF_KIND_REQUEST = 1;
     */
    ALL_KEYS_OF_KIND_REQUEST = 1
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentityKeysRequest
 */
export interface GetIdentityKeysRequest {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetIdentityKeysRequest.GetIdentityKeysRequestV0 v0 = 1;
         */
        v0: GetIdentityKeysRequest_GetIdentityKeysRequestV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentityKeysRequest.GetIdentityKeysRequestV0
 */
export interface GetIdentityKeysRequest_GetIdentityKeysRequestV0 {
    /**
     * @generated from protobuf field: bytes identity_id = 1;
     */
    identityId: Uint8Array;
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.KeyRequestType request_type = 2;
     */
    requestType?: KeyRequestType;
    /**
     * @generated from protobuf field: google.protobuf.UInt32Value limit = 3;
     */
    limit?: UInt32Value;
    /**
     * @generated from protobuf field: google.protobuf.UInt32Value offset = 4;
     */
    offset?: UInt32Value;
    /**
     * @generated from protobuf field: bool prove = 5;
     */
    prove: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentityKeysResponse
 */
export interface GetIdentityKeysResponse {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetIdentityKeysResponse.GetIdentityKeysResponseV0 v0 = 1;
         */
        v0: GetIdentityKeysResponse_GetIdentityKeysResponseV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentityKeysResponse.GetIdentityKeysResponseV0
 */
export interface GetIdentityKeysResponse_GetIdentityKeysResponseV0 {
    /**
     * @generated from protobuf oneof: result
     */
    result: {
        oneofKind: "keys";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetIdentityKeysResponse.GetIdentityKeysResponseV0.Keys keys = 1;
         */
        keys: GetIdentityKeysResponse_GetIdentityKeysResponseV0_Keys;
    } | {
        oneofKind: "proof";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.Proof proof = 2;
         */
        proof: Proof;
    } | {
        oneofKind: undefined;
    };
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.ResponseMetadata metadata = 3;
     */
    metadata?: ResponseMetadata;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentityKeysResponse.GetIdentityKeysResponseV0.Keys
 */
export interface GetIdentityKeysResponse_GetIdentityKeysResponseV0_Keys {
    /**
     * @generated from protobuf field: repeated bytes keys_bytes = 1;
     */
    keysBytes: Uint8Array[];
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentitiesContractKeysRequest
 */
export interface GetIdentitiesContractKeysRequest {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetIdentitiesContractKeysRequest.GetIdentitiesContractKeysRequestV0 v0 = 1;
         */
        v0: GetIdentitiesContractKeysRequest_GetIdentitiesContractKeysRequestV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentitiesContractKeysRequest.GetIdentitiesContractKeysRequestV0
 */
export interface GetIdentitiesContractKeysRequest_GetIdentitiesContractKeysRequestV0 {
    /**
     * @generated from protobuf field: repeated bytes identities_ids = 1;
     */
    identitiesIds: Uint8Array[];
    /**
     * @generated from protobuf field: bytes contract_id = 2;
     */
    contractId: Uint8Array;
    /**
     * @generated from protobuf field: optional string document_type_name = 3;
     */
    documentTypeName?: string;
    /**
     * @generated from protobuf field: repeated org.dash.platform.dapi.v0.KeyPurpose purposes = 4;
     */
    purposes: KeyPurpose[];
    /**
     * @generated from protobuf field: bool prove = 5;
     */
    prove: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentitiesContractKeysResponse
 */
export interface GetIdentitiesContractKeysResponse {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetIdentitiesContractKeysResponse.GetIdentitiesContractKeysResponseV0 v0 = 1;
         */
        v0: GetIdentitiesContractKeysResponse_GetIdentitiesContractKeysResponseV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentitiesContractKeysResponse.GetIdentitiesContractKeysResponseV0
 */
export interface GetIdentitiesContractKeysResponse_GetIdentitiesContractKeysResponseV0 {
    /**
     * @generated from protobuf oneof: result
     */
    result: {
        oneofKind: "identitiesKeys";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetIdentitiesContractKeysResponse.GetIdentitiesContractKeysResponseV0.IdentitiesKeys identities_keys = 1;
         */
        identitiesKeys: GetIdentitiesContractKeysResponse_GetIdentitiesContractKeysResponseV0_IdentitiesKeys;
    } | {
        oneofKind: "proof";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.Proof proof = 2;
         */
        proof: Proof;
    } | {
        oneofKind: undefined;
    };
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.ResponseMetadata metadata = 3;
     */
    metadata?: ResponseMetadata;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentitiesContractKeysResponse.GetIdentitiesContractKeysResponseV0.PurposeKeys
 */
export interface GetIdentitiesContractKeysResponse_GetIdentitiesContractKeysResponseV0_PurposeKeys {
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.KeyPurpose purpose = 1;
     */
    purpose: KeyPurpose;
    /**
     * @generated from protobuf field: repeated bytes keys_bytes = 2;
     */
    keysBytes: Uint8Array[];
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentitiesContractKeysResponse.GetIdentitiesContractKeysResponseV0.IdentityKeys
 */
export interface GetIdentitiesContractKeysResponse_GetIdentitiesContractKeysResponseV0_IdentityKeys {
    /**
     * @generated from protobuf field: bytes identity_id = 1;
     */
    identityId: Uint8Array;
    /**
     * @generated from protobuf field: repeated org.dash.platform.dapi.v0.GetIdentitiesContractKeysResponse.GetIdentitiesContractKeysResponseV0.PurposeKeys keys = 2;
     */
    keys: GetIdentitiesContractKeysResponse_GetIdentitiesContractKeysResponseV0_PurposeKeys[];
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentitiesContractKeysResponse.GetIdentitiesContractKeysResponseV0.IdentitiesKeys
 */
export interface GetIdentitiesContractKeysResponse_GetIdentitiesContractKeysResponseV0_IdentitiesKeys {
    /**
     * @generated from protobuf field: repeated org.dash.platform.dapi.v0.GetIdentitiesContractKeysResponse.GetIdentitiesContractKeysResponseV0.IdentityKeys entries = 1;
     */
    entries: GetIdentitiesContractKeysResponse_GetIdentitiesContractKeysResponseV0_IdentityKeys[];
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetEvonodesProposedEpochBlocksByIdsRequest
 */
export interface GetEvonodesProposedEpochBlocksByIdsRequest {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetEvonodesProposedEpochBlocksByIdsRequest.GetEvonodesProposedEpochBlocksByIdsRequestV0 v0 = 1;
         */
        v0: GetEvonodesProposedEpochBlocksByIdsRequest_GetEvonodesProposedEpochBlocksByIdsRequestV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetEvonodesProposedEpochBlocksByIdsRequest.GetEvonodesProposedEpochBlocksByIdsRequestV0
 */
export interface GetEvonodesProposedEpochBlocksByIdsRequest_GetEvonodesProposedEpochBlocksByIdsRequestV0 {
    /**
     * @generated from protobuf field: optional uint32 epoch = 1;
     */
    epoch?: number;
    /**
     * @generated from protobuf field: repeated bytes ids = 2;
     */
    ids: Uint8Array[];
    /**
     * @generated from protobuf field: bool prove = 3;
     */
    prove: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetEvonodesProposedEpochBlocksResponse
 */
export interface GetEvonodesProposedEpochBlocksResponse {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetEvonodesProposedEpochBlocksResponse.GetEvonodesProposedEpochBlocksResponseV0 v0 = 1;
         */
        v0: GetEvonodesProposedEpochBlocksResponse_GetEvonodesProposedEpochBlocksResponseV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetEvonodesProposedEpochBlocksResponse.GetEvonodesProposedEpochBlocksResponseV0
 */
export interface GetEvonodesProposedEpochBlocksResponse_GetEvonodesProposedEpochBlocksResponseV0 {
    /**
     * @generated from protobuf oneof: result
     */
    result: {
        oneofKind: "evonodesProposedBlockCountsInfo";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetEvonodesProposedEpochBlocksResponse.GetEvonodesProposedEpochBlocksResponseV0.EvonodesProposedBlocks evonodes_proposed_block_counts_info = 1;
         */
        evonodesProposedBlockCountsInfo: GetEvonodesProposedEpochBlocksResponse_GetEvonodesProposedEpochBlocksResponseV0_EvonodesProposedBlocks;
    } | {
        oneofKind: "proof";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.Proof proof = 2;
         */
        proof: Proof;
    } | {
        oneofKind: undefined;
    };
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.ResponseMetadata metadata = 3;
     */
    metadata?: ResponseMetadata;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetEvonodesProposedEpochBlocksResponse.GetEvonodesProposedEpochBlocksResponseV0.EvonodeProposedBlocks
 */
export interface GetEvonodesProposedEpochBlocksResponse_GetEvonodesProposedEpochBlocksResponseV0_EvonodeProposedBlocks {
    /**
     * @generated from protobuf field: bytes pro_tx_hash = 1;
     */
    proTxHash: Uint8Array;
    /**
     * @generated from protobuf field: uint64 count = 2 [jstype = JS_STRING];
     */
    count: string;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetEvonodesProposedEpochBlocksResponse.GetEvonodesProposedEpochBlocksResponseV0.EvonodesProposedBlocks
 */
export interface GetEvonodesProposedEpochBlocksResponse_GetEvonodesProposedEpochBlocksResponseV0_EvonodesProposedBlocks {
    /**
     * @generated from protobuf field: repeated org.dash.platform.dapi.v0.GetEvonodesProposedEpochBlocksResponse.GetEvonodesProposedEpochBlocksResponseV0.EvonodeProposedBlocks evonodes_proposed_block_counts = 1;
     */
    evonodesProposedBlockCounts: GetEvonodesProposedEpochBlocksResponse_GetEvonodesProposedEpochBlocksResponseV0_EvonodeProposedBlocks[];
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetEvonodesProposedEpochBlocksByRangeRequest
 */
export interface GetEvonodesProposedEpochBlocksByRangeRequest {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetEvonodesProposedEpochBlocksByRangeRequest.GetEvonodesProposedEpochBlocksByRangeRequestV0 v0 = 1;
         */
        v0: GetEvonodesProposedEpochBlocksByRangeRequest_GetEvonodesProposedEpochBlocksByRangeRequestV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetEvonodesProposedEpochBlocksByRangeRequest.GetEvonodesProposedEpochBlocksByRangeRequestV0
 */
export interface GetEvonodesProposedEpochBlocksByRangeRequest_GetEvonodesProposedEpochBlocksByRangeRequestV0 {
    /**
     * @generated from protobuf field: optional uint32 epoch = 1;
     */
    epoch?: number;
    /**
     * @generated from protobuf field: optional uint32 limit = 2;
     */
    limit?: number;
    /**
     * @generated from protobuf oneof: start
     */
    start: {
        oneofKind: "startAfter";
        /**
         * @generated from protobuf field: bytes start_after = 3;
         */
        startAfter: Uint8Array;
    } | {
        oneofKind: "startAt";
        /**
         * @generated from protobuf field: bytes start_at = 4;
         */
        startAt: Uint8Array;
    } | {
        oneofKind: undefined;
    };
    /**
     * @generated from protobuf field: bool prove = 5;
     */
    prove: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentitiesBalancesRequest
 */
export interface GetIdentitiesBalancesRequest {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetIdentitiesBalancesRequest.GetIdentitiesBalancesRequestV0 v0 = 1;
         */
        v0: GetIdentitiesBalancesRequest_GetIdentitiesBalancesRequestV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentitiesBalancesRequest.GetIdentitiesBalancesRequestV0
 */
export interface GetIdentitiesBalancesRequest_GetIdentitiesBalancesRequestV0 {
    /**
     * @generated from protobuf field: repeated bytes ids = 1;
     */
    ids: Uint8Array[];
    /**
     * @generated from protobuf field: bool prove = 2;
     */
    prove: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentitiesBalancesResponse
 */
export interface GetIdentitiesBalancesResponse {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetIdentitiesBalancesResponse.GetIdentitiesBalancesResponseV0 v0 = 1;
         */
        v0: GetIdentitiesBalancesResponse_GetIdentitiesBalancesResponseV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentitiesBalancesResponse.GetIdentitiesBalancesResponseV0
 */
export interface GetIdentitiesBalancesResponse_GetIdentitiesBalancesResponseV0 {
    /**
     * @generated from protobuf oneof: result
     */
    result: {
        oneofKind: "identitiesBalances";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetIdentitiesBalancesResponse.GetIdentitiesBalancesResponseV0.IdentitiesBalances identities_balances = 1;
         */
        identitiesBalances: GetIdentitiesBalancesResponse_GetIdentitiesBalancesResponseV0_IdentitiesBalances;
    } | {
        oneofKind: "proof";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.Proof proof = 2;
         */
        proof: Proof;
    } | {
        oneofKind: undefined;
    };
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.ResponseMetadata metadata = 3;
     */
    metadata?: ResponseMetadata;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentitiesBalancesResponse.GetIdentitiesBalancesResponseV0.IdentityBalance
 */
export interface GetIdentitiesBalancesResponse_GetIdentitiesBalancesResponseV0_IdentityBalance {
    /**
     * @generated from protobuf field: bytes identity_id = 1;
     */
    identityId: Uint8Array;
    /**
     * @generated from protobuf field: optional uint64 balance = 2 [jstype = JS_STRING];
     */
    balance?: string;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentitiesBalancesResponse.GetIdentitiesBalancesResponseV0.IdentitiesBalances
 */
export interface GetIdentitiesBalancesResponse_GetIdentitiesBalancesResponseV0_IdentitiesBalances {
    /**
     * @generated from protobuf field: repeated org.dash.platform.dapi.v0.GetIdentitiesBalancesResponse.GetIdentitiesBalancesResponseV0.IdentityBalance entries = 1;
     */
    entries: GetIdentitiesBalancesResponse_GetIdentitiesBalancesResponseV0_IdentityBalance[];
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetProofsRequest
 */
export interface GetProofsRequest {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetProofsRequest.GetProofsRequestV0 v0 = 1;
         */
        v0: GetProofsRequest_GetProofsRequestV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetProofsRequest.GetProofsRequestV0
 */
export interface GetProofsRequest_GetProofsRequestV0 {
    /**
     * @generated from protobuf field: repeated org.dash.platform.dapi.v0.GetProofsRequest.GetProofsRequestV0.IdentityRequest identities = 1;
     */
    identities: GetProofsRequest_GetProofsRequestV0_IdentityRequest[];
    /**
     * @generated from protobuf field: repeated org.dash.platform.dapi.v0.GetProofsRequest.GetProofsRequestV0.ContractRequest contracts = 2;
     */
    contracts: GetProofsRequest_GetProofsRequestV0_ContractRequest[];
    /**
     * @generated from protobuf field: repeated org.dash.platform.dapi.v0.GetProofsRequest.GetProofsRequestV0.DocumentRequest documents = 3;
     */
    documents: GetProofsRequest_GetProofsRequestV0_DocumentRequest[];
    /**
     * @generated from protobuf field: repeated org.dash.platform.dapi.v0.GetProofsRequest.GetProofsRequestV0.VoteStatusRequest votes = 4;
     */
    votes: GetProofsRequest_GetProofsRequestV0_VoteStatusRequest[];
    /**
     * @generated from protobuf field: repeated org.dash.platform.dapi.v0.GetProofsRequest.GetProofsRequestV0.IdentityTokenBalanceRequest identity_token_balances = 5;
     */
    identityTokenBalances: GetProofsRequest_GetProofsRequestV0_IdentityTokenBalanceRequest[];
    /**
     * @generated from protobuf field: repeated org.dash.platform.dapi.v0.GetProofsRequest.GetProofsRequestV0.IdentityTokenInfoRequest identity_token_infos = 6;
     */
    identityTokenInfos: GetProofsRequest_GetProofsRequestV0_IdentityTokenInfoRequest[];
    /**
     * @generated from protobuf field: repeated org.dash.platform.dapi.v0.GetProofsRequest.GetProofsRequestV0.TokenStatusRequest token_statuses = 7;
     */
    tokenStatuses: GetProofsRequest_GetProofsRequestV0_TokenStatusRequest[];
}
/**
 * DocumentRequest specifies a request for a document proof
 *
 * @generated from protobuf message org.dash.platform.dapi.v0.GetProofsRequest.GetProofsRequestV0.DocumentRequest
 */
export interface GetProofsRequest_GetProofsRequestV0_DocumentRequest {
    /**
     * @generated from protobuf field: bytes contract_id = 1;
     */
    contractId: Uint8Array;
    /**
     * @generated from protobuf field: string document_type = 2;
     */
    documentType: string;
    /**
     * @generated from protobuf field: bool document_type_keeps_history = 3;
     */
    documentTypeKeepsHistory: boolean;
    /**
     * @generated from protobuf field: bytes document_id = 4;
     */
    documentId: Uint8Array;
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.GetProofsRequest.GetProofsRequestV0.DocumentRequest.DocumentContestedStatus document_contested_status = 5;
     */
    documentContestedStatus: GetProofsRequest_GetProofsRequestV0_DocumentRequest_DocumentContestedStatus;
}
/**
 * @generated from protobuf enum org.dash.platform.dapi.v0.GetProofsRequest.GetProofsRequestV0.DocumentRequest.DocumentContestedStatus
 */
export declare enum GetProofsRequest_GetProofsRequestV0_DocumentRequest_DocumentContestedStatus {
    /**
     * @generated from protobuf enum value: NOT_CONTESTED = 0;
     */
    NOT_CONTESTED = 0,
    /**
     * @generated from protobuf enum value: MAYBE_CONTESTED = 1;
     */
    MAYBE_CONTESTED = 1,
    /**
     * @generated from protobuf enum value: CONTESTED = 2;
     */
    CONTESTED = 2
}
/**
 * IdentityRequest specifies a request for an identity proof
 *
 * @generated from protobuf message org.dash.platform.dapi.v0.GetProofsRequest.GetProofsRequestV0.IdentityRequest
 */
export interface GetProofsRequest_GetProofsRequestV0_IdentityRequest {
    /**
     * @generated from protobuf field: bytes identity_id = 1;
     */
    identityId: Uint8Array;
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.GetProofsRequest.GetProofsRequestV0.IdentityRequest.Type request_type = 2;
     */
    requestType: GetProofsRequest_GetProofsRequestV0_IdentityRequest_Type;
}
/**
 * @generated from protobuf enum org.dash.platform.dapi.v0.GetProofsRequest.GetProofsRequestV0.IdentityRequest.Type
 */
export declare enum GetProofsRequest_GetProofsRequestV0_IdentityRequest_Type {
    /**
     * Request for the full identity
     *
     * @generated from protobuf enum value: FULL_IDENTITY = 0;
     */
    FULL_IDENTITY = 0,
    /**
     * Request for the identity's balance
     *
     * @generated from protobuf enum value: BALANCE = 1;
     */
    BALANCE = 1,
    /**
     * Request for the identity's keys
     *
     * @generated from protobuf enum value: KEYS = 2;
     */
    KEYS = 2,
    /**
     * Request for the identity's revision
     *
     * @generated from protobuf enum value: REVISION = 3;
     */
    REVISION = 3
}
/**
 * ContractRequest specifies a request for a data contract proof.
 *
 * @generated from protobuf message org.dash.platform.dapi.v0.GetProofsRequest.GetProofsRequestV0.ContractRequest
 */
export interface GetProofsRequest_GetProofsRequestV0_ContractRequest {
    /**
     * @generated from protobuf field: bytes contract_id = 1;
     */
    contractId: Uint8Array;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetProofsRequest.GetProofsRequestV0.VoteStatusRequest
 */
export interface GetProofsRequest_GetProofsRequestV0_VoteStatusRequest {
    /**
     * @generated from protobuf oneof: request_type
     */
    requestType: {
        oneofKind: "contestedResourceVoteStatusRequest";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetProofsRequest.GetProofsRequestV0.VoteStatusRequest.ContestedResourceVoteStatusRequest contested_resource_vote_status_request = 1;
         */
        contestedResourceVoteStatusRequest: GetProofsRequest_GetProofsRequestV0_VoteStatusRequest_ContestedResourceVoteStatusRequest;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetProofsRequest.GetProofsRequestV0.VoteStatusRequest.ContestedResourceVoteStatusRequest
 */
export interface GetProofsRequest_GetProofsRequestV0_VoteStatusRequest_ContestedResourceVoteStatusRequest {
    /**
     * @generated from protobuf field: bytes contract_id = 1;
     */
    contractId: Uint8Array;
    /**
     * @generated from protobuf field: string document_type_name = 2;
     */
    documentTypeName: string;
    /**
     * @generated from protobuf field: string index_name = 3;
     */
    indexName: string;
    /**
     * @generated from protobuf field: repeated bytes index_values = 4;
     */
    indexValues: Uint8Array[];
    /**
     * @generated from protobuf field: bytes voter_identifier = 5;
     */
    voterIdentifier: Uint8Array;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetProofsRequest.GetProofsRequestV0.IdentityTokenBalanceRequest
 */
export interface GetProofsRequest_GetProofsRequestV0_IdentityTokenBalanceRequest {
    /**
     * @generated from protobuf field: bytes token_id = 1;
     */
    tokenId: Uint8Array;
    /**
     * @generated from protobuf field: bytes identity_id = 2;
     */
    identityId: Uint8Array;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetProofsRequest.GetProofsRequestV0.IdentityTokenInfoRequest
 */
export interface GetProofsRequest_GetProofsRequestV0_IdentityTokenInfoRequest {
    /**
     * @generated from protobuf field: bytes token_id = 1;
     */
    tokenId: Uint8Array;
    /**
     * @generated from protobuf field: bytes identity_id = 2;
     */
    identityId: Uint8Array;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetProofsRequest.GetProofsRequestV0.TokenStatusRequest
 */
export interface GetProofsRequest_GetProofsRequestV0_TokenStatusRequest {
    /**
     * @generated from protobuf field: bytes token_id = 1;
     */
    tokenId: Uint8Array;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetProofsResponse
 */
export interface GetProofsResponse {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetProofsResponse.GetProofsResponseV0 v0 = 1;
         */
        v0: GetProofsResponse_GetProofsResponseV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetProofsResponse.GetProofsResponseV0
 */
export interface GetProofsResponse_GetProofsResponseV0 {
    /**
     * @generated from protobuf oneof: result
     */
    result: {
        oneofKind: "proof";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.Proof proof = 1;
         */
        proof: Proof;
    } | {
        oneofKind: undefined;
    };
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.ResponseMetadata metadata = 2;
     */
    metadata?: ResponseMetadata;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetDataContractRequest
 */
export interface GetDataContractRequest {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetDataContractRequest.GetDataContractRequestV0 v0 = 1;
         */
        v0: GetDataContractRequest_GetDataContractRequestV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetDataContractRequest.GetDataContractRequestV0
 */
export interface GetDataContractRequest_GetDataContractRequestV0 {
    /**
     * @generated from protobuf field: bytes id = 1;
     */
    id: Uint8Array;
    /**
     * @generated from protobuf field: bool prove = 2;
     */
    prove: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetDataContractResponse
 */
export interface GetDataContractResponse {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetDataContractResponse.GetDataContractResponseV0 v0 = 1;
         */
        v0: GetDataContractResponse_GetDataContractResponseV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetDataContractResponse.GetDataContractResponseV0
 */
export interface GetDataContractResponse_GetDataContractResponseV0 {
    /**
     * @generated from protobuf oneof: result
     */
    result: {
        oneofKind: "dataContract";
        /**
         * @generated from protobuf field: bytes data_contract = 1;
         */
        dataContract: Uint8Array;
    } | {
        oneofKind: "proof";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.Proof proof = 2;
         */
        proof: Proof;
    } | {
        oneofKind: undefined;
    };
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.ResponseMetadata metadata = 3;
     */
    metadata?: ResponseMetadata;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetDataContractsRequest
 */
export interface GetDataContractsRequest {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetDataContractsRequest.GetDataContractsRequestV0 v0 = 1;
         */
        v0: GetDataContractsRequest_GetDataContractsRequestV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetDataContractsRequest.GetDataContractsRequestV0
 */
export interface GetDataContractsRequest_GetDataContractsRequestV0 {
    /**
     * @generated from protobuf field: repeated bytes ids = 1;
     */
    ids: Uint8Array[];
    /**
     * @generated from protobuf field: bool prove = 2;
     */
    prove: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetDataContractsResponse
 */
export interface GetDataContractsResponse {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetDataContractsResponse.GetDataContractsResponseV0 v0 = 1;
         */
        v0: GetDataContractsResponse_GetDataContractsResponseV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetDataContractsResponse.DataContractEntry
 */
export interface GetDataContractsResponse_DataContractEntry {
    /**
     * @generated from protobuf field: bytes identifier = 1;
     */
    identifier: Uint8Array;
    /**
     * @generated from protobuf field: google.protobuf.BytesValue data_contract = 2;
     */
    dataContract?: BytesValue;
}
/**
 * DataContracts is a collection of data contract entries.
 *
 * @generated from protobuf message org.dash.platform.dapi.v0.GetDataContractsResponse.DataContracts
 */
export interface GetDataContractsResponse_DataContracts {
    /**
     * @generated from protobuf field: repeated org.dash.platform.dapi.v0.GetDataContractsResponse.DataContractEntry data_contract_entries = 1;
     */
    dataContractEntries: GetDataContractsResponse_DataContractEntry[];
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetDataContractsResponse.GetDataContractsResponseV0
 */
export interface GetDataContractsResponse_GetDataContractsResponseV0 {
    /**
     * @generated from protobuf oneof: result
     */
    result: {
        oneofKind: "dataContracts";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetDataContractsResponse.DataContracts data_contracts = 1;
         */
        dataContracts: GetDataContractsResponse_DataContracts;
    } | {
        oneofKind: "proof";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.Proof proof = 2;
         */
        proof: Proof;
    } | {
        oneofKind: undefined;
    };
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.ResponseMetadata metadata = 3;
     */
    metadata?: ResponseMetadata;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetDataContractHistoryRequest
 */
export interface GetDataContractHistoryRequest {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetDataContractHistoryRequest.GetDataContractHistoryRequestV0 v0 = 1;
         */
        v0: GetDataContractHistoryRequest_GetDataContractHistoryRequestV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetDataContractHistoryRequest.GetDataContractHistoryRequestV0
 */
export interface GetDataContractHistoryRequest_GetDataContractHistoryRequestV0 {
    /**
     * @generated from protobuf field: bytes id = 1;
     */
    id: Uint8Array;
    /**
     * @generated from protobuf field: google.protobuf.UInt32Value limit = 2;
     */
    limit?: UInt32Value;
    /**
     * @generated from protobuf field: google.protobuf.UInt32Value offset = 3;
     */
    offset?: UInt32Value;
    /**
     * @generated from protobuf field: uint64 start_at_ms = 4 [jstype = JS_STRING];
     */
    startAtMs: string;
    /**
     * @generated from protobuf field: bool prove = 5;
     */
    prove: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetDataContractHistoryResponse
 */
export interface GetDataContractHistoryResponse {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetDataContractHistoryResponse.GetDataContractHistoryResponseV0 v0 = 1;
         */
        v0: GetDataContractHistoryResponse_GetDataContractHistoryResponseV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetDataContractHistoryResponse.GetDataContractHistoryResponseV0
 */
export interface GetDataContractHistoryResponse_GetDataContractHistoryResponseV0 {
    /**
     * @generated from protobuf oneof: result
     */
    result: {
        oneofKind: "dataContractHistory";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetDataContractHistoryResponse.GetDataContractHistoryResponseV0.DataContractHistory data_contract_history = 1;
         */
        dataContractHistory: GetDataContractHistoryResponse_GetDataContractHistoryResponseV0_DataContractHistory;
    } | {
        oneofKind: "proof";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.Proof proof = 2;
         */
        proof: Proof;
    } | {
        oneofKind: undefined;
    };
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.ResponseMetadata metadata = 3;
     */
    metadata?: ResponseMetadata;
}
/**
 * Represents a single entry in the data contract's history
 *
 * @generated from protobuf message org.dash.platform.dapi.v0.GetDataContractHistoryResponse.GetDataContractHistoryResponseV0.DataContractHistoryEntry
 */
export interface GetDataContractHistoryResponse_GetDataContractHistoryResponseV0_DataContractHistoryEntry {
    /**
     * @generated from protobuf field: uint64 date = 1 [jstype = JS_STRING];
     */
    date: string;
    /**
     * @generated from protobuf field: bytes value = 2;
     */
    value: Uint8Array;
}
/**
 * Collection of data contract history entries
 *
 * @generated from protobuf message org.dash.platform.dapi.v0.GetDataContractHistoryResponse.GetDataContractHistoryResponseV0.DataContractHistory
 */
export interface GetDataContractHistoryResponse_GetDataContractHistoryResponseV0_DataContractHistory {
    /**
     * @generated from protobuf field: repeated org.dash.platform.dapi.v0.GetDataContractHistoryResponse.GetDataContractHistoryResponseV0.DataContractHistoryEntry data_contract_entries = 1;
     */
    dataContractEntries: GetDataContractHistoryResponse_GetDataContractHistoryResponseV0_DataContractHistoryEntry[];
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetDocumentsRequest
 */
export interface GetDocumentsRequest {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetDocumentsRequest.GetDocumentsRequestV0 v0 = 1;
         */
        v0: GetDocumentsRequest_GetDocumentsRequestV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetDocumentsRequest.GetDocumentsRequestV0
 */
export interface GetDocumentsRequest_GetDocumentsRequestV0 {
    /**
     * @generated from protobuf field: bytes data_contract_id = 1;
     */
    dataContractId: Uint8Array;
    /**
     * @generated from protobuf field: string document_type = 2;
     */
    documentType: string;
    /**
     * @generated from protobuf field: bytes where = 3;
     */
    where: Uint8Array;
    /**
     * @generated from protobuf field: bytes order_by = 4;
     */
    orderBy: Uint8Array;
    /**
     * @generated from protobuf field: uint32 limit = 5;
     */
    limit: number;
    /**
     * @generated from protobuf oneof: start
     */
    start: {
        oneofKind: "startAfter";
        /**
         * @generated from protobuf field: bytes start_after = 6;
         */
        startAfter: Uint8Array;
    } | {
        oneofKind: "startAt";
        /**
         * @generated from protobuf field: bytes start_at = 7;
         */
        startAt: Uint8Array;
    } | {
        oneofKind: undefined;
    };
    /**
     * @generated from protobuf field: bool prove = 8;
     */
    prove: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetDocumentsResponse
 */
export interface GetDocumentsResponse {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetDocumentsResponse.GetDocumentsResponseV0 v0 = 1;
         */
        v0: GetDocumentsResponse_GetDocumentsResponseV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetDocumentsResponse.GetDocumentsResponseV0
 */
export interface GetDocumentsResponse_GetDocumentsResponseV0 {
    /**
     * @generated from protobuf oneof: result
     */
    result: {
        oneofKind: "documents";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetDocumentsResponse.GetDocumentsResponseV0.Documents documents = 1;
         */
        documents: GetDocumentsResponse_GetDocumentsResponseV0_Documents;
    } | {
        oneofKind: "proof";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.Proof proof = 2;
         */
        proof: Proof;
    } | {
        oneofKind: undefined;
    };
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.ResponseMetadata metadata = 3;
     */
    metadata?: ResponseMetadata;
}
/**
 * Represents a collection of documents
 *
 * @generated from protobuf message org.dash.platform.dapi.v0.GetDocumentsResponse.GetDocumentsResponseV0.Documents
 */
export interface GetDocumentsResponse_GetDocumentsResponseV0_Documents {
    /**
     * @generated from protobuf field: repeated bytes documents = 1;
     */
    documents: Uint8Array[];
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentityByPublicKeyHashRequest
 */
export interface GetIdentityByPublicKeyHashRequest {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetIdentityByPublicKeyHashRequest.GetIdentityByPublicKeyHashRequestV0 v0 = 1;
         */
        v0: GetIdentityByPublicKeyHashRequest_GetIdentityByPublicKeyHashRequestV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentityByPublicKeyHashRequest.GetIdentityByPublicKeyHashRequestV0
 */
export interface GetIdentityByPublicKeyHashRequest_GetIdentityByPublicKeyHashRequestV0 {
    /**
     * @generated from protobuf field: bytes public_key_hash = 1;
     */
    publicKeyHash: Uint8Array;
    /**
     * @generated from protobuf field: bool prove = 2;
     */
    prove: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentityByPublicKeyHashResponse
 */
export interface GetIdentityByPublicKeyHashResponse {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetIdentityByPublicKeyHashResponse.GetIdentityByPublicKeyHashResponseV0 v0 = 1;
         */
        v0: GetIdentityByPublicKeyHashResponse_GetIdentityByPublicKeyHashResponseV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentityByPublicKeyHashResponse.GetIdentityByPublicKeyHashResponseV0
 */
export interface GetIdentityByPublicKeyHashResponse_GetIdentityByPublicKeyHashResponseV0 {
    /**
     * @generated from protobuf oneof: result
     */
    result: {
        oneofKind: "identity";
        /**
         * @generated from protobuf field: bytes identity = 1;
         */
        identity: Uint8Array;
    } | {
        oneofKind: "proof";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.Proof proof = 2;
         */
        proof: Proof;
    } | {
        oneofKind: undefined;
    };
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.ResponseMetadata metadata = 3;
     */
    metadata?: ResponseMetadata;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.WaitForStateTransitionResultRequest
 */
export interface WaitForStateTransitionResultRequest {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.WaitForStateTransitionResultRequest.WaitForStateTransitionResultRequestV0 v0 = 1;
         */
        v0: WaitForStateTransitionResultRequest_WaitForStateTransitionResultRequestV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.WaitForStateTransitionResultRequest.WaitForStateTransitionResultRequestV0
 */
export interface WaitForStateTransitionResultRequest_WaitForStateTransitionResultRequestV0 {
    /**
     * @generated from protobuf field: bytes state_transition_hash = 1;
     */
    stateTransitionHash: Uint8Array;
    /**
     * @generated from protobuf field: bool prove = 2;
     */
    prove: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.WaitForStateTransitionResultResponse
 */
export interface WaitForStateTransitionResultResponse {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.WaitForStateTransitionResultResponse.WaitForStateTransitionResultResponseV0 v0 = 1;
         */
        v0: WaitForStateTransitionResultResponse_WaitForStateTransitionResultResponseV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.WaitForStateTransitionResultResponse.WaitForStateTransitionResultResponseV0
 */
export interface WaitForStateTransitionResultResponse_WaitForStateTransitionResultResponseV0 {
    /**
     * @generated from protobuf oneof: result
     */
    result: {
        oneofKind: "error";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.StateTransitionBroadcastError error = 1;
         */
        error: StateTransitionBroadcastError;
    } | {
        oneofKind: "proof";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.Proof proof = 2;
         */
        proof: Proof;
    } | {
        oneofKind: undefined;
    };
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.ResponseMetadata metadata = 3;
     */
    metadata?: ResponseMetadata;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetConsensusParamsRequest
 */
export interface GetConsensusParamsRequest {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetConsensusParamsRequest.GetConsensusParamsRequestV0 v0 = 1;
         */
        v0: GetConsensusParamsRequest_GetConsensusParamsRequestV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetConsensusParamsRequest.GetConsensusParamsRequestV0
 */
export interface GetConsensusParamsRequest_GetConsensusParamsRequestV0 {
    /**
     * @generated from protobuf field: int32 height = 1;
     */
    height: number;
    /**
     * @generated from protobuf field: bool prove = 2;
     */
    prove: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetConsensusParamsResponse
 */
export interface GetConsensusParamsResponse {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetConsensusParamsResponse.GetConsensusParamsResponseV0 v0 = 1;
         */
        v0: GetConsensusParamsResponse_GetConsensusParamsResponseV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetConsensusParamsResponse.ConsensusParamsBlock
 */
export interface GetConsensusParamsResponse_ConsensusParamsBlock {
    /**
     * @generated from protobuf field: string max_bytes = 1;
     */
    maxBytes: string;
    /**
     * @generated from protobuf field: string max_gas = 2;
     */
    maxGas: string;
    /**
     * @generated from protobuf field: string time_iota_ms = 3;
     */
    timeIotaMs: string;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetConsensusParamsResponse.ConsensusParamsEvidence
 */
export interface GetConsensusParamsResponse_ConsensusParamsEvidence {
    /**
     * @generated from protobuf field: string max_age_num_blocks = 1;
     */
    maxAgeNumBlocks: string;
    /**
     * @generated from protobuf field: string max_age_duration = 2;
     */
    maxAgeDuration: string;
    /**
     * @generated from protobuf field: string max_bytes = 3;
     */
    maxBytes: string;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetConsensusParamsResponse.GetConsensusParamsResponseV0
 */
export interface GetConsensusParamsResponse_GetConsensusParamsResponseV0 {
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.GetConsensusParamsResponse.ConsensusParamsBlock block = 1;
     */
    block?: GetConsensusParamsResponse_ConsensusParamsBlock;
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.GetConsensusParamsResponse.ConsensusParamsEvidence evidence = 2;
     */
    evidence?: GetConsensusParamsResponse_ConsensusParamsEvidence;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetProtocolVersionUpgradeStateRequest
 */
export interface GetProtocolVersionUpgradeStateRequest {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetProtocolVersionUpgradeStateRequest.GetProtocolVersionUpgradeStateRequestV0 v0 = 1;
         */
        v0: GetProtocolVersionUpgradeStateRequest_GetProtocolVersionUpgradeStateRequestV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetProtocolVersionUpgradeStateRequest.GetProtocolVersionUpgradeStateRequestV0
 */
export interface GetProtocolVersionUpgradeStateRequest_GetProtocolVersionUpgradeStateRequestV0 {
    /**
     * @generated from protobuf field: bool prove = 1;
     */
    prove: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetProtocolVersionUpgradeStateResponse
 */
export interface GetProtocolVersionUpgradeStateResponse {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetProtocolVersionUpgradeStateResponse.GetProtocolVersionUpgradeStateResponseV0 v0 = 1;
         */
        v0: GetProtocolVersionUpgradeStateResponse_GetProtocolVersionUpgradeStateResponseV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetProtocolVersionUpgradeStateResponse.GetProtocolVersionUpgradeStateResponseV0
 */
export interface GetProtocolVersionUpgradeStateResponse_GetProtocolVersionUpgradeStateResponseV0 {
    /**
     * @generated from protobuf oneof: result
     */
    result: {
        oneofKind: "versions";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetProtocolVersionUpgradeStateResponse.GetProtocolVersionUpgradeStateResponseV0.Versions versions = 1;
         */
        versions: GetProtocolVersionUpgradeStateResponse_GetProtocolVersionUpgradeStateResponseV0_Versions;
    } | {
        oneofKind: "proof";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.Proof proof = 2;
         */
        proof: Proof;
    } | {
        oneofKind: undefined;
    };
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.ResponseMetadata metadata = 3;
     */
    metadata?: ResponseMetadata;
}
/**
 * Versions holds a collection of version entries
 *
 * @generated from protobuf message org.dash.platform.dapi.v0.GetProtocolVersionUpgradeStateResponse.GetProtocolVersionUpgradeStateResponseV0.Versions
 */
export interface GetProtocolVersionUpgradeStateResponse_GetProtocolVersionUpgradeStateResponseV0_Versions {
    /**
     * @generated from protobuf field: repeated org.dash.platform.dapi.v0.GetProtocolVersionUpgradeStateResponse.GetProtocolVersionUpgradeStateResponseV0.VersionEntry versions = 1;
     */
    versions: GetProtocolVersionUpgradeStateResponse_GetProtocolVersionUpgradeStateResponseV0_VersionEntry[];
}
/**
 * VersionEntry represents a single entry of a protocol version
 *
 * @generated from protobuf message org.dash.platform.dapi.v0.GetProtocolVersionUpgradeStateResponse.GetProtocolVersionUpgradeStateResponseV0.VersionEntry
 */
export interface GetProtocolVersionUpgradeStateResponse_GetProtocolVersionUpgradeStateResponseV0_VersionEntry {
    /**
     * @generated from protobuf field: uint32 version_number = 1;
     */
    versionNumber: number;
    /**
     * @generated from protobuf field: uint32 vote_count = 2;
     */
    voteCount: number;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetProtocolVersionUpgradeVoteStatusRequest
 */
export interface GetProtocolVersionUpgradeVoteStatusRequest {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetProtocolVersionUpgradeVoteStatusRequest.GetProtocolVersionUpgradeVoteStatusRequestV0 v0 = 1;
         */
        v0: GetProtocolVersionUpgradeVoteStatusRequest_GetProtocolVersionUpgradeVoteStatusRequestV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetProtocolVersionUpgradeVoteStatusRequest.GetProtocolVersionUpgradeVoteStatusRequestV0
 */
export interface GetProtocolVersionUpgradeVoteStatusRequest_GetProtocolVersionUpgradeVoteStatusRequestV0 {
    /**
     * @generated from protobuf field: bytes start_pro_tx_hash = 1;
     */
    startProTxHash: Uint8Array;
    /**
     * @generated from protobuf field: uint32 count = 2;
     */
    count: number;
    /**
     * @generated from protobuf field: bool prove = 3;
     */
    prove: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetProtocolVersionUpgradeVoteStatusResponse
 */
export interface GetProtocolVersionUpgradeVoteStatusResponse {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetProtocolVersionUpgradeVoteStatusResponse.GetProtocolVersionUpgradeVoteStatusResponseV0 v0 = 1;
         */
        v0: GetProtocolVersionUpgradeVoteStatusResponse_GetProtocolVersionUpgradeVoteStatusResponseV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetProtocolVersionUpgradeVoteStatusResponse.GetProtocolVersionUpgradeVoteStatusResponseV0
 */
export interface GetProtocolVersionUpgradeVoteStatusResponse_GetProtocolVersionUpgradeVoteStatusResponseV0 {
    /**
     * @generated from protobuf oneof: result
     */
    result: {
        oneofKind: "versions";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetProtocolVersionUpgradeVoteStatusResponse.GetProtocolVersionUpgradeVoteStatusResponseV0.VersionSignals versions = 1;
         */
        versions: GetProtocolVersionUpgradeVoteStatusResponse_GetProtocolVersionUpgradeVoteStatusResponseV0_VersionSignals;
    } | {
        oneofKind: "proof";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.Proof proof = 2;
         */
        proof: Proof;
    } | {
        oneofKind: undefined;
    };
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.ResponseMetadata metadata = 3;
     */
    metadata?: ResponseMetadata;
}
/**
 * VersionSignals holds a collection of version signal entries
 *
 * @generated from protobuf message org.dash.platform.dapi.v0.GetProtocolVersionUpgradeVoteStatusResponse.GetProtocolVersionUpgradeVoteStatusResponseV0.VersionSignals
 */
export interface GetProtocolVersionUpgradeVoteStatusResponse_GetProtocolVersionUpgradeVoteStatusResponseV0_VersionSignals {
    /**
     * @generated from protobuf field: repeated org.dash.platform.dapi.v0.GetProtocolVersionUpgradeVoteStatusResponse.GetProtocolVersionUpgradeVoteStatusResponseV0.VersionSignal version_signals = 1;
     */
    versionSignals: GetProtocolVersionUpgradeVoteStatusResponse_GetProtocolVersionUpgradeVoteStatusResponseV0_VersionSignal[];
}
/**
 * VersionSignal represents a single voting signal for a protocol version
 *
 * @generated from protobuf message org.dash.platform.dapi.v0.GetProtocolVersionUpgradeVoteStatusResponse.GetProtocolVersionUpgradeVoteStatusResponseV0.VersionSignal
 */
export interface GetProtocolVersionUpgradeVoteStatusResponse_GetProtocolVersionUpgradeVoteStatusResponseV0_VersionSignal {
    /**
     * @generated from protobuf field: bytes pro_tx_hash = 1;
     */
    proTxHash: Uint8Array;
    /**
     * @generated from protobuf field: uint32 version = 2;
     */
    version: number;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetEpochsInfoRequest
 */
export interface GetEpochsInfoRequest {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetEpochsInfoRequest.GetEpochsInfoRequestV0 v0 = 1;
         */
        v0: GetEpochsInfoRequest_GetEpochsInfoRequestV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetEpochsInfoRequest.GetEpochsInfoRequestV0
 */
export interface GetEpochsInfoRequest_GetEpochsInfoRequestV0 {
    /**
     * @generated from protobuf field: google.protobuf.UInt32Value start_epoch = 1;
     */
    startEpoch?: UInt32Value;
    /**
     * @generated from protobuf field: uint32 count = 2;
     */
    count: number;
    /**
     * @generated from protobuf field: bool ascending = 3;
     */
    ascending: boolean;
    /**
     * @generated from protobuf field: bool prove = 4;
     */
    prove: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetEpochsInfoResponse
 */
export interface GetEpochsInfoResponse {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetEpochsInfoResponse.GetEpochsInfoResponseV0 v0 = 1;
         */
        v0: GetEpochsInfoResponse_GetEpochsInfoResponseV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetEpochsInfoResponse.GetEpochsInfoResponseV0
 */
export interface GetEpochsInfoResponse_GetEpochsInfoResponseV0 {
    /**
     * @generated from protobuf oneof: result
     */
    result: {
        oneofKind: "epochs";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetEpochsInfoResponse.GetEpochsInfoResponseV0.EpochInfos epochs = 1;
         */
        epochs: GetEpochsInfoResponse_GetEpochsInfoResponseV0_EpochInfos;
    } | {
        oneofKind: "proof";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.Proof proof = 2;
         */
        proof: Proof;
    } | {
        oneofKind: undefined;
    };
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.ResponseMetadata metadata = 3;
     */
    metadata?: ResponseMetadata;
}
/**
 * EpochInfos holds a collection of epoch information entries
 *
 * @generated from protobuf message org.dash.platform.dapi.v0.GetEpochsInfoResponse.GetEpochsInfoResponseV0.EpochInfos
 */
export interface GetEpochsInfoResponse_GetEpochsInfoResponseV0_EpochInfos {
    /**
     * @generated from protobuf field: repeated org.dash.platform.dapi.v0.GetEpochsInfoResponse.GetEpochsInfoResponseV0.EpochInfo epoch_infos = 1;
     */
    epochInfos: GetEpochsInfoResponse_GetEpochsInfoResponseV0_EpochInfo[];
}
/**
 * EpochInfo represents information about a single epoch
 *
 * @generated from protobuf message org.dash.platform.dapi.v0.GetEpochsInfoResponse.GetEpochsInfoResponseV0.EpochInfo
 */
export interface GetEpochsInfoResponse_GetEpochsInfoResponseV0_EpochInfo {
    /**
     * @generated from protobuf field: uint32 number = 1;
     */
    number: number;
    /**
     * @generated from protobuf field: uint64 first_block_height = 2 [jstype = JS_STRING];
     */
    firstBlockHeight: string;
    /**
     * @generated from protobuf field: uint32 first_core_block_height = 3;
     */
    firstCoreBlockHeight: number;
    /**
     * @generated from protobuf field: uint64 start_time = 4 [jstype = JS_STRING];
     */
    startTime: string;
    /**
     * @generated from protobuf field: double fee_multiplier = 5;
     */
    feeMultiplier: number;
    /**
     * @generated from protobuf field: uint32 protocol_version = 6;
     */
    protocolVersion: number;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetContestedResourcesRequest
 */
export interface GetContestedResourcesRequest {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetContestedResourcesRequest.GetContestedResourcesRequestV0 v0 = 1;
         */
        v0: GetContestedResourcesRequest_GetContestedResourcesRequestV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetContestedResourcesRequest.GetContestedResourcesRequestV0
 */
export interface GetContestedResourcesRequest_GetContestedResourcesRequestV0 {
    /**
     * @generated from protobuf field: bytes contract_id = 1;
     */
    contractId: Uint8Array;
    /**
     * @generated from protobuf field: string document_type_name = 2;
     */
    documentTypeName: string;
    /**
     * @generated from protobuf field: string index_name = 3;
     */
    indexName: string;
    /**
     * @generated from protobuf field: repeated bytes start_index_values = 4;
     */
    startIndexValues: Uint8Array[];
    /**
     * @generated from protobuf field: repeated bytes end_index_values = 5;
     */
    endIndexValues: Uint8Array[];
    /**
     * @generated from protobuf field: optional org.dash.platform.dapi.v0.GetContestedResourcesRequest.GetContestedResourcesRequestV0.StartAtValueInfo start_at_value_info = 6;
     */
    startAtValueInfo?: GetContestedResourcesRequest_GetContestedResourcesRequestV0_StartAtValueInfo;
    /**
     * @generated from protobuf field: optional uint32 count = 7;
     */
    count?: number;
    /**
     * @generated from protobuf field: bool order_ascending = 8;
     */
    orderAscending: boolean;
    /**
     * @generated from protobuf field: bool prove = 9;
     */
    prove: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetContestedResourcesRequest.GetContestedResourcesRequestV0.StartAtValueInfo
 */
export interface GetContestedResourcesRequest_GetContestedResourcesRequestV0_StartAtValueInfo {
    /**
     * @generated from protobuf field: bytes start_value = 1;
     */
    startValue: Uint8Array;
    /**
     * @generated from protobuf field: bool start_value_included = 2;
     */
    startValueIncluded: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetContestedResourcesResponse
 */
export interface GetContestedResourcesResponse {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetContestedResourcesResponse.GetContestedResourcesResponseV0 v0 = 1;
         */
        v0: GetContestedResourcesResponse_GetContestedResourcesResponseV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetContestedResourcesResponse.GetContestedResourcesResponseV0
 */
export interface GetContestedResourcesResponse_GetContestedResourcesResponseV0 {
    /**
     * @generated from protobuf oneof: result
     */
    result: {
        oneofKind: "contestedResourceValues";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetContestedResourcesResponse.GetContestedResourcesResponseV0.ContestedResourceValues contested_resource_values = 1;
         */
        contestedResourceValues: GetContestedResourcesResponse_GetContestedResourcesResponseV0_ContestedResourceValues;
    } | {
        oneofKind: "proof";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.Proof proof = 2;
         */
        proof: Proof;
    } | {
        oneofKind: undefined;
    };
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.ResponseMetadata metadata = 3;
     */
    metadata?: ResponseMetadata;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetContestedResourcesResponse.GetContestedResourcesResponseV0.ContestedResourceValues
 */
export interface GetContestedResourcesResponse_GetContestedResourcesResponseV0_ContestedResourceValues {
    /**
     * @generated from protobuf field: repeated bytes contested_resource_values = 1;
     */
    contestedResourceValues: Uint8Array[];
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetVotePollsByEndDateRequest
 */
export interface GetVotePollsByEndDateRequest {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetVotePollsByEndDateRequest.GetVotePollsByEndDateRequestV0 v0 = 1;
         */
        v0: GetVotePollsByEndDateRequest_GetVotePollsByEndDateRequestV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetVotePollsByEndDateRequest.GetVotePollsByEndDateRequestV0
 */
export interface GetVotePollsByEndDateRequest_GetVotePollsByEndDateRequestV0 {
    /**
     * @generated from protobuf field: optional org.dash.platform.dapi.v0.GetVotePollsByEndDateRequest.GetVotePollsByEndDateRequestV0.StartAtTimeInfo start_time_info = 1;
     */
    startTimeInfo?: GetVotePollsByEndDateRequest_GetVotePollsByEndDateRequestV0_StartAtTimeInfo;
    /**
     * @generated from protobuf field: optional org.dash.platform.dapi.v0.GetVotePollsByEndDateRequest.GetVotePollsByEndDateRequestV0.EndAtTimeInfo end_time_info = 2;
     */
    endTimeInfo?: GetVotePollsByEndDateRequest_GetVotePollsByEndDateRequestV0_EndAtTimeInfo;
    /**
     * @generated from protobuf field: optional uint32 limit = 3;
     */
    limit?: number;
    /**
     * @generated from protobuf field: optional uint32 offset = 4;
     */
    offset?: number;
    /**
     * @generated from protobuf field: bool ascending = 5;
     */
    ascending: boolean;
    /**
     * @generated from protobuf field: bool prove = 6;
     */
    prove: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetVotePollsByEndDateRequest.GetVotePollsByEndDateRequestV0.StartAtTimeInfo
 */
export interface GetVotePollsByEndDateRequest_GetVotePollsByEndDateRequestV0_StartAtTimeInfo {
    /**
     * @generated from protobuf field: uint64 start_time_ms = 1 [jstype = JS_STRING];
     */
    startTimeMs: string;
    /**
     * @generated from protobuf field: bool start_time_included = 2;
     */
    startTimeIncluded: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetVotePollsByEndDateRequest.GetVotePollsByEndDateRequestV0.EndAtTimeInfo
 */
export interface GetVotePollsByEndDateRequest_GetVotePollsByEndDateRequestV0_EndAtTimeInfo {
    /**
     * @generated from protobuf field: uint64 end_time_ms = 1 [jstype = JS_STRING];
     */
    endTimeMs: string;
    /**
     * @generated from protobuf field: bool end_time_included = 2;
     */
    endTimeIncluded: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetVotePollsByEndDateResponse
 */
export interface GetVotePollsByEndDateResponse {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetVotePollsByEndDateResponse.GetVotePollsByEndDateResponseV0 v0 = 1;
         */
        v0: GetVotePollsByEndDateResponse_GetVotePollsByEndDateResponseV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetVotePollsByEndDateResponse.GetVotePollsByEndDateResponseV0
 */
export interface GetVotePollsByEndDateResponse_GetVotePollsByEndDateResponseV0 {
    /**
     * @generated from protobuf oneof: result
     */
    result: {
        oneofKind: "votePollsByTimestamps";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetVotePollsByEndDateResponse.GetVotePollsByEndDateResponseV0.SerializedVotePollsByTimestamps vote_polls_by_timestamps = 1;
         */
        votePollsByTimestamps: GetVotePollsByEndDateResponse_GetVotePollsByEndDateResponseV0_SerializedVotePollsByTimestamps;
    } | {
        oneofKind: "proof";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.Proof proof = 2;
         */
        proof: Proof;
    } | {
        oneofKind: undefined;
    };
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.ResponseMetadata metadata = 3;
     */
    metadata?: ResponseMetadata;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetVotePollsByEndDateResponse.GetVotePollsByEndDateResponseV0.SerializedVotePollsByTimestamp
 */
export interface GetVotePollsByEndDateResponse_GetVotePollsByEndDateResponseV0_SerializedVotePollsByTimestamp {
    /**
     * @generated from protobuf field: uint64 timestamp = 1 [jstype = JS_STRING];
     */
    timestamp: string;
    /**
     * @generated from protobuf field: repeated bytes serialized_vote_polls = 2;
     */
    serializedVotePolls: Uint8Array[];
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetVotePollsByEndDateResponse.GetVotePollsByEndDateResponseV0.SerializedVotePollsByTimestamps
 */
export interface GetVotePollsByEndDateResponse_GetVotePollsByEndDateResponseV0_SerializedVotePollsByTimestamps {
    /**
     * @generated from protobuf field: repeated org.dash.platform.dapi.v0.GetVotePollsByEndDateResponse.GetVotePollsByEndDateResponseV0.SerializedVotePollsByTimestamp vote_polls_by_timestamps = 1;
     */
    votePollsByTimestamps: GetVotePollsByEndDateResponse_GetVotePollsByEndDateResponseV0_SerializedVotePollsByTimestamp[];
    /**
     * @generated from protobuf field: bool finished_results = 2;
     */
    finishedResults: boolean;
}
/**
 * What's the state of a contested resource vote? (ie who is winning?)
 *
 * @generated from protobuf message org.dash.platform.dapi.v0.GetContestedResourceVoteStateRequest
 */
export interface GetContestedResourceVoteStateRequest {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetContestedResourceVoteStateRequest.GetContestedResourceVoteStateRequestV0 v0 = 1;
         */
        v0: GetContestedResourceVoteStateRequest_GetContestedResourceVoteStateRequestV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetContestedResourceVoteStateRequest.GetContestedResourceVoteStateRequestV0
 */
export interface GetContestedResourceVoteStateRequest_GetContestedResourceVoteStateRequestV0 {
    /**
     * @generated from protobuf field: bytes contract_id = 1;
     */
    contractId: Uint8Array;
    /**
     * @generated from protobuf field: string document_type_name = 2;
     */
    documentTypeName: string;
    /**
     * @generated from protobuf field: string index_name = 3;
     */
    indexName: string;
    /**
     * @generated from protobuf field: repeated bytes index_values = 4;
     */
    indexValues: Uint8Array[];
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.GetContestedResourceVoteStateRequest.GetContestedResourceVoteStateRequestV0.ResultType result_type = 5;
     */
    resultType: GetContestedResourceVoteStateRequest_GetContestedResourceVoteStateRequestV0_ResultType;
    /**
     * @generated from protobuf field: bool allow_include_locked_and_abstaining_vote_tally = 6;
     */
    allowIncludeLockedAndAbstainingVoteTally: boolean;
    /**
     * @generated from protobuf field: optional org.dash.platform.dapi.v0.GetContestedResourceVoteStateRequest.GetContestedResourceVoteStateRequestV0.StartAtIdentifierInfo start_at_identifier_info = 7;
     */
    startAtIdentifierInfo?: GetContestedResourceVoteStateRequest_GetContestedResourceVoteStateRequestV0_StartAtIdentifierInfo;
    /**
     * @generated from protobuf field: optional uint32 count = 8;
     */
    count?: number;
    /**
     * @generated from protobuf field: bool prove = 9;
     */
    prove: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetContestedResourceVoteStateRequest.GetContestedResourceVoteStateRequestV0.StartAtIdentifierInfo
 */
export interface GetContestedResourceVoteStateRequest_GetContestedResourceVoteStateRequestV0_StartAtIdentifierInfo {
    /**
     * @generated from protobuf field: bytes start_identifier = 1;
     */
    startIdentifier: Uint8Array;
    /**
     * @generated from protobuf field: bool start_identifier_included = 2;
     */
    startIdentifierIncluded: boolean;
}
/**
 * @generated from protobuf enum org.dash.platform.dapi.v0.GetContestedResourceVoteStateRequest.GetContestedResourceVoteStateRequestV0.ResultType
 */
export declare enum GetContestedResourceVoteStateRequest_GetContestedResourceVoteStateRequestV0_ResultType {
    /**
     * @generated from protobuf enum value: DOCUMENTS = 0;
     */
    DOCUMENTS = 0,
    /**
     * @generated from protobuf enum value: VOTE_TALLY = 1;
     */
    VOTE_TALLY = 1,
    /**
     * @generated from protobuf enum value: DOCUMENTS_AND_VOTE_TALLY = 2;
     */
    DOCUMENTS_AND_VOTE_TALLY = 2
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetContestedResourceVoteStateResponse
 */
export interface GetContestedResourceVoteStateResponse {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetContestedResourceVoteStateResponse.GetContestedResourceVoteStateResponseV0 v0 = 1;
         */
        v0: GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetContestedResourceVoteStateResponse.GetContestedResourceVoteStateResponseV0
 */
export interface GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0 {
    /**
     * @generated from protobuf oneof: result
     */
    result: {
        oneofKind: "contestedResourceContenders";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetContestedResourceVoteStateResponse.GetContestedResourceVoteStateResponseV0.ContestedResourceContenders contested_resource_contenders = 1;
         */
        contestedResourceContenders: GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0_ContestedResourceContenders;
    } | {
        oneofKind: "proof";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.Proof proof = 2;
         */
        proof: Proof;
    } | {
        oneofKind: undefined;
    };
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.ResponseMetadata metadata = 3;
     */
    metadata?: ResponseMetadata;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetContestedResourceVoteStateResponse.GetContestedResourceVoteStateResponseV0.FinishedVoteInfo
 */
export interface GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0_FinishedVoteInfo {
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.GetContestedResourceVoteStateResponse.GetContestedResourceVoteStateResponseV0.FinishedVoteInfo.FinishedVoteOutcome finished_vote_outcome = 1;
     */
    finishedVoteOutcome: GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0_FinishedVoteInfo_FinishedVoteOutcome;
    /**
     * @generated from protobuf field: optional bytes won_by_identity_id = 2;
     */
    wonByIdentityId?: Uint8Array;
    /**
     * @generated from protobuf field: uint64 finished_at_block_height = 3 [jstype = JS_STRING];
     */
    finishedAtBlockHeight: string;
    /**
     * @generated from protobuf field: uint32 finished_at_core_block_height = 4;
     */
    finishedAtCoreBlockHeight: number;
    /**
     * @generated from protobuf field: uint64 finished_at_block_time_ms = 5 [jstype = JS_STRING];
     */
    finishedAtBlockTimeMs: string;
    /**
     * @generated from protobuf field: uint32 finished_at_epoch = 6;
     */
    finishedAtEpoch: number;
}
/**
 * @generated from protobuf enum org.dash.platform.dapi.v0.GetContestedResourceVoteStateResponse.GetContestedResourceVoteStateResponseV0.FinishedVoteInfo.FinishedVoteOutcome
 */
export declare enum GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0_FinishedVoteInfo_FinishedVoteOutcome {
    /**
     * @generated from protobuf enum value: TOWARDS_IDENTITY = 0;
     */
    TOWARDS_IDENTITY = 0,
    /**
     * @generated from protobuf enum value: LOCKED = 1;
     */
    LOCKED = 1,
    /**
     * @generated from protobuf enum value: NO_PREVIOUS_WINNER = 2;
     */
    NO_PREVIOUS_WINNER = 2
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetContestedResourceVoteStateResponse.GetContestedResourceVoteStateResponseV0.ContestedResourceContenders
 */
export interface GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0_ContestedResourceContenders {
    /**
     * @generated from protobuf field: repeated org.dash.platform.dapi.v0.GetContestedResourceVoteStateResponse.GetContestedResourceVoteStateResponseV0.Contender contenders = 1;
     */
    contenders: GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0_Contender[];
    /**
     * @generated from protobuf field: optional uint32 abstain_vote_tally = 2;
     */
    abstainVoteTally?: number;
    /**
     * @generated from protobuf field: optional uint32 lock_vote_tally = 3;
     */
    lockVoteTally?: number;
    /**
     * @generated from protobuf field: optional org.dash.platform.dapi.v0.GetContestedResourceVoteStateResponse.GetContestedResourceVoteStateResponseV0.FinishedVoteInfo finished_vote_info = 4;
     */
    finishedVoteInfo?: GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0_FinishedVoteInfo;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetContestedResourceVoteStateResponse.GetContestedResourceVoteStateResponseV0.Contender
 */
export interface GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0_Contender {
    /**
     * @generated from protobuf field: bytes identifier = 1;
     */
    identifier: Uint8Array;
    /**
     * @generated from protobuf field: optional uint32 vote_count = 2;
     */
    voteCount?: number;
    /**
     * @generated from protobuf field: optional bytes document = 3;
     */
    document?: Uint8Array;
}
/**
 * Who voted for a contested resource to go to a specific identity?
 *
 * @generated from protobuf message org.dash.platform.dapi.v0.GetContestedResourceVotersForIdentityRequest
 */
export interface GetContestedResourceVotersForIdentityRequest {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetContestedResourceVotersForIdentityRequest.GetContestedResourceVotersForIdentityRequestV0 v0 = 1;
         */
        v0: GetContestedResourceVotersForIdentityRequest_GetContestedResourceVotersForIdentityRequestV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetContestedResourceVotersForIdentityRequest.GetContestedResourceVotersForIdentityRequestV0
 */
export interface GetContestedResourceVotersForIdentityRequest_GetContestedResourceVotersForIdentityRequestV0 {
    /**
     * @generated from protobuf field: bytes contract_id = 1;
     */
    contractId: Uint8Array;
    /**
     * @generated from protobuf field: string document_type_name = 2;
     */
    documentTypeName: string;
    /**
     * @generated from protobuf field: string index_name = 3;
     */
    indexName: string;
    /**
     * @generated from protobuf field: repeated bytes index_values = 4;
     */
    indexValues: Uint8Array[];
    /**
     * @generated from protobuf field: bytes contestant_id = 5;
     */
    contestantId: Uint8Array;
    /**
     * @generated from protobuf field: optional org.dash.platform.dapi.v0.GetContestedResourceVotersForIdentityRequest.GetContestedResourceVotersForIdentityRequestV0.StartAtIdentifierInfo start_at_identifier_info = 6;
     */
    startAtIdentifierInfo?: GetContestedResourceVotersForIdentityRequest_GetContestedResourceVotersForIdentityRequestV0_StartAtIdentifierInfo;
    /**
     * @generated from protobuf field: optional uint32 count = 7;
     */
    count?: number;
    /**
     * @generated from protobuf field: bool order_ascending = 8;
     */
    orderAscending: boolean;
    /**
     * @generated from protobuf field: bool prove = 9;
     */
    prove: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetContestedResourceVotersForIdentityRequest.GetContestedResourceVotersForIdentityRequestV0.StartAtIdentifierInfo
 */
export interface GetContestedResourceVotersForIdentityRequest_GetContestedResourceVotersForIdentityRequestV0_StartAtIdentifierInfo {
    /**
     * @generated from protobuf field: bytes start_identifier = 1;
     */
    startIdentifier: Uint8Array;
    /**
     * @generated from protobuf field: bool start_identifier_included = 2;
     */
    startIdentifierIncluded: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetContestedResourceVotersForIdentityResponse
 */
export interface GetContestedResourceVotersForIdentityResponse {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetContestedResourceVotersForIdentityResponse.GetContestedResourceVotersForIdentityResponseV0 v0 = 1;
         */
        v0: GetContestedResourceVotersForIdentityResponse_GetContestedResourceVotersForIdentityResponseV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetContestedResourceVotersForIdentityResponse.GetContestedResourceVotersForIdentityResponseV0
 */
export interface GetContestedResourceVotersForIdentityResponse_GetContestedResourceVotersForIdentityResponseV0 {
    /**
     * @generated from protobuf oneof: result
     */
    result: {
        oneofKind: "contestedResourceVoters";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetContestedResourceVotersForIdentityResponse.GetContestedResourceVotersForIdentityResponseV0.ContestedResourceVoters contested_resource_voters = 1;
         */
        contestedResourceVoters: GetContestedResourceVotersForIdentityResponse_GetContestedResourceVotersForIdentityResponseV0_ContestedResourceVoters;
    } | {
        oneofKind: "proof";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.Proof proof = 2;
         */
        proof: Proof;
    } | {
        oneofKind: undefined;
    };
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.ResponseMetadata metadata = 3;
     */
    metadata?: ResponseMetadata;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetContestedResourceVotersForIdentityResponse.GetContestedResourceVotersForIdentityResponseV0.ContestedResourceVoters
 */
export interface GetContestedResourceVotersForIdentityResponse_GetContestedResourceVotersForIdentityResponseV0_ContestedResourceVoters {
    /**
     * @generated from protobuf field: repeated bytes voters = 1;
     */
    voters: Uint8Array[];
    /**
     * @generated from protobuf field: bool finished_results = 2;
     */
    finishedResults: boolean;
}
/**
 * How did an identity vote?
 *
 * @generated from protobuf message org.dash.platform.dapi.v0.GetContestedResourceIdentityVotesRequest
 */
export interface GetContestedResourceIdentityVotesRequest {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetContestedResourceIdentityVotesRequest.GetContestedResourceIdentityVotesRequestV0 v0 = 1;
         */
        v0: GetContestedResourceIdentityVotesRequest_GetContestedResourceIdentityVotesRequestV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetContestedResourceIdentityVotesRequest.GetContestedResourceIdentityVotesRequestV0
 */
export interface GetContestedResourceIdentityVotesRequest_GetContestedResourceIdentityVotesRequestV0 {
    /**
     * @generated from protobuf field: bytes identity_id = 1;
     */
    identityId: Uint8Array;
    /**
     * @generated from protobuf field: google.protobuf.UInt32Value limit = 2;
     */
    limit?: UInt32Value;
    /**
     * @generated from protobuf field: google.protobuf.UInt32Value offset = 3;
     */
    offset?: UInt32Value;
    /**
     * @generated from protobuf field: bool order_ascending = 4;
     */
    orderAscending: boolean;
    /**
     * @generated from protobuf field: optional org.dash.platform.dapi.v0.GetContestedResourceIdentityVotesRequest.GetContestedResourceIdentityVotesRequestV0.StartAtVotePollIdInfo start_at_vote_poll_id_info = 5;
     */
    startAtVotePollIdInfo?: GetContestedResourceIdentityVotesRequest_GetContestedResourceIdentityVotesRequestV0_StartAtVotePollIdInfo;
    /**
     * @generated from protobuf field: bool prove = 6;
     */
    prove: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetContestedResourceIdentityVotesRequest.GetContestedResourceIdentityVotesRequestV0.StartAtVotePollIdInfo
 */
export interface GetContestedResourceIdentityVotesRequest_GetContestedResourceIdentityVotesRequestV0_StartAtVotePollIdInfo {
    /**
     * @generated from protobuf field: bytes start_at_poll_identifier = 1;
     */
    startAtPollIdentifier: Uint8Array;
    /**
     * @generated from protobuf field: bool start_poll_identifier_included = 2;
     */
    startPollIdentifierIncluded: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetContestedResourceIdentityVotesResponse
 */
export interface GetContestedResourceIdentityVotesResponse {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetContestedResourceIdentityVotesResponse.GetContestedResourceIdentityVotesResponseV0 v0 = 1;
         */
        v0: GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetContestedResourceIdentityVotesResponse.GetContestedResourceIdentityVotesResponseV0
 */
export interface GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0 {
    /**
     * @generated from protobuf oneof: result
     */
    result: {
        oneofKind: "votes";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetContestedResourceIdentityVotesResponse.GetContestedResourceIdentityVotesResponseV0.ContestedResourceIdentityVotes votes = 1;
         */
        votes: GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0_ContestedResourceIdentityVotes;
    } | {
        oneofKind: "proof";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.Proof proof = 2;
         */
        proof: Proof;
    } | {
        oneofKind: undefined;
    };
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.ResponseMetadata metadata = 3;
     */
    metadata?: ResponseMetadata;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetContestedResourceIdentityVotesResponse.GetContestedResourceIdentityVotesResponseV0.ContestedResourceIdentityVotes
 */
export interface GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0_ContestedResourceIdentityVotes {
    /**
     * @generated from protobuf field: repeated org.dash.platform.dapi.v0.GetContestedResourceIdentityVotesResponse.GetContestedResourceIdentityVotesResponseV0.ContestedResourceIdentityVote contested_resource_identity_votes = 1;
     */
    contestedResourceIdentityVotes: GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0_ContestedResourceIdentityVote[];
    /**
     * @generated from protobuf field: bool finished_results = 2;
     */
    finishedResults: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetContestedResourceIdentityVotesResponse.GetContestedResourceIdentityVotesResponseV0.ResourceVoteChoice
 */
export interface GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0_ResourceVoteChoice {
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.GetContestedResourceIdentityVotesResponse.GetContestedResourceIdentityVotesResponseV0.ResourceVoteChoice.VoteChoiceType vote_choice_type = 1;
     */
    voteChoiceType: GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0_ResourceVoteChoice_VoteChoiceType;
    /**
     * @generated from protobuf field: optional bytes identity_id = 2;
     */
    identityId?: Uint8Array;
}
/**
 * @generated from protobuf enum org.dash.platform.dapi.v0.GetContestedResourceIdentityVotesResponse.GetContestedResourceIdentityVotesResponseV0.ResourceVoteChoice.VoteChoiceType
 */
export declare enum GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0_ResourceVoteChoice_VoteChoiceType {
    /**
     * @generated from protobuf enum value: TOWARDS_IDENTITY = 0;
     */
    TOWARDS_IDENTITY = 0,
    /**
     * @generated from protobuf enum value: ABSTAIN = 1;
     */
    ABSTAIN = 1,
    /**
     * @generated from protobuf enum value: LOCK = 2;
     */
    LOCK = 2
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetContestedResourceIdentityVotesResponse.GetContestedResourceIdentityVotesResponseV0.ContestedResourceIdentityVote
 */
export interface GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0_ContestedResourceIdentityVote {
    /**
     * @generated from protobuf field: bytes contract_id = 1;
     */
    contractId: Uint8Array;
    /**
     * @generated from protobuf field: string document_type_name = 2;
     */
    documentTypeName: string;
    /**
     * @generated from protobuf field: repeated bytes serialized_index_storage_values = 3;
     */
    serializedIndexStorageValues: Uint8Array[];
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.GetContestedResourceIdentityVotesResponse.GetContestedResourceIdentityVotesResponseV0.ResourceVoteChoice vote_choice = 4;
     */
    voteChoice?: GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0_ResourceVoteChoice;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetPrefundedSpecializedBalanceRequest
 */
export interface GetPrefundedSpecializedBalanceRequest {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetPrefundedSpecializedBalanceRequest.GetPrefundedSpecializedBalanceRequestV0 v0 = 1;
         */
        v0: GetPrefundedSpecializedBalanceRequest_GetPrefundedSpecializedBalanceRequestV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetPrefundedSpecializedBalanceRequest.GetPrefundedSpecializedBalanceRequestV0
 */
export interface GetPrefundedSpecializedBalanceRequest_GetPrefundedSpecializedBalanceRequestV0 {
    /**
     * @generated from protobuf field: bytes id = 1;
     */
    id: Uint8Array;
    /**
     * @generated from protobuf field: bool prove = 2;
     */
    prove: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetPrefundedSpecializedBalanceResponse
 */
export interface GetPrefundedSpecializedBalanceResponse {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetPrefundedSpecializedBalanceResponse.GetPrefundedSpecializedBalanceResponseV0 v0 = 1;
         */
        v0: GetPrefundedSpecializedBalanceResponse_GetPrefundedSpecializedBalanceResponseV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetPrefundedSpecializedBalanceResponse.GetPrefundedSpecializedBalanceResponseV0
 */
export interface GetPrefundedSpecializedBalanceResponse_GetPrefundedSpecializedBalanceResponseV0 {
    /**
     * @generated from protobuf oneof: result
     */
    result: {
        oneofKind: "balance";
        /**
         * @generated from protobuf field: uint64 balance = 1 [jstype = JS_STRING];
         */
        balance: string;
    } | {
        oneofKind: "proof";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.Proof proof = 2;
         */
        proof: Proof;
    } | {
        oneofKind: undefined;
    };
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.ResponseMetadata metadata = 3;
     */
    metadata?: ResponseMetadata;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetTotalCreditsInPlatformRequest
 */
export interface GetTotalCreditsInPlatformRequest {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetTotalCreditsInPlatformRequest.GetTotalCreditsInPlatformRequestV0 v0 = 1;
         */
        v0: GetTotalCreditsInPlatformRequest_GetTotalCreditsInPlatformRequestV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetTotalCreditsInPlatformRequest.GetTotalCreditsInPlatformRequestV0
 */
export interface GetTotalCreditsInPlatformRequest_GetTotalCreditsInPlatformRequestV0 {
    /**
     * @generated from protobuf field: bool prove = 1;
     */
    prove: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetTotalCreditsInPlatformResponse
 */
export interface GetTotalCreditsInPlatformResponse {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetTotalCreditsInPlatformResponse.GetTotalCreditsInPlatformResponseV0 v0 = 1;
         */
        v0: GetTotalCreditsInPlatformResponse_GetTotalCreditsInPlatformResponseV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetTotalCreditsInPlatformResponse.GetTotalCreditsInPlatformResponseV0
 */
export interface GetTotalCreditsInPlatformResponse_GetTotalCreditsInPlatformResponseV0 {
    /**
     * @generated from protobuf oneof: result
     */
    result: {
        oneofKind: "credits";
        /**
         * @generated from protobuf field: uint64 credits = 1 [jstype = JS_STRING];
         */
        credits: string;
    } | {
        oneofKind: "proof";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.Proof proof = 2;
         */
        proof: Proof;
    } | {
        oneofKind: undefined;
    };
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.ResponseMetadata metadata = 3;
     */
    metadata?: ResponseMetadata;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetPathElementsRequest
 */
export interface GetPathElementsRequest {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetPathElementsRequest.GetPathElementsRequestV0 v0 = 1;
         */
        v0: GetPathElementsRequest_GetPathElementsRequestV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetPathElementsRequest.GetPathElementsRequestV0
 */
export interface GetPathElementsRequest_GetPathElementsRequestV0 {
    /**
     * @generated from protobuf field: repeated bytes path = 1;
     */
    path: Uint8Array[];
    /**
     * @generated from protobuf field: repeated bytes keys = 2;
     */
    keys: Uint8Array[];
    /**
     * @generated from protobuf field: bool prove = 3;
     */
    prove: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetPathElementsResponse
 */
export interface GetPathElementsResponse {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetPathElementsResponse.GetPathElementsResponseV0 v0 = 1;
         */
        v0: GetPathElementsResponse_GetPathElementsResponseV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetPathElementsResponse.GetPathElementsResponseV0
 */
export interface GetPathElementsResponse_GetPathElementsResponseV0 {
    /**
     * @generated from protobuf oneof: result
     */
    result: {
        oneofKind: "elements";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetPathElementsResponse.GetPathElementsResponseV0.Elements elements = 1;
         */
        elements: GetPathElementsResponse_GetPathElementsResponseV0_Elements;
    } | {
        oneofKind: "proof";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.Proof proof = 2;
         */
        proof: Proof;
    } | {
        oneofKind: undefined;
    };
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.ResponseMetadata metadata = 3;
     */
    metadata?: ResponseMetadata;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetPathElementsResponse.GetPathElementsResponseV0.Elements
 */
export interface GetPathElementsResponse_GetPathElementsResponseV0_Elements {
    /**
     * @generated from protobuf field: repeated bytes elements = 1;
     */
    elements: Uint8Array[];
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetStatusRequest
 */
export interface GetStatusRequest {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetStatusRequest.GetStatusRequestV0 v0 = 1;
         */
        v0: GetStatusRequest_GetStatusRequestV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetStatusRequest.GetStatusRequestV0
 */
export interface GetStatusRequest_GetStatusRequestV0 {
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetStatusResponse
 */
export interface GetStatusResponse {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetStatusResponse.GetStatusResponseV0 v0 = 1;
         */
        v0: GetStatusResponse_GetStatusResponseV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetStatusResponse.GetStatusResponseV0
 */
export interface GetStatusResponse_GetStatusResponseV0 {
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.GetStatusResponse.GetStatusResponseV0.Version version = 1;
     */
    version?: GetStatusResponse_GetStatusResponseV0_Version;
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.GetStatusResponse.GetStatusResponseV0.Node node = 2;
     */
    node?: GetStatusResponse_GetStatusResponseV0_Node;
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.GetStatusResponse.GetStatusResponseV0.Chain chain = 3;
     */
    chain?: GetStatusResponse_GetStatusResponseV0_Chain;
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.GetStatusResponse.GetStatusResponseV0.Network network = 4;
     */
    network?: GetStatusResponse_GetStatusResponseV0_Network;
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.GetStatusResponse.GetStatusResponseV0.StateSync state_sync = 5;
     */
    stateSync?: GetStatusResponse_GetStatusResponseV0_StateSync;
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.GetStatusResponse.GetStatusResponseV0.Time time = 6;
     */
    time?: GetStatusResponse_GetStatusResponseV0_Time;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetStatusResponse.GetStatusResponseV0.Version
 */
export interface GetStatusResponse_GetStatusResponseV0_Version {
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.GetStatusResponse.GetStatusResponseV0.Version.Software software = 1;
     */
    software?: GetStatusResponse_GetStatusResponseV0_Version_Software;
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.GetStatusResponse.GetStatusResponseV0.Version.Protocol protocol = 2;
     */
    protocol?: GetStatusResponse_GetStatusResponseV0_Version_Protocol;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetStatusResponse.GetStatusResponseV0.Version.Software
 */
export interface GetStatusResponse_GetStatusResponseV0_Version_Software {
    /**
     * @generated from protobuf field: string dapi = 1;
     */
    dapi: string;
    /**
     * It will be missing if Drive is not responding
     *
     * @generated from protobuf field: optional string drive = 2;
     */
    drive?: string;
    /**
     * It will be missing if Tenderdash is not responding
     *
     * @generated from protobuf field: optional string tenderdash = 3;
     */
    tenderdash?: string;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetStatusResponse.GetStatusResponseV0.Version.Protocol
 */
export interface GetStatusResponse_GetStatusResponseV0_Version_Protocol {
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.GetStatusResponse.GetStatusResponseV0.Version.Protocol.Tenderdash tenderdash = 1;
     */
    tenderdash?: GetStatusResponse_GetStatusResponseV0_Version_Protocol_Tenderdash;
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.GetStatusResponse.GetStatusResponseV0.Version.Protocol.Drive drive = 2;
     */
    drive?: GetStatusResponse_GetStatusResponseV0_Version_Protocol_Drive;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetStatusResponse.GetStatusResponseV0.Version.Protocol.Tenderdash
 */
export interface GetStatusResponse_GetStatusResponseV0_Version_Protocol_Tenderdash {
    /**
     * @generated from protobuf field: uint32 p2p = 1 [json_name = "p2p"];
     */
    p2P: number;
    /**
     * @generated from protobuf field: uint32 block = 2;
     */
    block: number;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetStatusResponse.GetStatusResponseV0.Version.Protocol.Drive
 */
export interface GetStatusResponse_GetStatusResponseV0_Version_Protocol_Drive {
    /**
     * @generated from protobuf field: uint32 latest = 3;
     */
    latest: number;
    /**
     * @generated from protobuf field: uint32 current = 4;
     */
    current: number;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetStatusResponse.GetStatusResponseV0.Time
 */
export interface GetStatusResponse_GetStatusResponseV0_Time {
    /**
     * @generated from protobuf field: uint64 local = 1 [jstype = JS_STRING];
     */
    local: string;
    /**
     * It will be missing if Drive is not responding
     *
     * @generated from protobuf field: optional uint64 block = 2 [jstype = JS_STRING];
     */
    block?: string;
    /**
     * It will be missing if Drive is not responding
     *
     * @generated from protobuf field: optional uint64 genesis = 3 [jstype = JS_STRING];
     */
    genesis?: string;
    /**
     * It will be missing if Drive is not responding
     *
     * @generated from protobuf field: optional uint32 epoch = 4;
     */
    epoch?: number;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetStatusResponse.GetStatusResponseV0.Node
 */
export interface GetStatusResponse_GetStatusResponseV0_Node {
    /**
     * Platform node ID
     *
     * @generated from protobuf field: bytes id = 1;
     */
    id: Uint8Array;
    /**
     * Evo masternode pro tx hash. It will be absent if the node is a fullnode
     *
     * @generated from protobuf field: optional bytes pro_tx_hash = 2;
     */
    proTxHash?: Uint8Array;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetStatusResponse.GetStatusResponseV0.Chain
 */
export interface GetStatusResponse_GetStatusResponseV0_Chain {
    /**
     * @generated from protobuf field: bool catching_up = 1;
     */
    catchingUp: boolean;
    /**
     * @generated from protobuf field: bytes latest_block_hash = 2;
     */
    latestBlockHash: Uint8Array;
    /**
     * @generated from protobuf field: bytes latest_app_hash = 3;
     */
    latestAppHash: Uint8Array;
    /**
     * @generated from protobuf field: uint64 latest_block_height = 4 [jstype = JS_STRING];
     */
    latestBlockHeight: string;
    /**
     * @generated from protobuf field: bytes earliest_block_hash = 5;
     */
    earliestBlockHash: Uint8Array;
    /**
     * @generated from protobuf field: bytes earliest_app_hash = 6;
     */
    earliestAppHash: Uint8Array;
    /**
     * @generated from protobuf field: uint64 earliest_block_height = 7 [jstype = JS_STRING];
     */
    earliestBlockHeight: string;
    /**
     * @generated from protobuf field: uint64 max_peer_block_height = 9 [jstype = JS_STRING];
     */
    maxPeerBlockHeight: string;
    /**
     * Latest known core height in consensus.
     * It will be missing if Drive is not responding
     *
     * @generated from protobuf field: optional uint32 core_chain_locked_height = 10;
     */
    coreChainLockedHeight?: number;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetStatusResponse.GetStatusResponseV0.Network
 */
export interface GetStatusResponse_GetStatusResponseV0_Network {
    /**
     * @generated from protobuf field: string chain_id = 1;
     */
    chainId: string;
    /**
     * @generated from protobuf field: uint32 peers_count = 2;
     */
    peersCount: number;
    /**
     * @generated from protobuf field: bool listening = 3;
     */
    listening: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetStatusResponse.GetStatusResponseV0.StateSync
 */
export interface GetStatusResponse_GetStatusResponseV0_StateSync {
    /**
     * @generated from protobuf field: uint64 total_synced_time = 1 [jstype = JS_STRING];
     */
    totalSyncedTime: string;
    /**
     * @generated from protobuf field: uint64 remaining_time = 2 [jstype = JS_STRING];
     */
    remainingTime: string;
    /**
     * @generated from protobuf field: uint32 total_snapshots = 3;
     */
    totalSnapshots: number;
    /**
     * @generated from protobuf field: uint64 chunk_process_avg_time = 4 [jstype = JS_STRING];
     */
    chunkProcessAvgTime: string;
    /**
     * @generated from protobuf field: uint64 snapshot_height = 5 [jstype = JS_STRING];
     */
    snapshotHeight: string;
    /**
     * @generated from protobuf field: uint64 snapshot_chunks_count = 6 [jstype = JS_STRING];
     */
    snapshotChunksCount: string;
    /**
     * @generated from protobuf field: uint64 backfilled_blocks = 7 [jstype = JS_STRING];
     */
    backfilledBlocks: string;
    /**
     * @generated from protobuf field: uint64 backfill_blocks_total = 8 [jstype = JS_STRING];
     */
    backfillBlocksTotal: string;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetCurrentQuorumsInfoRequest
 */
export interface GetCurrentQuorumsInfoRequest {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetCurrentQuorumsInfoRequest.GetCurrentQuorumsInfoRequestV0 v0 = 1;
         */
        v0: GetCurrentQuorumsInfoRequest_GetCurrentQuorumsInfoRequestV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetCurrentQuorumsInfoRequest.GetCurrentQuorumsInfoRequestV0
 */
export interface GetCurrentQuorumsInfoRequest_GetCurrentQuorumsInfoRequestV0 {
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetCurrentQuorumsInfoResponse
 */
export interface GetCurrentQuorumsInfoResponse {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetCurrentQuorumsInfoResponse.GetCurrentQuorumsInfoResponseV0 v0 = 1;
         */
        v0: GetCurrentQuorumsInfoResponse_GetCurrentQuorumsInfoResponseV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetCurrentQuorumsInfoResponse.ValidatorV0
 */
export interface GetCurrentQuorumsInfoResponse_ValidatorV0 {
    /**
     * @generated from protobuf field: bytes pro_tx_hash = 1;
     */
    proTxHash: Uint8Array;
    /**
     * @generated from protobuf field: string node_ip = 2;
     */
    nodeIp: string;
    /**
     * @generated from protobuf field: bool is_banned = 3;
     */
    isBanned: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetCurrentQuorumsInfoResponse.ValidatorSetV0
 */
export interface GetCurrentQuorumsInfoResponse_ValidatorSetV0 {
    /**
     * @generated from protobuf field: bytes quorum_hash = 1;
     */
    quorumHash: Uint8Array;
    /**
     * @generated from protobuf field: uint32 core_height = 2;
     */
    coreHeight: number;
    /**
     * @generated from protobuf field: repeated org.dash.platform.dapi.v0.GetCurrentQuorumsInfoResponse.ValidatorV0 members = 3;
     */
    members: GetCurrentQuorumsInfoResponse_ValidatorV0[];
    /**
     * @generated from protobuf field: bytes threshold_public_key = 4;
     */
    thresholdPublicKey: Uint8Array;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetCurrentQuorumsInfoResponse.GetCurrentQuorumsInfoResponseV0
 */
export interface GetCurrentQuorumsInfoResponse_GetCurrentQuorumsInfoResponseV0 {
    /**
     * @generated from protobuf field: repeated bytes quorum_hashes = 1;
     */
    quorumHashes: Uint8Array[];
    /**
     * @generated from protobuf field: bytes current_quorum_hash = 2;
     */
    currentQuorumHash: Uint8Array;
    /**
     * @generated from protobuf field: repeated org.dash.platform.dapi.v0.GetCurrentQuorumsInfoResponse.ValidatorSetV0 validator_sets = 3;
     */
    validatorSets: GetCurrentQuorumsInfoResponse_ValidatorSetV0[];
    /**
     * @generated from protobuf field: bytes last_block_proposer = 4;
     */
    lastBlockProposer: Uint8Array;
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.ResponseMetadata metadata = 5;
     */
    metadata?: ResponseMetadata;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentityTokenBalancesRequest
 */
export interface GetIdentityTokenBalancesRequest {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetIdentityTokenBalancesRequest.GetIdentityTokenBalancesRequestV0 v0 = 1;
         */
        v0: GetIdentityTokenBalancesRequest_GetIdentityTokenBalancesRequestV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentityTokenBalancesRequest.GetIdentityTokenBalancesRequestV0
 */
export interface GetIdentityTokenBalancesRequest_GetIdentityTokenBalancesRequestV0 {
    /**
     * @generated from protobuf field: bytes identity_id = 1;
     */
    identityId: Uint8Array;
    /**
     * @generated from protobuf field: repeated bytes token_ids = 2;
     */
    tokenIds: Uint8Array[];
    /**
     * @generated from protobuf field: bool prove = 3;
     */
    prove: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentityTokenBalancesResponse
 */
export interface GetIdentityTokenBalancesResponse {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetIdentityTokenBalancesResponse.GetIdentityTokenBalancesResponseV0 v0 = 1;
         */
        v0: GetIdentityTokenBalancesResponse_GetIdentityTokenBalancesResponseV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentityTokenBalancesResponse.GetIdentityTokenBalancesResponseV0
 */
export interface GetIdentityTokenBalancesResponse_GetIdentityTokenBalancesResponseV0 {
    /**
     * @generated from protobuf oneof: result
     */
    result: {
        oneofKind: "tokenBalances";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetIdentityTokenBalancesResponse.GetIdentityTokenBalancesResponseV0.TokenBalances token_balances = 1;
         */
        tokenBalances: GetIdentityTokenBalancesResponse_GetIdentityTokenBalancesResponseV0_TokenBalances;
    } | {
        oneofKind: "proof";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.Proof proof = 2;
         */
        proof: Proof;
    } | {
        oneofKind: undefined;
    };
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.ResponseMetadata metadata = 3;
     */
    metadata?: ResponseMetadata;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentityTokenBalancesResponse.GetIdentityTokenBalancesResponseV0.TokenBalanceEntry
 */
export interface GetIdentityTokenBalancesResponse_GetIdentityTokenBalancesResponseV0_TokenBalanceEntry {
    /**
     * @generated from protobuf field: bytes token_id = 1;
     */
    tokenId: Uint8Array;
    /**
     * @generated from protobuf field: optional uint64 balance = 2;
     */
    balance?: bigint;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentityTokenBalancesResponse.GetIdentityTokenBalancesResponseV0.TokenBalances
 */
export interface GetIdentityTokenBalancesResponse_GetIdentityTokenBalancesResponseV0_TokenBalances {
    /**
     * @generated from protobuf field: repeated org.dash.platform.dapi.v0.GetIdentityTokenBalancesResponse.GetIdentityTokenBalancesResponseV0.TokenBalanceEntry token_balances = 1;
     */
    tokenBalances: GetIdentityTokenBalancesResponse_GetIdentityTokenBalancesResponseV0_TokenBalanceEntry[];
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentitiesTokenBalancesRequest
 */
export interface GetIdentitiesTokenBalancesRequest {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetIdentitiesTokenBalancesRequest.GetIdentitiesTokenBalancesRequestV0 v0 = 1;
         */
        v0: GetIdentitiesTokenBalancesRequest_GetIdentitiesTokenBalancesRequestV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentitiesTokenBalancesRequest.GetIdentitiesTokenBalancesRequestV0
 */
export interface GetIdentitiesTokenBalancesRequest_GetIdentitiesTokenBalancesRequestV0 {
    /**
     * @generated from protobuf field: bytes token_id = 1;
     */
    tokenId: Uint8Array;
    /**
     * @generated from protobuf field: repeated bytes identity_ids = 2;
     */
    identityIds: Uint8Array[];
    /**
     * @generated from protobuf field: bool prove = 3;
     */
    prove: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentitiesTokenBalancesResponse
 */
export interface GetIdentitiesTokenBalancesResponse {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetIdentitiesTokenBalancesResponse.GetIdentitiesTokenBalancesResponseV0 v0 = 1;
         */
        v0: GetIdentitiesTokenBalancesResponse_GetIdentitiesTokenBalancesResponseV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentitiesTokenBalancesResponse.GetIdentitiesTokenBalancesResponseV0
 */
export interface GetIdentitiesTokenBalancesResponse_GetIdentitiesTokenBalancesResponseV0 {
    /**
     * @generated from protobuf oneof: result
     */
    result: {
        oneofKind: "identityTokenBalances";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetIdentitiesTokenBalancesResponse.GetIdentitiesTokenBalancesResponseV0.IdentityTokenBalances identity_token_balances = 1;
         */
        identityTokenBalances: GetIdentitiesTokenBalancesResponse_GetIdentitiesTokenBalancesResponseV0_IdentityTokenBalances;
    } | {
        oneofKind: "proof";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.Proof proof = 2;
         */
        proof: Proof;
    } | {
        oneofKind: undefined;
    };
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.ResponseMetadata metadata = 3;
     */
    metadata?: ResponseMetadata;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentitiesTokenBalancesResponse.GetIdentitiesTokenBalancesResponseV0.IdentityTokenBalanceEntry
 */
export interface GetIdentitiesTokenBalancesResponse_GetIdentitiesTokenBalancesResponseV0_IdentityTokenBalanceEntry {
    /**
     * @generated from protobuf field: bytes identity_id = 1;
     */
    identityId: Uint8Array;
    /**
     * @generated from protobuf field: optional uint64 balance = 2;
     */
    balance?: bigint;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentitiesTokenBalancesResponse.GetIdentitiesTokenBalancesResponseV0.IdentityTokenBalances
 */
export interface GetIdentitiesTokenBalancesResponse_GetIdentitiesTokenBalancesResponseV0_IdentityTokenBalances {
    /**
     * @generated from protobuf field: repeated org.dash.platform.dapi.v0.GetIdentitiesTokenBalancesResponse.GetIdentitiesTokenBalancesResponseV0.IdentityTokenBalanceEntry identity_token_balances = 1;
     */
    identityTokenBalances: GetIdentitiesTokenBalancesResponse_GetIdentitiesTokenBalancesResponseV0_IdentityTokenBalanceEntry[];
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentityTokenInfosRequest
 */
export interface GetIdentityTokenInfosRequest {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetIdentityTokenInfosRequest.GetIdentityTokenInfosRequestV0 v0 = 1;
         */
        v0: GetIdentityTokenInfosRequest_GetIdentityTokenInfosRequestV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentityTokenInfosRequest.GetIdentityTokenInfosRequestV0
 */
export interface GetIdentityTokenInfosRequest_GetIdentityTokenInfosRequestV0 {
    /**
     * @generated from protobuf field: bytes identity_id = 1;
     */
    identityId: Uint8Array;
    /**
     * @generated from protobuf field: repeated bytes token_ids = 2;
     */
    tokenIds: Uint8Array[];
    /**
     * @generated from protobuf field: bool prove = 3;
     */
    prove: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentityTokenInfosResponse
 */
export interface GetIdentityTokenInfosResponse {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetIdentityTokenInfosResponse.GetIdentityTokenInfosResponseV0 v0 = 1;
         */
        v0: GetIdentityTokenInfosResponse_GetIdentityTokenInfosResponseV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentityTokenInfosResponse.GetIdentityTokenInfosResponseV0
 */
export interface GetIdentityTokenInfosResponse_GetIdentityTokenInfosResponseV0 {
    /**
     * @generated from protobuf oneof: result
     */
    result: {
        oneofKind: "tokenInfos";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetIdentityTokenInfosResponse.GetIdentityTokenInfosResponseV0.TokenInfos token_infos = 1;
         */
        tokenInfos: GetIdentityTokenInfosResponse_GetIdentityTokenInfosResponseV0_TokenInfos;
    } | {
        oneofKind: "proof";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.Proof proof = 2;
         */
        proof: Proof;
    } | {
        oneofKind: undefined;
    };
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.ResponseMetadata metadata = 3;
     */
    metadata?: ResponseMetadata;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentityTokenInfosResponse.GetIdentityTokenInfosResponseV0.TokenIdentityInfoEntry
 */
export interface GetIdentityTokenInfosResponse_GetIdentityTokenInfosResponseV0_TokenIdentityInfoEntry {
    /**
     * @generated from protobuf field: bool frozen = 1;
     */
    frozen: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentityTokenInfosResponse.GetIdentityTokenInfosResponseV0.TokenInfoEntry
 */
export interface GetIdentityTokenInfosResponse_GetIdentityTokenInfosResponseV0_TokenInfoEntry {
    /**
     * @generated from protobuf field: bytes token_id = 1;
     */
    tokenId: Uint8Array;
    /**
     * @generated from protobuf field: optional org.dash.platform.dapi.v0.GetIdentityTokenInfosResponse.GetIdentityTokenInfosResponseV0.TokenIdentityInfoEntry info = 2;
     */
    info?: GetIdentityTokenInfosResponse_GetIdentityTokenInfosResponseV0_TokenIdentityInfoEntry;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentityTokenInfosResponse.GetIdentityTokenInfosResponseV0.TokenInfos
 */
export interface GetIdentityTokenInfosResponse_GetIdentityTokenInfosResponseV0_TokenInfos {
    /**
     * @generated from protobuf field: repeated org.dash.platform.dapi.v0.GetIdentityTokenInfosResponse.GetIdentityTokenInfosResponseV0.TokenInfoEntry token_infos = 1;
     */
    tokenInfos: GetIdentityTokenInfosResponse_GetIdentityTokenInfosResponseV0_TokenInfoEntry[];
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentitiesTokenInfosRequest
 */
export interface GetIdentitiesTokenInfosRequest {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetIdentitiesTokenInfosRequest.GetIdentitiesTokenInfosRequestV0 v0 = 1;
         */
        v0: GetIdentitiesTokenInfosRequest_GetIdentitiesTokenInfosRequestV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentitiesTokenInfosRequest.GetIdentitiesTokenInfosRequestV0
 */
export interface GetIdentitiesTokenInfosRequest_GetIdentitiesTokenInfosRequestV0 {
    /**
     * @generated from protobuf field: bytes token_id = 1;
     */
    tokenId: Uint8Array;
    /**
     * @generated from protobuf field: repeated bytes identity_ids = 2;
     */
    identityIds: Uint8Array[];
    /**
     * @generated from protobuf field: bool prove = 3;
     */
    prove: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentitiesTokenInfosResponse
 */
export interface GetIdentitiesTokenInfosResponse {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetIdentitiesTokenInfosResponse.GetIdentitiesTokenInfosResponseV0 v0 = 1;
         */
        v0: GetIdentitiesTokenInfosResponse_GetIdentitiesTokenInfosResponseV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentitiesTokenInfosResponse.GetIdentitiesTokenInfosResponseV0
 */
export interface GetIdentitiesTokenInfosResponse_GetIdentitiesTokenInfosResponseV0 {
    /**
     * @generated from protobuf oneof: result
     */
    result: {
        oneofKind: "identityTokenInfos";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetIdentitiesTokenInfosResponse.GetIdentitiesTokenInfosResponseV0.IdentityTokenInfos identity_token_infos = 1;
         */
        identityTokenInfos: GetIdentitiesTokenInfosResponse_GetIdentitiesTokenInfosResponseV0_IdentityTokenInfos;
    } | {
        oneofKind: "proof";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.Proof proof = 2;
         */
        proof: Proof;
    } | {
        oneofKind: undefined;
    };
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.ResponseMetadata metadata = 3;
     */
    metadata?: ResponseMetadata;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentitiesTokenInfosResponse.GetIdentitiesTokenInfosResponseV0.TokenIdentityInfoEntry
 */
export interface GetIdentitiesTokenInfosResponse_GetIdentitiesTokenInfosResponseV0_TokenIdentityInfoEntry {
    /**
     * @generated from protobuf field: bool frozen = 1;
     */
    frozen: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentitiesTokenInfosResponse.GetIdentitiesTokenInfosResponseV0.TokenInfoEntry
 */
export interface GetIdentitiesTokenInfosResponse_GetIdentitiesTokenInfosResponseV0_TokenInfoEntry {
    /**
     * @generated from protobuf field: bytes identity_id = 1;
     */
    identityId: Uint8Array;
    /**
     * @generated from protobuf field: optional org.dash.platform.dapi.v0.GetIdentitiesTokenInfosResponse.GetIdentitiesTokenInfosResponseV0.TokenIdentityInfoEntry info = 2;
     */
    info?: GetIdentitiesTokenInfosResponse_GetIdentitiesTokenInfosResponseV0_TokenIdentityInfoEntry;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetIdentitiesTokenInfosResponse.GetIdentitiesTokenInfosResponseV0.IdentityTokenInfos
 */
export interface GetIdentitiesTokenInfosResponse_GetIdentitiesTokenInfosResponseV0_IdentityTokenInfos {
    /**
     * @generated from protobuf field: repeated org.dash.platform.dapi.v0.GetIdentitiesTokenInfosResponse.GetIdentitiesTokenInfosResponseV0.TokenInfoEntry token_infos = 1;
     */
    tokenInfos: GetIdentitiesTokenInfosResponse_GetIdentitiesTokenInfosResponseV0_TokenInfoEntry[];
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetTokenStatusesRequest
 */
export interface GetTokenStatusesRequest {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetTokenStatusesRequest.GetTokenStatusesRequestV0 v0 = 1;
         */
        v0: GetTokenStatusesRequest_GetTokenStatusesRequestV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetTokenStatusesRequest.GetTokenStatusesRequestV0
 */
export interface GetTokenStatusesRequest_GetTokenStatusesRequestV0 {
    /**
     * @generated from protobuf field: repeated bytes token_ids = 1;
     */
    tokenIds: Uint8Array[];
    /**
     * @generated from protobuf field: bool prove = 2;
     */
    prove: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetTokenStatusesResponse
 */
export interface GetTokenStatusesResponse {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetTokenStatusesResponse.GetTokenStatusesResponseV0 v0 = 1;
         */
        v0: GetTokenStatusesResponse_GetTokenStatusesResponseV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetTokenStatusesResponse.GetTokenStatusesResponseV0
 */
export interface GetTokenStatusesResponse_GetTokenStatusesResponseV0 {
    /**
     * @generated from protobuf oneof: result
     */
    result: {
        oneofKind: "tokenStatuses";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetTokenStatusesResponse.GetTokenStatusesResponseV0.TokenStatuses token_statuses = 1;
         */
        tokenStatuses: GetTokenStatusesResponse_GetTokenStatusesResponseV0_TokenStatuses;
    } | {
        oneofKind: "proof";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.Proof proof = 2;
         */
        proof: Proof;
    } | {
        oneofKind: undefined;
    };
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.ResponseMetadata metadata = 3;
     */
    metadata?: ResponseMetadata;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetTokenStatusesResponse.GetTokenStatusesResponseV0.TokenStatusEntry
 */
export interface GetTokenStatusesResponse_GetTokenStatusesResponseV0_TokenStatusEntry {
    /**
     * @generated from protobuf field: bytes token_id = 1;
     */
    tokenId: Uint8Array;
    /**
     * @generated from protobuf field: optional bool paused = 2;
     */
    paused?: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetTokenStatusesResponse.GetTokenStatusesResponseV0.TokenStatuses
 */
export interface GetTokenStatusesResponse_GetTokenStatusesResponseV0_TokenStatuses {
    /**
     * @generated from protobuf field: repeated org.dash.platform.dapi.v0.GetTokenStatusesResponse.GetTokenStatusesResponseV0.TokenStatusEntry token_statuses = 1;
     */
    tokenStatuses: GetTokenStatusesResponse_GetTokenStatusesResponseV0_TokenStatusEntry[];
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetTokenPreProgrammedDistributionsRequest
 */
export interface GetTokenPreProgrammedDistributionsRequest {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetTokenPreProgrammedDistributionsRequest.GetTokenPreProgrammedDistributionsRequestV0 v0 = 1;
         */
        v0: GetTokenPreProgrammedDistributionsRequest_GetTokenPreProgrammedDistributionsRequestV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetTokenPreProgrammedDistributionsRequest.GetTokenPreProgrammedDistributionsRequestV0
 */
export interface GetTokenPreProgrammedDistributionsRequest_GetTokenPreProgrammedDistributionsRequestV0 {
    /**
     * @generated from protobuf field: bytes token_id = 1;
     */
    tokenId: Uint8Array;
    /**
     * @generated from protobuf field: optional org.dash.platform.dapi.v0.GetTokenPreProgrammedDistributionsRequest.GetTokenPreProgrammedDistributionsRequestV0.StartAtInfo start_at_info = 2;
     */
    startAtInfo?: GetTokenPreProgrammedDistributionsRequest_GetTokenPreProgrammedDistributionsRequestV0_StartAtInfo;
    /**
     * @generated from protobuf field: optional uint32 limit = 3;
     */
    limit?: number;
    /**
     * @generated from protobuf field: bool prove = 4;
     */
    prove: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetTokenPreProgrammedDistributionsRequest.GetTokenPreProgrammedDistributionsRequestV0.StartAtInfo
 */
export interface GetTokenPreProgrammedDistributionsRequest_GetTokenPreProgrammedDistributionsRequestV0_StartAtInfo {
    /**
     * @generated from protobuf field: uint64 start_time_ms = 1;
     */
    startTimeMs: bigint;
    /**
     * @generated from protobuf field: optional bytes start_recipient = 2;
     */
    startRecipient?: Uint8Array;
    /**
     * @generated from protobuf field: optional bool start_recipient_included = 3;
     */
    startRecipientIncluded?: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetTokenPreProgrammedDistributionsResponse
 */
export interface GetTokenPreProgrammedDistributionsResponse {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetTokenPreProgrammedDistributionsResponse.GetTokenPreProgrammedDistributionsResponseV0 v0 = 1;
         */
        v0: GetTokenPreProgrammedDistributionsResponse_GetTokenPreProgrammedDistributionsResponseV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetTokenPreProgrammedDistributionsResponse.GetTokenPreProgrammedDistributionsResponseV0
 */
export interface GetTokenPreProgrammedDistributionsResponse_GetTokenPreProgrammedDistributionsResponseV0 {
    /**
     * @generated from protobuf oneof: result
     */
    result: {
        oneofKind: "tokenDistributions";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetTokenPreProgrammedDistributionsResponse.GetTokenPreProgrammedDistributionsResponseV0.TokenDistributions token_distributions = 1;
         */
        tokenDistributions: GetTokenPreProgrammedDistributionsResponse_GetTokenPreProgrammedDistributionsResponseV0_TokenDistributions;
    } | {
        oneofKind: "proof";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.Proof proof = 2;
         */
        proof: Proof;
    } | {
        oneofKind: undefined;
    };
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.ResponseMetadata metadata = 3;
     */
    metadata?: ResponseMetadata;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetTokenPreProgrammedDistributionsResponse.GetTokenPreProgrammedDistributionsResponseV0.TokenDistributionEntry
 */
export interface GetTokenPreProgrammedDistributionsResponse_GetTokenPreProgrammedDistributionsResponseV0_TokenDistributionEntry {
    /**
     * @generated from protobuf field: bytes recipient_id = 1;
     */
    recipientId: Uint8Array;
    /**
     * @generated from protobuf field: uint64 amount = 2;
     */
    amount: bigint;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetTokenPreProgrammedDistributionsResponse.GetTokenPreProgrammedDistributionsResponseV0.TokenTimedDistributionEntry
 */
export interface GetTokenPreProgrammedDistributionsResponse_GetTokenPreProgrammedDistributionsResponseV0_TokenTimedDistributionEntry {
    /**
     * @generated from protobuf field: uint64 timestamp = 1;
     */
    timestamp: bigint;
    /**
     * @generated from protobuf field: repeated org.dash.platform.dapi.v0.GetTokenPreProgrammedDistributionsResponse.GetTokenPreProgrammedDistributionsResponseV0.TokenDistributionEntry distributions = 2;
     */
    distributions: GetTokenPreProgrammedDistributionsResponse_GetTokenPreProgrammedDistributionsResponseV0_TokenDistributionEntry[];
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetTokenPreProgrammedDistributionsResponse.GetTokenPreProgrammedDistributionsResponseV0.TokenDistributions
 */
export interface GetTokenPreProgrammedDistributionsResponse_GetTokenPreProgrammedDistributionsResponseV0_TokenDistributions {
    /**
     * @generated from protobuf field: repeated org.dash.platform.dapi.v0.GetTokenPreProgrammedDistributionsResponse.GetTokenPreProgrammedDistributionsResponseV0.TokenTimedDistributionEntry token_distributions = 1;
     */
    tokenDistributions: GetTokenPreProgrammedDistributionsResponse_GetTokenPreProgrammedDistributionsResponseV0_TokenTimedDistributionEntry[];
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetTokenTotalSupplyRequest
 */
export interface GetTokenTotalSupplyRequest {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetTokenTotalSupplyRequest.GetTokenTotalSupplyRequestV0 v0 = 1;
         */
        v0: GetTokenTotalSupplyRequest_GetTokenTotalSupplyRequestV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetTokenTotalSupplyRequest.GetTokenTotalSupplyRequestV0
 */
export interface GetTokenTotalSupplyRequest_GetTokenTotalSupplyRequestV0 {
    /**
     * @generated from protobuf field: bytes token_id = 1;
     */
    tokenId: Uint8Array;
    /**
     * @generated from protobuf field: bool prove = 2;
     */
    prove: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetTokenTotalSupplyResponse
 */
export interface GetTokenTotalSupplyResponse {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetTokenTotalSupplyResponse.GetTokenTotalSupplyResponseV0 v0 = 1;
         */
        v0: GetTokenTotalSupplyResponse_GetTokenTotalSupplyResponseV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetTokenTotalSupplyResponse.GetTokenTotalSupplyResponseV0
 */
export interface GetTokenTotalSupplyResponse_GetTokenTotalSupplyResponseV0 {
    /**
     * @generated from protobuf oneof: result
     */
    result: {
        oneofKind: "tokenTotalSupply";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetTokenTotalSupplyResponse.GetTokenTotalSupplyResponseV0.TokenTotalSupplyEntry token_total_supply = 1;
         */
        tokenTotalSupply: GetTokenTotalSupplyResponse_GetTokenTotalSupplyResponseV0_TokenTotalSupplyEntry;
    } | {
        oneofKind: "proof";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.Proof proof = 2;
         */
        proof: Proof;
    } | {
        oneofKind: undefined;
    };
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.ResponseMetadata metadata = 3;
     */
    metadata?: ResponseMetadata;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetTokenTotalSupplyResponse.GetTokenTotalSupplyResponseV0.TokenTotalSupplyEntry
 */
export interface GetTokenTotalSupplyResponse_GetTokenTotalSupplyResponseV0_TokenTotalSupplyEntry {
    /**
     * @generated from protobuf field: bytes token_id = 1;
     */
    tokenId: Uint8Array;
    /**
     * @generated from protobuf field: uint64 total_aggregated_amount_in_user_accounts = 2;
     */
    totalAggregatedAmountInUserAccounts: bigint;
    /**
     * @generated from protobuf field: uint64 total_system_amount = 3;
     */
    totalSystemAmount: bigint;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetGroupInfoRequest
 */
export interface GetGroupInfoRequest {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetGroupInfoRequest.GetGroupInfoRequestV0 v0 = 1;
         */
        v0: GetGroupInfoRequest_GetGroupInfoRequestV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetGroupInfoRequest.GetGroupInfoRequestV0
 */
export interface GetGroupInfoRequest_GetGroupInfoRequestV0 {
    /**
     * @generated from protobuf field: bytes contract_id = 1;
     */
    contractId: Uint8Array;
    /**
     * @generated from protobuf field: uint32 group_contract_position = 2;
     */
    groupContractPosition: number;
    /**
     * @generated from protobuf field: bool prove = 3;
     */
    prove: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetGroupInfoResponse
 */
export interface GetGroupInfoResponse {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetGroupInfoResponse.GetGroupInfoResponseV0 v0 = 1;
         */
        v0: GetGroupInfoResponse_GetGroupInfoResponseV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetGroupInfoResponse.GetGroupInfoResponseV0
 */
export interface GetGroupInfoResponse_GetGroupInfoResponseV0 {
    /**
     * @generated from protobuf oneof: result
     */
    result: {
        oneofKind: "groupInfo";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetGroupInfoResponse.GetGroupInfoResponseV0.GroupInfo group_info = 1;
         */
        groupInfo: GetGroupInfoResponse_GetGroupInfoResponseV0_GroupInfo;
    } | {
        oneofKind: "proof";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.Proof proof = 2;
         */
        proof: Proof;
    } | {
        oneofKind: undefined;
    };
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.ResponseMetadata metadata = 4;
     */
    metadata?: ResponseMetadata;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetGroupInfoResponse.GetGroupInfoResponseV0.GroupMemberEntry
 */
export interface GetGroupInfoResponse_GetGroupInfoResponseV0_GroupMemberEntry {
    /**
     * @generated from protobuf field: bytes member_id = 1;
     */
    memberId: Uint8Array;
    /**
     * @generated from protobuf field: uint32 power = 2;
     */
    power: number;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetGroupInfoResponse.GetGroupInfoResponseV0.GroupInfoEntry
 */
export interface GetGroupInfoResponse_GetGroupInfoResponseV0_GroupInfoEntry {
    /**
     * @generated from protobuf field: repeated org.dash.platform.dapi.v0.GetGroupInfoResponse.GetGroupInfoResponseV0.GroupMemberEntry members = 1;
     */
    members: GetGroupInfoResponse_GetGroupInfoResponseV0_GroupMemberEntry[];
    /**
     * @generated from protobuf field: uint32 group_required_power = 2;
     */
    groupRequiredPower: number;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetGroupInfoResponse.GetGroupInfoResponseV0.GroupInfo
 */
export interface GetGroupInfoResponse_GetGroupInfoResponseV0_GroupInfo {
    /**
     * @generated from protobuf field: optional org.dash.platform.dapi.v0.GetGroupInfoResponse.GetGroupInfoResponseV0.GroupInfoEntry group_info = 1;
     */
    groupInfo?: GetGroupInfoResponse_GetGroupInfoResponseV0_GroupInfoEntry;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetGroupInfosRequest
 */
export interface GetGroupInfosRequest {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetGroupInfosRequest.GetGroupInfosRequestV0 v0 = 1;
         */
        v0: GetGroupInfosRequest_GetGroupInfosRequestV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetGroupInfosRequest.StartAtGroupContractPosition
 */
export interface GetGroupInfosRequest_StartAtGroupContractPosition {
    /**
     * @generated from protobuf field: uint32 start_group_contract_position = 1;
     */
    startGroupContractPosition: number;
    /**
     * @generated from protobuf field: bool start_group_contract_position_included = 2;
     */
    startGroupContractPositionIncluded: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetGroupInfosRequest.GetGroupInfosRequestV0
 */
export interface GetGroupInfosRequest_GetGroupInfosRequestV0 {
    /**
     * @generated from protobuf field: bytes contract_id = 1;
     */
    contractId: Uint8Array;
    /**
     * @generated from protobuf field: optional org.dash.platform.dapi.v0.GetGroupInfosRequest.StartAtGroupContractPosition start_at_group_contract_position = 2;
     */
    startAtGroupContractPosition?: GetGroupInfosRequest_StartAtGroupContractPosition;
    /**
     * @generated from protobuf field: optional uint32 count = 3;
     */
    count?: number;
    /**
     * @generated from protobuf field: bool prove = 4;
     */
    prove: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetGroupInfosResponse
 */
export interface GetGroupInfosResponse {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetGroupInfosResponse.GetGroupInfosResponseV0 v0 = 1;
         */
        v0: GetGroupInfosResponse_GetGroupInfosResponseV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetGroupInfosResponse.GetGroupInfosResponseV0
 */
export interface GetGroupInfosResponse_GetGroupInfosResponseV0 {
    /**
     * @generated from protobuf oneof: result
     */
    result: {
        oneofKind: "groupInfos";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetGroupInfosResponse.GetGroupInfosResponseV0.GroupInfos group_infos = 1;
         */
        groupInfos: GetGroupInfosResponse_GetGroupInfosResponseV0_GroupInfos;
    } | {
        oneofKind: "proof";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.Proof proof = 2;
         */
        proof: Proof;
    } | {
        oneofKind: undefined;
    };
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.ResponseMetadata metadata = 4;
     */
    metadata?: ResponseMetadata;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetGroupInfosResponse.GetGroupInfosResponseV0.GroupMemberEntry
 */
export interface GetGroupInfosResponse_GetGroupInfosResponseV0_GroupMemberEntry {
    /**
     * @generated from protobuf field: bytes member_id = 1;
     */
    memberId: Uint8Array;
    /**
     * @generated from protobuf field: uint32 power = 2;
     */
    power: number;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetGroupInfosResponse.GetGroupInfosResponseV0.GroupPositionInfoEntry
 */
export interface GetGroupInfosResponse_GetGroupInfosResponseV0_GroupPositionInfoEntry {
    /**
     * @generated from protobuf field: uint32 group_contract_position = 1;
     */
    groupContractPosition: number;
    /**
     * @generated from protobuf field: repeated org.dash.platform.dapi.v0.GetGroupInfosResponse.GetGroupInfosResponseV0.GroupMemberEntry members = 2;
     */
    members: GetGroupInfosResponse_GetGroupInfosResponseV0_GroupMemberEntry[];
    /**
     * @generated from protobuf field: uint32 group_required_power = 3;
     */
    groupRequiredPower: number;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetGroupInfosResponse.GetGroupInfosResponseV0.GroupInfos
 */
export interface GetGroupInfosResponse_GetGroupInfosResponseV0_GroupInfos {
    /**
     * @generated from protobuf field: repeated org.dash.platform.dapi.v0.GetGroupInfosResponse.GetGroupInfosResponseV0.GroupPositionInfoEntry group_infos = 1;
     */
    groupInfos: GetGroupInfosResponse_GetGroupInfosResponseV0_GroupPositionInfoEntry[];
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetGroupActionsRequest
 */
export interface GetGroupActionsRequest {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetGroupActionsRequest.GetGroupActionsRequestV0 v0 = 1;
         */
        v0: GetGroupActionsRequest_GetGroupActionsRequestV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetGroupActionsRequest.StartAtActionId
 */
export interface GetGroupActionsRequest_StartAtActionId {
    /**
     * @generated from protobuf field: bytes start_action_id = 1;
     */
    startActionId: Uint8Array;
    /**
     * @generated from protobuf field: bool start_action_id_included = 2;
     */
    startActionIdIncluded: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetGroupActionsRequest.GetGroupActionsRequestV0
 */
export interface GetGroupActionsRequest_GetGroupActionsRequestV0 {
    /**
     * @generated from protobuf field: bytes contract_id = 1;
     */
    contractId: Uint8Array;
    /**
     * @generated from protobuf field: uint32 group_contract_position = 2;
     */
    groupContractPosition: number;
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.GetGroupActionsRequest.ActionStatus status = 3;
     */
    status: GetGroupActionsRequest_ActionStatus;
    /**
     * @generated from protobuf field: optional org.dash.platform.dapi.v0.GetGroupActionsRequest.StartAtActionId start_at_action_id = 4;
     */
    startAtActionId?: GetGroupActionsRequest_StartAtActionId;
    /**
     * @generated from protobuf field: optional uint32 count = 5;
     */
    count?: number;
    /**
     * @generated from protobuf field: bool prove = 6;
     */
    prove: boolean;
}
/**
 * @generated from protobuf enum org.dash.platform.dapi.v0.GetGroupActionsRequest.ActionStatus
 */
export declare enum GetGroupActionsRequest_ActionStatus {
    /**
     * Request the active actions
     *
     * @generated from protobuf enum value: ACTIVE = 0;
     */
    ACTIVE = 0,
    /**
     * Request the closed actions
     *
     * @generated from protobuf enum value: CLOSED = 1;
     */
    CLOSED = 1
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetGroupActionsResponse
 */
export interface GetGroupActionsResponse {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0 v0 = 1;
         */
        v0: GetGroupActionsResponse_GetGroupActionsResponseV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0
 */
export interface GetGroupActionsResponse_GetGroupActionsResponseV0 {
    /**
     * @generated from protobuf oneof: result
     */
    result: {
        oneofKind: "groupActions";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.GroupActions group_actions = 1;
         */
        groupActions: GetGroupActionsResponse_GetGroupActionsResponseV0_GroupActions;
    } | {
        oneofKind: "proof";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.Proof proof = 2;
         */
        proof: Proof;
    } | {
        oneofKind: undefined;
    };
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.ResponseMetadata metadata = 3;
     */
    metadata?: ResponseMetadata;
}
/**
 * Mint event
 *
 * @generated from protobuf message org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.MintEvent
 */
export interface GetGroupActionsResponse_GetGroupActionsResponseV0_MintEvent {
    /**
     * @generated from protobuf field: uint64 amount = 1;
     */
    amount: bigint;
    /**
     * @generated from protobuf field: bytes recipient_id = 2;
     */
    recipientId: Uint8Array;
    /**
     * @generated from protobuf field: optional string public_note = 3;
     */
    publicNote?: string;
}
/**
 * Burn event
 *
 * @generated from protobuf message org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.BurnEvent
 */
export interface GetGroupActionsResponse_GetGroupActionsResponseV0_BurnEvent {
    /**
     * @generated from protobuf field: uint64 amount = 1;
     */
    amount: bigint;
    /**
     * @generated from protobuf field: optional string public_note = 2;
     */
    publicNote?: string;
}
/**
 * Freeze event
 *
 * @generated from protobuf message org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.FreezeEvent
 */
export interface GetGroupActionsResponse_GetGroupActionsResponseV0_FreezeEvent {
    /**
     * @generated from protobuf field: bytes frozen_id = 1;
     */
    frozenId: Uint8Array;
    /**
     * @generated from protobuf field: optional string public_note = 2;
     */
    publicNote?: string;
}
/**
 * Unfreeze event
 *
 * @generated from protobuf message org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.UnfreezeEvent
 */
export interface GetGroupActionsResponse_GetGroupActionsResponseV0_UnfreezeEvent {
    /**
     * @generated from protobuf field: bytes frozen_id = 1;
     */
    frozenId: Uint8Array;
    /**
     * @generated from protobuf field: optional string public_note = 2;
     */
    publicNote?: string;
}
/**
 * Destroy frozen funds event
 *
 * @generated from protobuf message org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.DestroyFrozenFundsEvent
 */
export interface GetGroupActionsResponse_GetGroupActionsResponseV0_DestroyFrozenFundsEvent {
    /**
     * @generated from protobuf field: bytes frozen_id = 1;
     */
    frozenId: Uint8Array;
    /**
     * @generated from protobuf field: uint64 amount = 2;
     */
    amount: bigint;
    /**
     * @generated from protobuf field: optional string public_note = 3;
     */
    publicNote?: string;
}
/**
 * Shared encrypted note
 *
 * @generated from protobuf message org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.SharedEncryptedNote
 */
export interface GetGroupActionsResponse_GetGroupActionsResponseV0_SharedEncryptedNote {
    /**
     * @generated from protobuf field: uint32 sender_key_index = 1;
     */
    senderKeyIndex: number;
    /**
     * @generated from protobuf field: uint32 recipient_key_index = 2;
     */
    recipientKeyIndex: number;
    /**
     * @generated from protobuf field: bytes encrypted_data = 3;
     */
    encryptedData: Uint8Array;
}
/**
 * Personal encrypted note
 *
 * @generated from protobuf message org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.PersonalEncryptedNote
 */
export interface GetGroupActionsResponse_GetGroupActionsResponseV0_PersonalEncryptedNote {
    /**
     * @generated from protobuf field: uint32 root_encryption_key_index = 1;
     */
    rootEncryptionKeyIndex: number;
    /**
     * @generated from protobuf field: uint32 derivation_encryption_key_index = 2;
     */
    derivationEncryptionKeyIndex: number;
    /**
     * @generated from protobuf field: bytes encrypted_data = 3;
     */
    encryptedData: Uint8Array;
}
/**
 * Emergency action event
 *
 * @generated from protobuf message org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.EmergencyActionEvent
 */
export interface GetGroupActionsResponse_GetGroupActionsResponseV0_EmergencyActionEvent {
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.EmergencyActionEvent.ActionType action_type = 1;
     */
    actionType: GetGroupActionsResponse_GetGroupActionsResponseV0_EmergencyActionEvent_ActionType;
    /**
     * @generated from protobuf field: optional string public_note = 2;
     */
    publicNote?: string;
}
/**
 * Enum for emergency action types
 *
 * @generated from protobuf enum org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.EmergencyActionEvent.ActionType
 */
export declare enum GetGroupActionsResponse_GetGroupActionsResponseV0_EmergencyActionEvent_ActionType {
    /**
     * Pause action
     *
     * @generated from protobuf enum value: PAUSE = 0;
     */
    PAUSE = 0,
    /**
     * Resume action
     *
     * @generated from protobuf enum value: RESUME = 1;
     */
    RESUME = 1
}
/**
 * Token config update event
 *
 * @generated from protobuf message org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.TokenConfigUpdateEvent
 */
export interface GetGroupActionsResponse_GetGroupActionsResponseV0_TokenConfigUpdateEvent {
    /**
     * @generated from protobuf field: bytes token_config_update_item = 1;
     */
    tokenConfigUpdateItem: Uint8Array;
    /**
     * @generated from protobuf field: optional string public_note = 2;
     */
    publicNote?: string;
}
/**
 * Event associated with this action
 *
 * @generated from protobuf message org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.GroupActionEvent
 */
export interface GetGroupActionsResponse_GetGroupActionsResponseV0_GroupActionEvent {
    /**
     * @generated from protobuf oneof: event_type
     */
    eventType: {
        oneofKind: "tokenEvent";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.TokenEvent token_event = 1;
         */
        tokenEvent: GetGroupActionsResponse_GetGroupActionsResponseV0_TokenEvent;
    } | {
        oneofKind: "documentEvent";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.DocumentEvent document_event = 2;
         */
        documentEvent: GetGroupActionsResponse_GetGroupActionsResponseV0_DocumentEvent;
    } | {
        oneofKind: "contractEvent";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.ContractEvent contract_event = 3;
         */
        contractEvent: GetGroupActionsResponse_GetGroupActionsResponseV0_ContractEvent;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.DocumentEvent
 */
export interface GetGroupActionsResponse_GetGroupActionsResponseV0_DocumentEvent {
    /**
     * @generated from protobuf oneof: type
     */
    type: {
        oneofKind: "create";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.DocumentCreateEvent create = 1;
         */
        create: GetGroupActionsResponse_GetGroupActionsResponseV0_DocumentCreateEvent;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.DocumentCreateEvent
 */
export interface GetGroupActionsResponse_GetGroupActionsResponseV0_DocumentCreateEvent {
    /**
     * @generated from protobuf field: bytes created_document = 1;
     */
    createdDocument: Uint8Array;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.ContractUpdateEvent
 */
export interface GetGroupActionsResponse_GetGroupActionsResponseV0_ContractUpdateEvent {
    /**
     * @generated from protobuf field: bytes updated_contract = 1;
     */
    updatedContract: Uint8Array;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.ContractEvent
 */
export interface GetGroupActionsResponse_GetGroupActionsResponseV0_ContractEvent {
    /**
     * @generated from protobuf oneof: type
     */
    type: {
        oneofKind: "update";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.ContractUpdateEvent update = 1;
         */
        update: GetGroupActionsResponse_GetGroupActionsResponseV0_ContractUpdateEvent;
    } | {
        oneofKind: undefined;
    };
}
/**
 * Details for token events
 *
 * @generated from protobuf message org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.TokenEvent
 */
export interface GetGroupActionsResponse_GetGroupActionsResponseV0_TokenEvent {
    /**
     * @generated from protobuf oneof: type
     */
    type: {
        oneofKind: "mint";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.MintEvent mint = 1;
         */
        mint: GetGroupActionsResponse_GetGroupActionsResponseV0_MintEvent;
    } | {
        oneofKind: "burn";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.BurnEvent burn = 2;
         */
        burn: GetGroupActionsResponse_GetGroupActionsResponseV0_BurnEvent;
    } | {
        oneofKind: "freeze";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.FreezeEvent freeze = 3;
         */
        freeze: GetGroupActionsResponse_GetGroupActionsResponseV0_FreezeEvent;
    } | {
        oneofKind: "unfreeze";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.UnfreezeEvent unfreeze = 4;
         */
        unfreeze: GetGroupActionsResponse_GetGroupActionsResponseV0_UnfreezeEvent;
    } | {
        oneofKind: "destroyFrozenFunds";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.DestroyFrozenFundsEvent destroy_frozen_funds = 5;
         */
        destroyFrozenFunds: GetGroupActionsResponse_GetGroupActionsResponseV0_DestroyFrozenFundsEvent;
    } | {
        oneofKind: "emergencyAction";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.EmergencyActionEvent emergency_action = 6;
         */
        emergencyAction: GetGroupActionsResponse_GetGroupActionsResponseV0_EmergencyActionEvent;
    } | {
        oneofKind: "tokenConfigUpdate";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.TokenConfigUpdateEvent token_config_update = 7;
         */
        tokenConfigUpdate: GetGroupActionsResponse_GetGroupActionsResponseV0_TokenConfigUpdateEvent;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.GroupActionEntry
 */
export interface GetGroupActionsResponse_GetGroupActionsResponseV0_GroupActionEntry {
    /**
     * @generated from protobuf field: bytes action_id = 1;
     */
    actionId: Uint8Array;
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.GroupActionEvent event = 2;
     */
    event?: GetGroupActionsResponse_GetGroupActionsResponseV0_GroupActionEvent;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.GroupActions
 */
export interface GetGroupActionsResponse_GetGroupActionsResponseV0_GroupActions {
    /**
     * @generated from protobuf field: repeated org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.GroupActionEntry group_actions = 1;
     */
    groupActions: GetGroupActionsResponse_GetGroupActionsResponseV0_GroupActionEntry[];
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetGroupActionSignersRequest
 */
export interface GetGroupActionSignersRequest {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetGroupActionSignersRequest.GetGroupActionSignersRequestV0 v0 = 1;
         */
        v0: GetGroupActionSignersRequest_GetGroupActionSignersRequestV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetGroupActionSignersRequest.GetGroupActionSignersRequestV0
 */
export interface GetGroupActionSignersRequest_GetGroupActionSignersRequestV0 {
    /**
     * @generated from protobuf field: bytes contract_id = 1;
     */
    contractId: Uint8Array;
    /**
     * @generated from protobuf field: uint32 group_contract_position = 2;
     */
    groupContractPosition: number;
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.GetGroupActionSignersRequest.ActionStatus status = 3;
     */
    status: GetGroupActionSignersRequest_ActionStatus;
    /**
     * @generated from protobuf field: bytes action_id = 4;
     */
    actionId: Uint8Array;
    /**
     * @generated from protobuf field: bool prove = 5;
     */
    prove: boolean;
}
/**
 * @generated from protobuf enum org.dash.platform.dapi.v0.GetGroupActionSignersRequest.ActionStatus
 */
export declare enum GetGroupActionSignersRequest_ActionStatus {
    /**
     * Request the active actions
     *
     * @generated from protobuf enum value: ACTIVE = 0;
     */
    ACTIVE = 0,
    /**
     * Request the closed actions
     *
     * @generated from protobuf enum value: CLOSED = 1;
     */
    CLOSED = 1
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetGroupActionSignersResponse
 */
export interface GetGroupActionSignersResponse {
    /**
     * @generated from protobuf oneof: version
     */
    version: {
        oneofKind: "v0";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetGroupActionSignersResponse.GetGroupActionSignersResponseV0 v0 = 1;
         */
        v0: GetGroupActionSignersResponse_GetGroupActionSignersResponseV0;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetGroupActionSignersResponse.GetGroupActionSignersResponseV0
 */
export interface GetGroupActionSignersResponse_GetGroupActionSignersResponseV0 {
    /**
     * @generated from protobuf oneof: result
     */
    result: {
        oneofKind: "groupActionSigners";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.GetGroupActionSignersResponse.GetGroupActionSignersResponseV0.GroupActionSigners group_action_signers = 1;
         */
        groupActionSigners: GetGroupActionSignersResponse_GetGroupActionSignersResponseV0_GroupActionSigners;
    } | {
        oneofKind: "proof";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.Proof proof = 2;
         */
        proof: Proof;
    } | {
        oneofKind: undefined;
    };
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.ResponseMetadata metadata = 3;
     */
    metadata?: ResponseMetadata;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetGroupActionSignersResponse.GetGroupActionSignersResponseV0.GroupActionSigner
 */
export interface GetGroupActionSignersResponse_GetGroupActionSignersResponseV0_GroupActionSigner {
    /**
     * @generated from protobuf field: bytes signer_id = 1;
     */
    signerId: Uint8Array;
    /**
     * @generated from protobuf field: uint32 power = 2;
     */
    power: number;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetGroupActionSignersResponse.GetGroupActionSignersResponseV0.GroupActionSigners
 */
export interface GetGroupActionSignersResponse_GetGroupActionSignersResponseV0_GroupActionSigners {
    /**
     * @generated from protobuf field: repeated org.dash.platform.dapi.v0.GetGroupActionSignersResponse.GetGroupActionSignersResponseV0.GroupActionSigner signers = 1;
     */
    signers: GetGroupActionSignersResponse_GetGroupActionSignersResponseV0_GroupActionSigner[];
}
/**
 * @generated from protobuf enum org.dash.platform.dapi.v0.KeyPurpose
 */
export declare enum KeyPurpose {
    /**
     * @generated from protobuf enum value: AUTHENTICATION = 0;
     */
    AUTHENTICATION = 0,
    /**
     * @generated from protobuf enum value: ENCRYPTION = 1;
     */
    ENCRYPTION = 1,
    /**
     * @generated from protobuf enum value: DECRYPTION = 2;
     */
    DECRYPTION = 2,
    /**
     * @generated from protobuf enum value: TRANSFER = 3;
     */
    TRANSFER = 3,
    /**
     * @generated from protobuf enum value: VOTING = 5;
     */
    VOTING = 5
}
declare class Proof$Type extends MessageType<Proof> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.Proof
 */
export declare const Proof: Proof$Type;
declare class ResponseMetadata$Type extends MessageType<ResponseMetadata> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.ResponseMetadata
 */
export declare const ResponseMetadata: ResponseMetadata$Type;
declare class StateTransitionBroadcastError$Type extends MessageType<StateTransitionBroadcastError> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.StateTransitionBroadcastError
 */
export declare const StateTransitionBroadcastError: StateTransitionBroadcastError$Type;
declare class BroadcastStateTransitionRequest$Type extends MessageType<BroadcastStateTransitionRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.BroadcastStateTransitionRequest
 */
export declare const BroadcastStateTransitionRequest: BroadcastStateTransitionRequest$Type;
declare class BroadcastStateTransitionResponse$Type extends MessageType<BroadcastStateTransitionResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.BroadcastStateTransitionResponse
 */
export declare const BroadcastStateTransitionResponse: BroadcastStateTransitionResponse$Type;
declare class GetIdentityRequest$Type extends MessageType<GetIdentityRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentityRequest
 */
export declare const GetIdentityRequest: GetIdentityRequest$Type;
declare class GetIdentityRequest_GetIdentityRequestV0$Type extends MessageType<GetIdentityRequest_GetIdentityRequestV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentityRequest.GetIdentityRequestV0
 */
export declare const GetIdentityRequest_GetIdentityRequestV0: GetIdentityRequest_GetIdentityRequestV0$Type;
declare class GetIdentityNonceRequest$Type extends MessageType<GetIdentityNonceRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentityNonceRequest
 */
export declare const GetIdentityNonceRequest: GetIdentityNonceRequest$Type;
declare class GetIdentityNonceRequest_GetIdentityNonceRequestV0$Type extends MessageType<GetIdentityNonceRequest_GetIdentityNonceRequestV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentityNonceRequest.GetIdentityNonceRequestV0
 */
export declare const GetIdentityNonceRequest_GetIdentityNonceRequestV0: GetIdentityNonceRequest_GetIdentityNonceRequestV0$Type;
declare class GetIdentityContractNonceRequest$Type extends MessageType<GetIdentityContractNonceRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentityContractNonceRequest
 */
export declare const GetIdentityContractNonceRequest: GetIdentityContractNonceRequest$Type;
declare class GetIdentityContractNonceRequest_GetIdentityContractNonceRequestV0$Type extends MessageType<GetIdentityContractNonceRequest_GetIdentityContractNonceRequestV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentityContractNonceRequest.GetIdentityContractNonceRequestV0
 */
export declare const GetIdentityContractNonceRequest_GetIdentityContractNonceRequestV0: GetIdentityContractNonceRequest_GetIdentityContractNonceRequestV0$Type;
declare class GetIdentityBalanceRequest$Type extends MessageType<GetIdentityBalanceRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentityBalanceRequest
 */
export declare const GetIdentityBalanceRequest: GetIdentityBalanceRequest$Type;
declare class GetIdentityBalanceRequest_GetIdentityBalanceRequestV0$Type extends MessageType<GetIdentityBalanceRequest_GetIdentityBalanceRequestV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentityBalanceRequest.GetIdentityBalanceRequestV0
 */
export declare const GetIdentityBalanceRequest_GetIdentityBalanceRequestV0: GetIdentityBalanceRequest_GetIdentityBalanceRequestV0$Type;
declare class GetIdentityBalanceAndRevisionRequest$Type extends MessageType<GetIdentityBalanceAndRevisionRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentityBalanceAndRevisionRequest
 */
export declare const GetIdentityBalanceAndRevisionRequest: GetIdentityBalanceAndRevisionRequest$Type;
declare class GetIdentityBalanceAndRevisionRequest_GetIdentityBalanceAndRevisionRequestV0$Type extends MessageType<GetIdentityBalanceAndRevisionRequest_GetIdentityBalanceAndRevisionRequestV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentityBalanceAndRevisionRequest.GetIdentityBalanceAndRevisionRequestV0
 */
export declare const GetIdentityBalanceAndRevisionRequest_GetIdentityBalanceAndRevisionRequestV0: GetIdentityBalanceAndRevisionRequest_GetIdentityBalanceAndRevisionRequestV0$Type;
declare class GetIdentityResponse$Type extends MessageType<GetIdentityResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentityResponse
 */
export declare const GetIdentityResponse: GetIdentityResponse$Type;
declare class GetIdentityResponse_GetIdentityResponseV0$Type extends MessageType<GetIdentityResponse_GetIdentityResponseV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentityResponse.GetIdentityResponseV0
 */
export declare const GetIdentityResponse_GetIdentityResponseV0: GetIdentityResponse_GetIdentityResponseV0$Type;
declare class GetIdentityNonceResponse$Type extends MessageType<GetIdentityNonceResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentityNonceResponse
 */
export declare const GetIdentityNonceResponse: GetIdentityNonceResponse$Type;
declare class GetIdentityNonceResponse_GetIdentityNonceResponseV0$Type extends MessageType<GetIdentityNonceResponse_GetIdentityNonceResponseV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentityNonceResponse.GetIdentityNonceResponseV0
 */
export declare const GetIdentityNonceResponse_GetIdentityNonceResponseV0: GetIdentityNonceResponse_GetIdentityNonceResponseV0$Type;
declare class GetIdentityContractNonceResponse$Type extends MessageType<GetIdentityContractNonceResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentityContractNonceResponse
 */
export declare const GetIdentityContractNonceResponse: GetIdentityContractNonceResponse$Type;
declare class GetIdentityContractNonceResponse_GetIdentityContractNonceResponseV0$Type extends MessageType<GetIdentityContractNonceResponse_GetIdentityContractNonceResponseV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentityContractNonceResponse.GetIdentityContractNonceResponseV0
 */
export declare const GetIdentityContractNonceResponse_GetIdentityContractNonceResponseV0: GetIdentityContractNonceResponse_GetIdentityContractNonceResponseV0$Type;
declare class GetIdentityBalanceResponse$Type extends MessageType<GetIdentityBalanceResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentityBalanceResponse
 */
export declare const GetIdentityBalanceResponse: GetIdentityBalanceResponse$Type;
declare class GetIdentityBalanceResponse_GetIdentityBalanceResponseV0$Type extends MessageType<GetIdentityBalanceResponse_GetIdentityBalanceResponseV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentityBalanceResponse.GetIdentityBalanceResponseV0
 */
export declare const GetIdentityBalanceResponse_GetIdentityBalanceResponseV0: GetIdentityBalanceResponse_GetIdentityBalanceResponseV0$Type;
declare class GetIdentityBalanceAndRevisionResponse$Type extends MessageType<GetIdentityBalanceAndRevisionResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentityBalanceAndRevisionResponse
 */
export declare const GetIdentityBalanceAndRevisionResponse: GetIdentityBalanceAndRevisionResponse$Type;
declare class GetIdentityBalanceAndRevisionResponse_GetIdentityBalanceAndRevisionResponseV0$Type extends MessageType<GetIdentityBalanceAndRevisionResponse_GetIdentityBalanceAndRevisionResponseV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentityBalanceAndRevisionResponse.GetIdentityBalanceAndRevisionResponseV0
 */
export declare const GetIdentityBalanceAndRevisionResponse_GetIdentityBalanceAndRevisionResponseV0: GetIdentityBalanceAndRevisionResponse_GetIdentityBalanceAndRevisionResponseV0$Type;
declare class GetIdentityBalanceAndRevisionResponse_GetIdentityBalanceAndRevisionResponseV0_BalanceAndRevision$Type extends MessageType<GetIdentityBalanceAndRevisionResponse_GetIdentityBalanceAndRevisionResponseV0_BalanceAndRevision> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentityBalanceAndRevisionResponse.GetIdentityBalanceAndRevisionResponseV0.BalanceAndRevision
 */
export declare const GetIdentityBalanceAndRevisionResponse_GetIdentityBalanceAndRevisionResponseV0_BalanceAndRevision: GetIdentityBalanceAndRevisionResponse_GetIdentityBalanceAndRevisionResponseV0_BalanceAndRevision$Type;
declare class KeyRequestType$Type extends MessageType<KeyRequestType> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.KeyRequestType
 */
export declare const KeyRequestType: KeyRequestType$Type;
declare class AllKeys$Type extends MessageType<AllKeys> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.AllKeys
 */
export declare const AllKeys: AllKeys$Type;
declare class SpecificKeys$Type extends MessageType<SpecificKeys> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.SpecificKeys
 */
export declare const SpecificKeys: SpecificKeys$Type;
declare class SearchKey$Type extends MessageType<SearchKey> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.SearchKey
 */
export declare const SearchKey: SearchKey$Type;
declare class SecurityLevelMap$Type extends MessageType<SecurityLevelMap> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.SecurityLevelMap
 */
export declare const SecurityLevelMap: SecurityLevelMap$Type;
declare class GetIdentityKeysRequest$Type extends MessageType<GetIdentityKeysRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentityKeysRequest
 */
export declare const GetIdentityKeysRequest: GetIdentityKeysRequest$Type;
declare class GetIdentityKeysRequest_GetIdentityKeysRequestV0$Type extends MessageType<GetIdentityKeysRequest_GetIdentityKeysRequestV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentityKeysRequest.GetIdentityKeysRequestV0
 */
export declare const GetIdentityKeysRequest_GetIdentityKeysRequestV0: GetIdentityKeysRequest_GetIdentityKeysRequestV0$Type;
declare class GetIdentityKeysResponse$Type extends MessageType<GetIdentityKeysResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentityKeysResponse
 */
export declare const GetIdentityKeysResponse: GetIdentityKeysResponse$Type;
declare class GetIdentityKeysResponse_GetIdentityKeysResponseV0$Type extends MessageType<GetIdentityKeysResponse_GetIdentityKeysResponseV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentityKeysResponse.GetIdentityKeysResponseV0
 */
export declare const GetIdentityKeysResponse_GetIdentityKeysResponseV0: GetIdentityKeysResponse_GetIdentityKeysResponseV0$Type;
declare class GetIdentityKeysResponse_GetIdentityKeysResponseV0_Keys$Type extends MessageType<GetIdentityKeysResponse_GetIdentityKeysResponseV0_Keys> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentityKeysResponse.GetIdentityKeysResponseV0.Keys
 */
export declare const GetIdentityKeysResponse_GetIdentityKeysResponseV0_Keys: GetIdentityKeysResponse_GetIdentityKeysResponseV0_Keys$Type;
declare class GetIdentitiesContractKeysRequest$Type extends MessageType<GetIdentitiesContractKeysRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentitiesContractKeysRequest
 */
export declare const GetIdentitiesContractKeysRequest: GetIdentitiesContractKeysRequest$Type;
declare class GetIdentitiesContractKeysRequest_GetIdentitiesContractKeysRequestV0$Type extends MessageType<GetIdentitiesContractKeysRequest_GetIdentitiesContractKeysRequestV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentitiesContractKeysRequest.GetIdentitiesContractKeysRequestV0
 */
export declare const GetIdentitiesContractKeysRequest_GetIdentitiesContractKeysRequestV0: GetIdentitiesContractKeysRequest_GetIdentitiesContractKeysRequestV0$Type;
declare class GetIdentitiesContractKeysResponse$Type extends MessageType<GetIdentitiesContractKeysResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentitiesContractKeysResponse
 */
export declare const GetIdentitiesContractKeysResponse: GetIdentitiesContractKeysResponse$Type;
declare class GetIdentitiesContractKeysResponse_GetIdentitiesContractKeysResponseV0$Type extends MessageType<GetIdentitiesContractKeysResponse_GetIdentitiesContractKeysResponseV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentitiesContractKeysResponse.GetIdentitiesContractKeysResponseV0
 */
export declare const GetIdentitiesContractKeysResponse_GetIdentitiesContractKeysResponseV0: GetIdentitiesContractKeysResponse_GetIdentitiesContractKeysResponseV0$Type;
declare class GetIdentitiesContractKeysResponse_GetIdentitiesContractKeysResponseV0_PurposeKeys$Type extends MessageType<GetIdentitiesContractKeysResponse_GetIdentitiesContractKeysResponseV0_PurposeKeys> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentitiesContractKeysResponse.GetIdentitiesContractKeysResponseV0.PurposeKeys
 */
export declare const GetIdentitiesContractKeysResponse_GetIdentitiesContractKeysResponseV0_PurposeKeys: GetIdentitiesContractKeysResponse_GetIdentitiesContractKeysResponseV0_PurposeKeys$Type;
declare class GetIdentitiesContractKeysResponse_GetIdentitiesContractKeysResponseV0_IdentityKeys$Type extends MessageType<GetIdentitiesContractKeysResponse_GetIdentitiesContractKeysResponseV0_IdentityKeys> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentitiesContractKeysResponse.GetIdentitiesContractKeysResponseV0.IdentityKeys
 */
export declare const GetIdentitiesContractKeysResponse_GetIdentitiesContractKeysResponseV0_IdentityKeys: GetIdentitiesContractKeysResponse_GetIdentitiesContractKeysResponseV0_IdentityKeys$Type;
declare class GetIdentitiesContractKeysResponse_GetIdentitiesContractKeysResponseV0_IdentitiesKeys$Type extends MessageType<GetIdentitiesContractKeysResponse_GetIdentitiesContractKeysResponseV0_IdentitiesKeys> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentitiesContractKeysResponse.GetIdentitiesContractKeysResponseV0.IdentitiesKeys
 */
export declare const GetIdentitiesContractKeysResponse_GetIdentitiesContractKeysResponseV0_IdentitiesKeys: GetIdentitiesContractKeysResponse_GetIdentitiesContractKeysResponseV0_IdentitiesKeys$Type;
declare class GetEvonodesProposedEpochBlocksByIdsRequest$Type extends MessageType<GetEvonodesProposedEpochBlocksByIdsRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetEvonodesProposedEpochBlocksByIdsRequest
 */
export declare const GetEvonodesProposedEpochBlocksByIdsRequest: GetEvonodesProposedEpochBlocksByIdsRequest$Type;
declare class GetEvonodesProposedEpochBlocksByIdsRequest_GetEvonodesProposedEpochBlocksByIdsRequestV0$Type extends MessageType<GetEvonodesProposedEpochBlocksByIdsRequest_GetEvonodesProposedEpochBlocksByIdsRequestV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetEvonodesProposedEpochBlocksByIdsRequest.GetEvonodesProposedEpochBlocksByIdsRequestV0
 */
export declare const GetEvonodesProposedEpochBlocksByIdsRequest_GetEvonodesProposedEpochBlocksByIdsRequestV0: GetEvonodesProposedEpochBlocksByIdsRequest_GetEvonodesProposedEpochBlocksByIdsRequestV0$Type;
declare class GetEvonodesProposedEpochBlocksResponse$Type extends MessageType<GetEvonodesProposedEpochBlocksResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetEvonodesProposedEpochBlocksResponse
 */
export declare const GetEvonodesProposedEpochBlocksResponse: GetEvonodesProposedEpochBlocksResponse$Type;
declare class GetEvonodesProposedEpochBlocksResponse_GetEvonodesProposedEpochBlocksResponseV0$Type extends MessageType<GetEvonodesProposedEpochBlocksResponse_GetEvonodesProposedEpochBlocksResponseV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetEvonodesProposedEpochBlocksResponse.GetEvonodesProposedEpochBlocksResponseV0
 */
export declare const GetEvonodesProposedEpochBlocksResponse_GetEvonodesProposedEpochBlocksResponseV0: GetEvonodesProposedEpochBlocksResponse_GetEvonodesProposedEpochBlocksResponseV0$Type;
declare class GetEvonodesProposedEpochBlocksResponse_GetEvonodesProposedEpochBlocksResponseV0_EvonodeProposedBlocks$Type extends MessageType<GetEvonodesProposedEpochBlocksResponse_GetEvonodesProposedEpochBlocksResponseV0_EvonodeProposedBlocks> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetEvonodesProposedEpochBlocksResponse.GetEvonodesProposedEpochBlocksResponseV0.EvonodeProposedBlocks
 */
export declare const GetEvonodesProposedEpochBlocksResponse_GetEvonodesProposedEpochBlocksResponseV0_EvonodeProposedBlocks: GetEvonodesProposedEpochBlocksResponse_GetEvonodesProposedEpochBlocksResponseV0_EvonodeProposedBlocks$Type;
declare class GetEvonodesProposedEpochBlocksResponse_GetEvonodesProposedEpochBlocksResponseV0_EvonodesProposedBlocks$Type extends MessageType<GetEvonodesProposedEpochBlocksResponse_GetEvonodesProposedEpochBlocksResponseV0_EvonodesProposedBlocks> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetEvonodesProposedEpochBlocksResponse.GetEvonodesProposedEpochBlocksResponseV0.EvonodesProposedBlocks
 */
export declare const GetEvonodesProposedEpochBlocksResponse_GetEvonodesProposedEpochBlocksResponseV0_EvonodesProposedBlocks: GetEvonodesProposedEpochBlocksResponse_GetEvonodesProposedEpochBlocksResponseV0_EvonodesProposedBlocks$Type;
declare class GetEvonodesProposedEpochBlocksByRangeRequest$Type extends MessageType<GetEvonodesProposedEpochBlocksByRangeRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetEvonodesProposedEpochBlocksByRangeRequest
 */
export declare const GetEvonodesProposedEpochBlocksByRangeRequest: GetEvonodesProposedEpochBlocksByRangeRequest$Type;
declare class GetEvonodesProposedEpochBlocksByRangeRequest_GetEvonodesProposedEpochBlocksByRangeRequestV0$Type extends MessageType<GetEvonodesProposedEpochBlocksByRangeRequest_GetEvonodesProposedEpochBlocksByRangeRequestV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetEvonodesProposedEpochBlocksByRangeRequest.GetEvonodesProposedEpochBlocksByRangeRequestV0
 */
export declare const GetEvonodesProposedEpochBlocksByRangeRequest_GetEvonodesProposedEpochBlocksByRangeRequestV0: GetEvonodesProposedEpochBlocksByRangeRequest_GetEvonodesProposedEpochBlocksByRangeRequestV0$Type;
declare class GetIdentitiesBalancesRequest$Type extends MessageType<GetIdentitiesBalancesRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentitiesBalancesRequest
 */
export declare const GetIdentitiesBalancesRequest: GetIdentitiesBalancesRequest$Type;
declare class GetIdentitiesBalancesRequest_GetIdentitiesBalancesRequestV0$Type extends MessageType<GetIdentitiesBalancesRequest_GetIdentitiesBalancesRequestV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentitiesBalancesRequest.GetIdentitiesBalancesRequestV0
 */
export declare const GetIdentitiesBalancesRequest_GetIdentitiesBalancesRequestV0: GetIdentitiesBalancesRequest_GetIdentitiesBalancesRequestV0$Type;
declare class GetIdentitiesBalancesResponse$Type extends MessageType<GetIdentitiesBalancesResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentitiesBalancesResponse
 */
export declare const GetIdentitiesBalancesResponse: GetIdentitiesBalancesResponse$Type;
declare class GetIdentitiesBalancesResponse_GetIdentitiesBalancesResponseV0$Type extends MessageType<GetIdentitiesBalancesResponse_GetIdentitiesBalancesResponseV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentitiesBalancesResponse.GetIdentitiesBalancesResponseV0
 */
export declare const GetIdentitiesBalancesResponse_GetIdentitiesBalancesResponseV0: GetIdentitiesBalancesResponse_GetIdentitiesBalancesResponseV0$Type;
declare class GetIdentitiesBalancesResponse_GetIdentitiesBalancesResponseV0_IdentityBalance$Type extends MessageType<GetIdentitiesBalancesResponse_GetIdentitiesBalancesResponseV0_IdentityBalance> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentitiesBalancesResponse.GetIdentitiesBalancesResponseV0.IdentityBalance
 */
export declare const GetIdentitiesBalancesResponse_GetIdentitiesBalancesResponseV0_IdentityBalance: GetIdentitiesBalancesResponse_GetIdentitiesBalancesResponseV0_IdentityBalance$Type;
declare class GetIdentitiesBalancesResponse_GetIdentitiesBalancesResponseV0_IdentitiesBalances$Type extends MessageType<GetIdentitiesBalancesResponse_GetIdentitiesBalancesResponseV0_IdentitiesBalances> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentitiesBalancesResponse.GetIdentitiesBalancesResponseV0.IdentitiesBalances
 */
export declare const GetIdentitiesBalancesResponse_GetIdentitiesBalancesResponseV0_IdentitiesBalances: GetIdentitiesBalancesResponse_GetIdentitiesBalancesResponseV0_IdentitiesBalances$Type;
declare class GetProofsRequest$Type extends MessageType<GetProofsRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetProofsRequest
 */
export declare const GetProofsRequest: GetProofsRequest$Type;
declare class GetProofsRequest_GetProofsRequestV0$Type extends MessageType<GetProofsRequest_GetProofsRequestV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetProofsRequest.GetProofsRequestV0
 */
export declare const GetProofsRequest_GetProofsRequestV0: GetProofsRequest_GetProofsRequestV0$Type;
declare class GetProofsRequest_GetProofsRequestV0_DocumentRequest$Type extends MessageType<GetProofsRequest_GetProofsRequestV0_DocumentRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetProofsRequest.GetProofsRequestV0.DocumentRequest
 */
export declare const GetProofsRequest_GetProofsRequestV0_DocumentRequest: GetProofsRequest_GetProofsRequestV0_DocumentRequest$Type;
declare class GetProofsRequest_GetProofsRequestV0_IdentityRequest$Type extends MessageType<GetProofsRequest_GetProofsRequestV0_IdentityRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetProofsRequest.GetProofsRequestV0.IdentityRequest
 */
export declare const GetProofsRequest_GetProofsRequestV0_IdentityRequest: GetProofsRequest_GetProofsRequestV0_IdentityRequest$Type;
declare class GetProofsRequest_GetProofsRequestV0_ContractRequest$Type extends MessageType<GetProofsRequest_GetProofsRequestV0_ContractRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetProofsRequest.GetProofsRequestV0.ContractRequest
 */
export declare const GetProofsRequest_GetProofsRequestV0_ContractRequest: GetProofsRequest_GetProofsRequestV0_ContractRequest$Type;
declare class GetProofsRequest_GetProofsRequestV0_VoteStatusRequest$Type extends MessageType<GetProofsRequest_GetProofsRequestV0_VoteStatusRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetProofsRequest.GetProofsRequestV0.VoteStatusRequest
 */
export declare const GetProofsRequest_GetProofsRequestV0_VoteStatusRequest: GetProofsRequest_GetProofsRequestV0_VoteStatusRequest$Type;
declare class GetProofsRequest_GetProofsRequestV0_VoteStatusRequest_ContestedResourceVoteStatusRequest$Type extends MessageType<GetProofsRequest_GetProofsRequestV0_VoteStatusRequest_ContestedResourceVoteStatusRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetProofsRequest.GetProofsRequestV0.VoteStatusRequest.ContestedResourceVoteStatusRequest
 */
export declare const GetProofsRequest_GetProofsRequestV0_VoteStatusRequest_ContestedResourceVoteStatusRequest: GetProofsRequest_GetProofsRequestV0_VoteStatusRequest_ContestedResourceVoteStatusRequest$Type;
declare class GetProofsRequest_GetProofsRequestV0_IdentityTokenBalanceRequest$Type extends MessageType<GetProofsRequest_GetProofsRequestV0_IdentityTokenBalanceRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetProofsRequest.GetProofsRequestV0.IdentityTokenBalanceRequest
 */
export declare const GetProofsRequest_GetProofsRequestV0_IdentityTokenBalanceRequest: GetProofsRequest_GetProofsRequestV0_IdentityTokenBalanceRequest$Type;
declare class GetProofsRequest_GetProofsRequestV0_IdentityTokenInfoRequest$Type extends MessageType<GetProofsRequest_GetProofsRequestV0_IdentityTokenInfoRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetProofsRequest.GetProofsRequestV0.IdentityTokenInfoRequest
 */
export declare const GetProofsRequest_GetProofsRequestV0_IdentityTokenInfoRequest: GetProofsRequest_GetProofsRequestV0_IdentityTokenInfoRequest$Type;
declare class GetProofsRequest_GetProofsRequestV0_TokenStatusRequest$Type extends MessageType<GetProofsRequest_GetProofsRequestV0_TokenStatusRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetProofsRequest.GetProofsRequestV0.TokenStatusRequest
 */
export declare const GetProofsRequest_GetProofsRequestV0_TokenStatusRequest: GetProofsRequest_GetProofsRequestV0_TokenStatusRequest$Type;
declare class GetProofsResponse$Type extends MessageType<GetProofsResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetProofsResponse
 */
export declare const GetProofsResponse: GetProofsResponse$Type;
declare class GetProofsResponse_GetProofsResponseV0$Type extends MessageType<GetProofsResponse_GetProofsResponseV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetProofsResponse.GetProofsResponseV0
 */
export declare const GetProofsResponse_GetProofsResponseV0: GetProofsResponse_GetProofsResponseV0$Type;
declare class GetDataContractRequest$Type extends MessageType<GetDataContractRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetDataContractRequest
 */
export declare const GetDataContractRequest: GetDataContractRequest$Type;
declare class GetDataContractRequest_GetDataContractRequestV0$Type extends MessageType<GetDataContractRequest_GetDataContractRequestV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetDataContractRequest.GetDataContractRequestV0
 */
export declare const GetDataContractRequest_GetDataContractRequestV0: GetDataContractRequest_GetDataContractRequestV0$Type;
declare class GetDataContractResponse$Type extends MessageType<GetDataContractResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetDataContractResponse
 */
export declare const GetDataContractResponse: GetDataContractResponse$Type;
declare class GetDataContractResponse_GetDataContractResponseV0$Type extends MessageType<GetDataContractResponse_GetDataContractResponseV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetDataContractResponse.GetDataContractResponseV0
 */
export declare const GetDataContractResponse_GetDataContractResponseV0: GetDataContractResponse_GetDataContractResponseV0$Type;
declare class GetDataContractsRequest$Type extends MessageType<GetDataContractsRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetDataContractsRequest
 */
export declare const GetDataContractsRequest: GetDataContractsRequest$Type;
declare class GetDataContractsRequest_GetDataContractsRequestV0$Type extends MessageType<GetDataContractsRequest_GetDataContractsRequestV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetDataContractsRequest.GetDataContractsRequestV0
 */
export declare const GetDataContractsRequest_GetDataContractsRequestV0: GetDataContractsRequest_GetDataContractsRequestV0$Type;
declare class GetDataContractsResponse$Type extends MessageType<GetDataContractsResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetDataContractsResponse
 */
export declare const GetDataContractsResponse: GetDataContractsResponse$Type;
declare class GetDataContractsResponse_DataContractEntry$Type extends MessageType<GetDataContractsResponse_DataContractEntry> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetDataContractsResponse.DataContractEntry
 */
export declare const GetDataContractsResponse_DataContractEntry: GetDataContractsResponse_DataContractEntry$Type;
declare class GetDataContractsResponse_DataContracts$Type extends MessageType<GetDataContractsResponse_DataContracts> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetDataContractsResponse.DataContracts
 */
export declare const GetDataContractsResponse_DataContracts: GetDataContractsResponse_DataContracts$Type;
declare class GetDataContractsResponse_GetDataContractsResponseV0$Type extends MessageType<GetDataContractsResponse_GetDataContractsResponseV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetDataContractsResponse.GetDataContractsResponseV0
 */
export declare const GetDataContractsResponse_GetDataContractsResponseV0: GetDataContractsResponse_GetDataContractsResponseV0$Type;
declare class GetDataContractHistoryRequest$Type extends MessageType<GetDataContractHistoryRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetDataContractHistoryRequest
 */
export declare const GetDataContractHistoryRequest: GetDataContractHistoryRequest$Type;
declare class GetDataContractHistoryRequest_GetDataContractHistoryRequestV0$Type extends MessageType<GetDataContractHistoryRequest_GetDataContractHistoryRequestV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetDataContractHistoryRequest.GetDataContractHistoryRequestV0
 */
export declare const GetDataContractHistoryRequest_GetDataContractHistoryRequestV0: GetDataContractHistoryRequest_GetDataContractHistoryRequestV0$Type;
declare class GetDataContractHistoryResponse$Type extends MessageType<GetDataContractHistoryResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetDataContractHistoryResponse
 */
export declare const GetDataContractHistoryResponse: GetDataContractHistoryResponse$Type;
declare class GetDataContractHistoryResponse_GetDataContractHistoryResponseV0$Type extends MessageType<GetDataContractHistoryResponse_GetDataContractHistoryResponseV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetDataContractHistoryResponse.GetDataContractHistoryResponseV0
 */
export declare const GetDataContractHistoryResponse_GetDataContractHistoryResponseV0: GetDataContractHistoryResponse_GetDataContractHistoryResponseV0$Type;
declare class GetDataContractHistoryResponse_GetDataContractHistoryResponseV0_DataContractHistoryEntry$Type extends MessageType<GetDataContractHistoryResponse_GetDataContractHistoryResponseV0_DataContractHistoryEntry> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetDataContractHistoryResponse.GetDataContractHistoryResponseV0.DataContractHistoryEntry
 */
export declare const GetDataContractHistoryResponse_GetDataContractHistoryResponseV0_DataContractHistoryEntry: GetDataContractHistoryResponse_GetDataContractHistoryResponseV0_DataContractHistoryEntry$Type;
declare class GetDataContractHistoryResponse_GetDataContractHistoryResponseV0_DataContractHistory$Type extends MessageType<GetDataContractHistoryResponse_GetDataContractHistoryResponseV0_DataContractHistory> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetDataContractHistoryResponse.GetDataContractHistoryResponseV0.DataContractHistory
 */
export declare const GetDataContractHistoryResponse_GetDataContractHistoryResponseV0_DataContractHistory: GetDataContractHistoryResponse_GetDataContractHistoryResponseV0_DataContractHistory$Type;
declare class GetDocumentsRequest$Type extends MessageType<GetDocumentsRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetDocumentsRequest
 */
export declare const GetDocumentsRequest: GetDocumentsRequest$Type;
declare class GetDocumentsRequest_GetDocumentsRequestV0$Type extends MessageType<GetDocumentsRequest_GetDocumentsRequestV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetDocumentsRequest.GetDocumentsRequestV0
 */
export declare const GetDocumentsRequest_GetDocumentsRequestV0: GetDocumentsRequest_GetDocumentsRequestV0$Type;
declare class GetDocumentsResponse$Type extends MessageType<GetDocumentsResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetDocumentsResponse
 */
export declare const GetDocumentsResponse: GetDocumentsResponse$Type;
declare class GetDocumentsResponse_GetDocumentsResponseV0$Type extends MessageType<GetDocumentsResponse_GetDocumentsResponseV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetDocumentsResponse.GetDocumentsResponseV0
 */
export declare const GetDocumentsResponse_GetDocumentsResponseV0: GetDocumentsResponse_GetDocumentsResponseV0$Type;
declare class GetDocumentsResponse_GetDocumentsResponseV0_Documents$Type extends MessageType<GetDocumentsResponse_GetDocumentsResponseV0_Documents> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetDocumentsResponse.GetDocumentsResponseV0.Documents
 */
export declare const GetDocumentsResponse_GetDocumentsResponseV0_Documents: GetDocumentsResponse_GetDocumentsResponseV0_Documents$Type;
declare class GetIdentityByPublicKeyHashRequest$Type extends MessageType<GetIdentityByPublicKeyHashRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentityByPublicKeyHashRequest
 */
export declare const GetIdentityByPublicKeyHashRequest: GetIdentityByPublicKeyHashRequest$Type;
declare class GetIdentityByPublicKeyHashRequest_GetIdentityByPublicKeyHashRequestV0$Type extends MessageType<GetIdentityByPublicKeyHashRequest_GetIdentityByPublicKeyHashRequestV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentityByPublicKeyHashRequest.GetIdentityByPublicKeyHashRequestV0
 */
export declare const GetIdentityByPublicKeyHashRequest_GetIdentityByPublicKeyHashRequestV0: GetIdentityByPublicKeyHashRequest_GetIdentityByPublicKeyHashRequestV0$Type;
declare class GetIdentityByPublicKeyHashResponse$Type extends MessageType<GetIdentityByPublicKeyHashResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentityByPublicKeyHashResponse
 */
export declare const GetIdentityByPublicKeyHashResponse: GetIdentityByPublicKeyHashResponse$Type;
declare class GetIdentityByPublicKeyHashResponse_GetIdentityByPublicKeyHashResponseV0$Type extends MessageType<GetIdentityByPublicKeyHashResponse_GetIdentityByPublicKeyHashResponseV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentityByPublicKeyHashResponse.GetIdentityByPublicKeyHashResponseV0
 */
export declare const GetIdentityByPublicKeyHashResponse_GetIdentityByPublicKeyHashResponseV0: GetIdentityByPublicKeyHashResponse_GetIdentityByPublicKeyHashResponseV0$Type;
declare class WaitForStateTransitionResultRequest$Type extends MessageType<WaitForStateTransitionResultRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.WaitForStateTransitionResultRequest
 */
export declare const WaitForStateTransitionResultRequest: WaitForStateTransitionResultRequest$Type;
declare class WaitForStateTransitionResultRequest_WaitForStateTransitionResultRequestV0$Type extends MessageType<WaitForStateTransitionResultRequest_WaitForStateTransitionResultRequestV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.WaitForStateTransitionResultRequest.WaitForStateTransitionResultRequestV0
 */
export declare const WaitForStateTransitionResultRequest_WaitForStateTransitionResultRequestV0: WaitForStateTransitionResultRequest_WaitForStateTransitionResultRequestV0$Type;
declare class WaitForStateTransitionResultResponse$Type extends MessageType<WaitForStateTransitionResultResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.WaitForStateTransitionResultResponse
 */
export declare const WaitForStateTransitionResultResponse: WaitForStateTransitionResultResponse$Type;
declare class WaitForStateTransitionResultResponse_WaitForStateTransitionResultResponseV0$Type extends MessageType<WaitForStateTransitionResultResponse_WaitForStateTransitionResultResponseV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.WaitForStateTransitionResultResponse.WaitForStateTransitionResultResponseV0
 */
export declare const WaitForStateTransitionResultResponse_WaitForStateTransitionResultResponseV0: WaitForStateTransitionResultResponse_WaitForStateTransitionResultResponseV0$Type;
declare class GetConsensusParamsRequest$Type extends MessageType<GetConsensusParamsRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetConsensusParamsRequest
 */
export declare const GetConsensusParamsRequest: GetConsensusParamsRequest$Type;
declare class GetConsensusParamsRequest_GetConsensusParamsRequestV0$Type extends MessageType<GetConsensusParamsRequest_GetConsensusParamsRequestV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetConsensusParamsRequest.GetConsensusParamsRequestV0
 */
export declare const GetConsensusParamsRequest_GetConsensusParamsRequestV0: GetConsensusParamsRequest_GetConsensusParamsRequestV0$Type;
declare class GetConsensusParamsResponse$Type extends MessageType<GetConsensusParamsResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetConsensusParamsResponse
 */
export declare const GetConsensusParamsResponse: GetConsensusParamsResponse$Type;
declare class GetConsensusParamsResponse_ConsensusParamsBlock$Type extends MessageType<GetConsensusParamsResponse_ConsensusParamsBlock> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetConsensusParamsResponse.ConsensusParamsBlock
 */
export declare const GetConsensusParamsResponse_ConsensusParamsBlock: GetConsensusParamsResponse_ConsensusParamsBlock$Type;
declare class GetConsensusParamsResponse_ConsensusParamsEvidence$Type extends MessageType<GetConsensusParamsResponse_ConsensusParamsEvidence> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetConsensusParamsResponse.ConsensusParamsEvidence
 */
export declare const GetConsensusParamsResponse_ConsensusParamsEvidence: GetConsensusParamsResponse_ConsensusParamsEvidence$Type;
declare class GetConsensusParamsResponse_GetConsensusParamsResponseV0$Type extends MessageType<GetConsensusParamsResponse_GetConsensusParamsResponseV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetConsensusParamsResponse.GetConsensusParamsResponseV0
 */
export declare const GetConsensusParamsResponse_GetConsensusParamsResponseV0: GetConsensusParamsResponse_GetConsensusParamsResponseV0$Type;
declare class GetProtocolVersionUpgradeStateRequest$Type extends MessageType<GetProtocolVersionUpgradeStateRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetProtocolVersionUpgradeStateRequest
 */
export declare const GetProtocolVersionUpgradeStateRequest: GetProtocolVersionUpgradeStateRequest$Type;
declare class GetProtocolVersionUpgradeStateRequest_GetProtocolVersionUpgradeStateRequestV0$Type extends MessageType<GetProtocolVersionUpgradeStateRequest_GetProtocolVersionUpgradeStateRequestV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetProtocolVersionUpgradeStateRequest.GetProtocolVersionUpgradeStateRequestV0
 */
export declare const GetProtocolVersionUpgradeStateRequest_GetProtocolVersionUpgradeStateRequestV0: GetProtocolVersionUpgradeStateRequest_GetProtocolVersionUpgradeStateRequestV0$Type;
declare class GetProtocolVersionUpgradeStateResponse$Type extends MessageType<GetProtocolVersionUpgradeStateResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetProtocolVersionUpgradeStateResponse
 */
export declare const GetProtocolVersionUpgradeStateResponse: GetProtocolVersionUpgradeStateResponse$Type;
declare class GetProtocolVersionUpgradeStateResponse_GetProtocolVersionUpgradeStateResponseV0$Type extends MessageType<GetProtocolVersionUpgradeStateResponse_GetProtocolVersionUpgradeStateResponseV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetProtocolVersionUpgradeStateResponse.GetProtocolVersionUpgradeStateResponseV0
 */
export declare const GetProtocolVersionUpgradeStateResponse_GetProtocolVersionUpgradeStateResponseV0: GetProtocolVersionUpgradeStateResponse_GetProtocolVersionUpgradeStateResponseV0$Type;
declare class GetProtocolVersionUpgradeStateResponse_GetProtocolVersionUpgradeStateResponseV0_Versions$Type extends MessageType<GetProtocolVersionUpgradeStateResponse_GetProtocolVersionUpgradeStateResponseV0_Versions> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetProtocolVersionUpgradeStateResponse.GetProtocolVersionUpgradeStateResponseV0.Versions
 */
export declare const GetProtocolVersionUpgradeStateResponse_GetProtocolVersionUpgradeStateResponseV0_Versions: GetProtocolVersionUpgradeStateResponse_GetProtocolVersionUpgradeStateResponseV0_Versions$Type;
declare class GetProtocolVersionUpgradeStateResponse_GetProtocolVersionUpgradeStateResponseV0_VersionEntry$Type extends MessageType<GetProtocolVersionUpgradeStateResponse_GetProtocolVersionUpgradeStateResponseV0_VersionEntry> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetProtocolVersionUpgradeStateResponse.GetProtocolVersionUpgradeStateResponseV0.VersionEntry
 */
export declare const GetProtocolVersionUpgradeStateResponse_GetProtocolVersionUpgradeStateResponseV0_VersionEntry: GetProtocolVersionUpgradeStateResponse_GetProtocolVersionUpgradeStateResponseV0_VersionEntry$Type;
declare class GetProtocolVersionUpgradeVoteStatusRequest$Type extends MessageType<GetProtocolVersionUpgradeVoteStatusRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetProtocolVersionUpgradeVoteStatusRequest
 */
export declare const GetProtocolVersionUpgradeVoteStatusRequest: GetProtocolVersionUpgradeVoteStatusRequest$Type;
declare class GetProtocolVersionUpgradeVoteStatusRequest_GetProtocolVersionUpgradeVoteStatusRequestV0$Type extends MessageType<GetProtocolVersionUpgradeVoteStatusRequest_GetProtocolVersionUpgradeVoteStatusRequestV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetProtocolVersionUpgradeVoteStatusRequest.GetProtocolVersionUpgradeVoteStatusRequestV0
 */
export declare const GetProtocolVersionUpgradeVoteStatusRequest_GetProtocolVersionUpgradeVoteStatusRequestV0: GetProtocolVersionUpgradeVoteStatusRequest_GetProtocolVersionUpgradeVoteStatusRequestV0$Type;
declare class GetProtocolVersionUpgradeVoteStatusResponse$Type extends MessageType<GetProtocolVersionUpgradeVoteStatusResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetProtocolVersionUpgradeVoteStatusResponse
 */
export declare const GetProtocolVersionUpgradeVoteStatusResponse: GetProtocolVersionUpgradeVoteStatusResponse$Type;
declare class GetProtocolVersionUpgradeVoteStatusResponse_GetProtocolVersionUpgradeVoteStatusResponseV0$Type extends MessageType<GetProtocolVersionUpgradeVoteStatusResponse_GetProtocolVersionUpgradeVoteStatusResponseV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetProtocolVersionUpgradeVoteStatusResponse.GetProtocolVersionUpgradeVoteStatusResponseV0
 */
export declare const GetProtocolVersionUpgradeVoteStatusResponse_GetProtocolVersionUpgradeVoteStatusResponseV0: GetProtocolVersionUpgradeVoteStatusResponse_GetProtocolVersionUpgradeVoteStatusResponseV0$Type;
declare class GetProtocolVersionUpgradeVoteStatusResponse_GetProtocolVersionUpgradeVoteStatusResponseV0_VersionSignals$Type extends MessageType<GetProtocolVersionUpgradeVoteStatusResponse_GetProtocolVersionUpgradeVoteStatusResponseV0_VersionSignals> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetProtocolVersionUpgradeVoteStatusResponse.GetProtocolVersionUpgradeVoteStatusResponseV0.VersionSignals
 */
export declare const GetProtocolVersionUpgradeVoteStatusResponse_GetProtocolVersionUpgradeVoteStatusResponseV0_VersionSignals: GetProtocolVersionUpgradeVoteStatusResponse_GetProtocolVersionUpgradeVoteStatusResponseV0_VersionSignals$Type;
declare class GetProtocolVersionUpgradeVoteStatusResponse_GetProtocolVersionUpgradeVoteStatusResponseV0_VersionSignal$Type extends MessageType<GetProtocolVersionUpgradeVoteStatusResponse_GetProtocolVersionUpgradeVoteStatusResponseV0_VersionSignal> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetProtocolVersionUpgradeVoteStatusResponse.GetProtocolVersionUpgradeVoteStatusResponseV0.VersionSignal
 */
export declare const GetProtocolVersionUpgradeVoteStatusResponse_GetProtocolVersionUpgradeVoteStatusResponseV0_VersionSignal: GetProtocolVersionUpgradeVoteStatusResponse_GetProtocolVersionUpgradeVoteStatusResponseV0_VersionSignal$Type;
declare class GetEpochsInfoRequest$Type extends MessageType<GetEpochsInfoRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetEpochsInfoRequest
 */
export declare const GetEpochsInfoRequest: GetEpochsInfoRequest$Type;
declare class GetEpochsInfoRequest_GetEpochsInfoRequestV0$Type extends MessageType<GetEpochsInfoRequest_GetEpochsInfoRequestV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetEpochsInfoRequest.GetEpochsInfoRequestV0
 */
export declare const GetEpochsInfoRequest_GetEpochsInfoRequestV0: GetEpochsInfoRequest_GetEpochsInfoRequestV0$Type;
declare class GetEpochsInfoResponse$Type extends MessageType<GetEpochsInfoResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetEpochsInfoResponse
 */
export declare const GetEpochsInfoResponse: GetEpochsInfoResponse$Type;
declare class GetEpochsInfoResponse_GetEpochsInfoResponseV0$Type extends MessageType<GetEpochsInfoResponse_GetEpochsInfoResponseV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetEpochsInfoResponse.GetEpochsInfoResponseV0
 */
export declare const GetEpochsInfoResponse_GetEpochsInfoResponseV0: GetEpochsInfoResponse_GetEpochsInfoResponseV0$Type;
declare class GetEpochsInfoResponse_GetEpochsInfoResponseV0_EpochInfos$Type extends MessageType<GetEpochsInfoResponse_GetEpochsInfoResponseV0_EpochInfos> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetEpochsInfoResponse.GetEpochsInfoResponseV0.EpochInfos
 */
export declare const GetEpochsInfoResponse_GetEpochsInfoResponseV0_EpochInfos: GetEpochsInfoResponse_GetEpochsInfoResponseV0_EpochInfos$Type;
declare class GetEpochsInfoResponse_GetEpochsInfoResponseV0_EpochInfo$Type extends MessageType<GetEpochsInfoResponse_GetEpochsInfoResponseV0_EpochInfo> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetEpochsInfoResponse.GetEpochsInfoResponseV0.EpochInfo
 */
export declare const GetEpochsInfoResponse_GetEpochsInfoResponseV0_EpochInfo: GetEpochsInfoResponse_GetEpochsInfoResponseV0_EpochInfo$Type;
declare class GetContestedResourcesRequest$Type extends MessageType<GetContestedResourcesRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetContestedResourcesRequest
 */
export declare const GetContestedResourcesRequest: GetContestedResourcesRequest$Type;
declare class GetContestedResourcesRequest_GetContestedResourcesRequestV0$Type extends MessageType<GetContestedResourcesRequest_GetContestedResourcesRequestV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetContestedResourcesRequest.GetContestedResourcesRequestV0
 */
export declare const GetContestedResourcesRequest_GetContestedResourcesRequestV0: GetContestedResourcesRequest_GetContestedResourcesRequestV0$Type;
declare class GetContestedResourcesRequest_GetContestedResourcesRequestV0_StartAtValueInfo$Type extends MessageType<GetContestedResourcesRequest_GetContestedResourcesRequestV0_StartAtValueInfo> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetContestedResourcesRequest.GetContestedResourcesRequestV0.StartAtValueInfo
 */
export declare const GetContestedResourcesRequest_GetContestedResourcesRequestV0_StartAtValueInfo: GetContestedResourcesRequest_GetContestedResourcesRequestV0_StartAtValueInfo$Type;
declare class GetContestedResourcesResponse$Type extends MessageType<GetContestedResourcesResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetContestedResourcesResponse
 */
export declare const GetContestedResourcesResponse: GetContestedResourcesResponse$Type;
declare class GetContestedResourcesResponse_GetContestedResourcesResponseV0$Type extends MessageType<GetContestedResourcesResponse_GetContestedResourcesResponseV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetContestedResourcesResponse.GetContestedResourcesResponseV0
 */
export declare const GetContestedResourcesResponse_GetContestedResourcesResponseV0: GetContestedResourcesResponse_GetContestedResourcesResponseV0$Type;
declare class GetContestedResourcesResponse_GetContestedResourcesResponseV0_ContestedResourceValues$Type extends MessageType<GetContestedResourcesResponse_GetContestedResourcesResponseV0_ContestedResourceValues> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetContestedResourcesResponse.GetContestedResourcesResponseV0.ContestedResourceValues
 */
export declare const GetContestedResourcesResponse_GetContestedResourcesResponseV0_ContestedResourceValues: GetContestedResourcesResponse_GetContestedResourcesResponseV0_ContestedResourceValues$Type;
declare class GetVotePollsByEndDateRequest$Type extends MessageType<GetVotePollsByEndDateRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetVotePollsByEndDateRequest
 */
export declare const GetVotePollsByEndDateRequest: GetVotePollsByEndDateRequest$Type;
declare class GetVotePollsByEndDateRequest_GetVotePollsByEndDateRequestV0$Type extends MessageType<GetVotePollsByEndDateRequest_GetVotePollsByEndDateRequestV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetVotePollsByEndDateRequest.GetVotePollsByEndDateRequestV0
 */
export declare const GetVotePollsByEndDateRequest_GetVotePollsByEndDateRequestV0: GetVotePollsByEndDateRequest_GetVotePollsByEndDateRequestV0$Type;
declare class GetVotePollsByEndDateRequest_GetVotePollsByEndDateRequestV0_StartAtTimeInfo$Type extends MessageType<GetVotePollsByEndDateRequest_GetVotePollsByEndDateRequestV0_StartAtTimeInfo> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetVotePollsByEndDateRequest.GetVotePollsByEndDateRequestV0.StartAtTimeInfo
 */
export declare const GetVotePollsByEndDateRequest_GetVotePollsByEndDateRequestV0_StartAtTimeInfo: GetVotePollsByEndDateRequest_GetVotePollsByEndDateRequestV0_StartAtTimeInfo$Type;
declare class GetVotePollsByEndDateRequest_GetVotePollsByEndDateRequestV0_EndAtTimeInfo$Type extends MessageType<GetVotePollsByEndDateRequest_GetVotePollsByEndDateRequestV0_EndAtTimeInfo> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetVotePollsByEndDateRequest.GetVotePollsByEndDateRequestV0.EndAtTimeInfo
 */
export declare const GetVotePollsByEndDateRequest_GetVotePollsByEndDateRequestV0_EndAtTimeInfo: GetVotePollsByEndDateRequest_GetVotePollsByEndDateRequestV0_EndAtTimeInfo$Type;
declare class GetVotePollsByEndDateResponse$Type extends MessageType<GetVotePollsByEndDateResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetVotePollsByEndDateResponse
 */
export declare const GetVotePollsByEndDateResponse: GetVotePollsByEndDateResponse$Type;
declare class GetVotePollsByEndDateResponse_GetVotePollsByEndDateResponseV0$Type extends MessageType<GetVotePollsByEndDateResponse_GetVotePollsByEndDateResponseV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetVotePollsByEndDateResponse.GetVotePollsByEndDateResponseV0
 */
export declare const GetVotePollsByEndDateResponse_GetVotePollsByEndDateResponseV0: GetVotePollsByEndDateResponse_GetVotePollsByEndDateResponseV0$Type;
declare class GetVotePollsByEndDateResponse_GetVotePollsByEndDateResponseV0_SerializedVotePollsByTimestamp$Type extends MessageType<GetVotePollsByEndDateResponse_GetVotePollsByEndDateResponseV0_SerializedVotePollsByTimestamp> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetVotePollsByEndDateResponse.GetVotePollsByEndDateResponseV0.SerializedVotePollsByTimestamp
 */
export declare const GetVotePollsByEndDateResponse_GetVotePollsByEndDateResponseV0_SerializedVotePollsByTimestamp: GetVotePollsByEndDateResponse_GetVotePollsByEndDateResponseV0_SerializedVotePollsByTimestamp$Type;
declare class GetVotePollsByEndDateResponse_GetVotePollsByEndDateResponseV0_SerializedVotePollsByTimestamps$Type extends MessageType<GetVotePollsByEndDateResponse_GetVotePollsByEndDateResponseV0_SerializedVotePollsByTimestamps> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetVotePollsByEndDateResponse.GetVotePollsByEndDateResponseV0.SerializedVotePollsByTimestamps
 */
export declare const GetVotePollsByEndDateResponse_GetVotePollsByEndDateResponseV0_SerializedVotePollsByTimestamps: GetVotePollsByEndDateResponse_GetVotePollsByEndDateResponseV0_SerializedVotePollsByTimestamps$Type;
declare class GetContestedResourceVoteStateRequest$Type extends MessageType<GetContestedResourceVoteStateRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetContestedResourceVoteStateRequest
 */
export declare const GetContestedResourceVoteStateRequest: GetContestedResourceVoteStateRequest$Type;
declare class GetContestedResourceVoteStateRequest_GetContestedResourceVoteStateRequestV0$Type extends MessageType<GetContestedResourceVoteStateRequest_GetContestedResourceVoteStateRequestV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetContestedResourceVoteStateRequest.GetContestedResourceVoteStateRequestV0
 */
export declare const GetContestedResourceVoteStateRequest_GetContestedResourceVoteStateRequestV0: GetContestedResourceVoteStateRequest_GetContestedResourceVoteStateRequestV0$Type;
declare class GetContestedResourceVoteStateRequest_GetContestedResourceVoteStateRequestV0_StartAtIdentifierInfo$Type extends MessageType<GetContestedResourceVoteStateRequest_GetContestedResourceVoteStateRequestV0_StartAtIdentifierInfo> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetContestedResourceVoteStateRequest.GetContestedResourceVoteStateRequestV0.StartAtIdentifierInfo
 */
export declare const GetContestedResourceVoteStateRequest_GetContestedResourceVoteStateRequestV0_StartAtIdentifierInfo: GetContestedResourceVoteStateRequest_GetContestedResourceVoteStateRequestV0_StartAtIdentifierInfo$Type;
declare class GetContestedResourceVoteStateResponse$Type extends MessageType<GetContestedResourceVoteStateResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetContestedResourceVoteStateResponse
 */
export declare const GetContestedResourceVoteStateResponse: GetContestedResourceVoteStateResponse$Type;
declare class GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0$Type extends MessageType<GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetContestedResourceVoteStateResponse.GetContestedResourceVoteStateResponseV0
 */
export declare const GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0: GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0$Type;
declare class GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0_FinishedVoteInfo$Type extends MessageType<GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0_FinishedVoteInfo> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetContestedResourceVoteStateResponse.GetContestedResourceVoteStateResponseV0.FinishedVoteInfo
 */
export declare const GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0_FinishedVoteInfo: GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0_FinishedVoteInfo$Type;
declare class GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0_ContestedResourceContenders$Type extends MessageType<GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0_ContestedResourceContenders> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetContestedResourceVoteStateResponse.GetContestedResourceVoteStateResponseV0.ContestedResourceContenders
 */
export declare const GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0_ContestedResourceContenders: GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0_ContestedResourceContenders$Type;
declare class GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0_Contender$Type extends MessageType<GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0_Contender> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetContestedResourceVoteStateResponse.GetContestedResourceVoteStateResponseV0.Contender
 */
export declare const GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0_Contender: GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0_Contender$Type;
declare class GetContestedResourceVotersForIdentityRequest$Type extends MessageType<GetContestedResourceVotersForIdentityRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetContestedResourceVotersForIdentityRequest
 */
export declare const GetContestedResourceVotersForIdentityRequest: GetContestedResourceVotersForIdentityRequest$Type;
declare class GetContestedResourceVotersForIdentityRequest_GetContestedResourceVotersForIdentityRequestV0$Type extends MessageType<GetContestedResourceVotersForIdentityRequest_GetContestedResourceVotersForIdentityRequestV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetContestedResourceVotersForIdentityRequest.GetContestedResourceVotersForIdentityRequestV0
 */
export declare const GetContestedResourceVotersForIdentityRequest_GetContestedResourceVotersForIdentityRequestV0: GetContestedResourceVotersForIdentityRequest_GetContestedResourceVotersForIdentityRequestV0$Type;
declare class GetContestedResourceVotersForIdentityRequest_GetContestedResourceVotersForIdentityRequestV0_StartAtIdentifierInfo$Type extends MessageType<GetContestedResourceVotersForIdentityRequest_GetContestedResourceVotersForIdentityRequestV0_StartAtIdentifierInfo> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetContestedResourceVotersForIdentityRequest.GetContestedResourceVotersForIdentityRequestV0.StartAtIdentifierInfo
 */
export declare const GetContestedResourceVotersForIdentityRequest_GetContestedResourceVotersForIdentityRequestV0_StartAtIdentifierInfo: GetContestedResourceVotersForIdentityRequest_GetContestedResourceVotersForIdentityRequestV0_StartAtIdentifierInfo$Type;
declare class GetContestedResourceVotersForIdentityResponse$Type extends MessageType<GetContestedResourceVotersForIdentityResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetContestedResourceVotersForIdentityResponse
 */
export declare const GetContestedResourceVotersForIdentityResponse: GetContestedResourceVotersForIdentityResponse$Type;
declare class GetContestedResourceVotersForIdentityResponse_GetContestedResourceVotersForIdentityResponseV0$Type extends MessageType<GetContestedResourceVotersForIdentityResponse_GetContestedResourceVotersForIdentityResponseV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetContestedResourceVotersForIdentityResponse.GetContestedResourceVotersForIdentityResponseV0
 */
export declare const GetContestedResourceVotersForIdentityResponse_GetContestedResourceVotersForIdentityResponseV0: GetContestedResourceVotersForIdentityResponse_GetContestedResourceVotersForIdentityResponseV0$Type;
declare class GetContestedResourceVotersForIdentityResponse_GetContestedResourceVotersForIdentityResponseV0_ContestedResourceVoters$Type extends MessageType<GetContestedResourceVotersForIdentityResponse_GetContestedResourceVotersForIdentityResponseV0_ContestedResourceVoters> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetContestedResourceVotersForIdentityResponse.GetContestedResourceVotersForIdentityResponseV0.ContestedResourceVoters
 */
export declare const GetContestedResourceVotersForIdentityResponse_GetContestedResourceVotersForIdentityResponseV0_ContestedResourceVoters: GetContestedResourceVotersForIdentityResponse_GetContestedResourceVotersForIdentityResponseV0_ContestedResourceVoters$Type;
declare class GetContestedResourceIdentityVotesRequest$Type extends MessageType<GetContestedResourceIdentityVotesRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetContestedResourceIdentityVotesRequest
 */
export declare const GetContestedResourceIdentityVotesRequest: GetContestedResourceIdentityVotesRequest$Type;
declare class GetContestedResourceIdentityVotesRequest_GetContestedResourceIdentityVotesRequestV0$Type extends MessageType<GetContestedResourceIdentityVotesRequest_GetContestedResourceIdentityVotesRequestV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetContestedResourceIdentityVotesRequest.GetContestedResourceIdentityVotesRequestV0
 */
export declare const GetContestedResourceIdentityVotesRequest_GetContestedResourceIdentityVotesRequestV0: GetContestedResourceIdentityVotesRequest_GetContestedResourceIdentityVotesRequestV0$Type;
declare class GetContestedResourceIdentityVotesRequest_GetContestedResourceIdentityVotesRequestV0_StartAtVotePollIdInfo$Type extends MessageType<GetContestedResourceIdentityVotesRequest_GetContestedResourceIdentityVotesRequestV0_StartAtVotePollIdInfo> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetContestedResourceIdentityVotesRequest.GetContestedResourceIdentityVotesRequestV0.StartAtVotePollIdInfo
 */
export declare const GetContestedResourceIdentityVotesRequest_GetContestedResourceIdentityVotesRequestV0_StartAtVotePollIdInfo: GetContestedResourceIdentityVotesRequest_GetContestedResourceIdentityVotesRequestV0_StartAtVotePollIdInfo$Type;
declare class GetContestedResourceIdentityVotesResponse$Type extends MessageType<GetContestedResourceIdentityVotesResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetContestedResourceIdentityVotesResponse
 */
export declare const GetContestedResourceIdentityVotesResponse: GetContestedResourceIdentityVotesResponse$Type;
declare class GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0$Type extends MessageType<GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetContestedResourceIdentityVotesResponse.GetContestedResourceIdentityVotesResponseV0
 */
export declare const GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0: GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0$Type;
declare class GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0_ContestedResourceIdentityVotes$Type extends MessageType<GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0_ContestedResourceIdentityVotes> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetContestedResourceIdentityVotesResponse.GetContestedResourceIdentityVotesResponseV0.ContestedResourceIdentityVotes
 */
export declare const GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0_ContestedResourceIdentityVotes: GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0_ContestedResourceIdentityVotes$Type;
declare class GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0_ResourceVoteChoice$Type extends MessageType<GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0_ResourceVoteChoice> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetContestedResourceIdentityVotesResponse.GetContestedResourceIdentityVotesResponseV0.ResourceVoteChoice
 */
export declare const GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0_ResourceVoteChoice: GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0_ResourceVoteChoice$Type;
declare class GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0_ContestedResourceIdentityVote$Type extends MessageType<GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0_ContestedResourceIdentityVote> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetContestedResourceIdentityVotesResponse.GetContestedResourceIdentityVotesResponseV0.ContestedResourceIdentityVote
 */
export declare const GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0_ContestedResourceIdentityVote: GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0_ContestedResourceIdentityVote$Type;
declare class GetPrefundedSpecializedBalanceRequest$Type extends MessageType<GetPrefundedSpecializedBalanceRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetPrefundedSpecializedBalanceRequest
 */
export declare const GetPrefundedSpecializedBalanceRequest: GetPrefundedSpecializedBalanceRequest$Type;
declare class GetPrefundedSpecializedBalanceRequest_GetPrefundedSpecializedBalanceRequestV0$Type extends MessageType<GetPrefundedSpecializedBalanceRequest_GetPrefundedSpecializedBalanceRequestV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetPrefundedSpecializedBalanceRequest.GetPrefundedSpecializedBalanceRequestV0
 */
export declare const GetPrefundedSpecializedBalanceRequest_GetPrefundedSpecializedBalanceRequestV0: GetPrefundedSpecializedBalanceRequest_GetPrefundedSpecializedBalanceRequestV0$Type;
declare class GetPrefundedSpecializedBalanceResponse$Type extends MessageType<GetPrefundedSpecializedBalanceResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetPrefundedSpecializedBalanceResponse
 */
export declare const GetPrefundedSpecializedBalanceResponse: GetPrefundedSpecializedBalanceResponse$Type;
declare class GetPrefundedSpecializedBalanceResponse_GetPrefundedSpecializedBalanceResponseV0$Type extends MessageType<GetPrefundedSpecializedBalanceResponse_GetPrefundedSpecializedBalanceResponseV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetPrefundedSpecializedBalanceResponse.GetPrefundedSpecializedBalanceResponseV0
 */
export declare const GetPrefundedSpecializedBalanceResponse_GetPrefundedSpecializedBalanceResponseV0: GetPrefundedSpecializedBalanceResponse_GetPrefundedSpecializedBalanceResponseV0$Type;
declare class GetTotalCreditsInPlatformRequest$Type extends MessageType<GetTotalCreditsInPlatformRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetTotalCreditsInPlatformRequest
 */
export declare const GetTotalCreditsInPlatformRequest: GetTotalCreditsInPlatformRequest$Type;
declare class GetTotalCreditsInPlatformRequest_GetTotalCreditsInPlatformRequestV0$Type extends MessageType<GetTotalCreditsInPlatformRequest_GetTotalCreditsInPlatformRequestV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetTotalCreditsInPlatformRequest.GetTotalCreditsInPlatformRequestV0
 */
export declare const GetTotalCreditsInPlatformRequest_GetTotalCreditsInPlatformRequestV0: GetTotalCreditsInPlatformRequest_GetTotalCreditsInPlatformRequestV0$Type;
declare class GetTotalCreditsInPlatformResponse$Type extends MessageType<GetTotalCreditsInPlatformResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetTotalCreditsInPlatformResponse
 */
export declare const GetTotalCreditsInPlatformResponse: GetTotalCreditsInPlatformResponse$Type;
declare class GetTotalCreditsInPlatformResponse_GetTotalCreditsInPlatformResponseV0$Type extends MessageType<GetTotalCreditsInPlatformResponse_GetTotalCreditsInPlatformResponseV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetTotalCreditsInPlatformResponse.GetTotalCreditsInPlatformResponseV0
 */
export declare const GetTotalCreditsInPlatformResponse_GetTotalCreditsInPlatformResponseV0: GetTotalCreditsInPlatformResponse_GetTotalCreditsInPlatformResponseV0$Type;
declare class GetPathElementsRequest$Type extends MessageType<GetPathElementsRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetPathElementsRequest
 */
export declare const GetPathElementsRequest: GetPathElementsRequest$Type;
declare class GetPathElementsRequest_GetPathElementsRequestV0$Type extends MessageType<GetPathElementsRequest_GetPathElementsRequestV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetPathElementsRequest.GetPathElementsRequestV0
 */
export declare const GetPathElementsRequest_GetPathElementsRequestV0: GetPathElementsRequest_GetPathElementsRequestV0$Type;
declare class GetPathElementsResponse$Type extends MessageType<GetPathElementsResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetPathElementsResponse
 */
export declare const GetPathElementsResponse: GetPathElementsResponse$Type;
declare class GetPathElementsResponse_GetPathElementsResponseV0$Type extends MessageType<GetPathElementsResponse_GetPathElementsResponseV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetPathElementsResponse.GetPathElementsResponseV0
 */
export declare const GetPathElementsResponse_GetPathElementsResponseV0: GetPathElementsResponse_GetPathElementsResponseV0$Type;
declare class GetPathElementsResponse_GetPathElementsResponseV0_Elements$Type extends MessageType<GetPathElementsResponse_GetPathElementsResponseV0_Elements> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetPathElementsResponse.GetPathElementsResponseV0.Elements
 */
export declare const GetPathElementsResponse_GetPathElementsResponseV0_Elements: GetPathElementsResponse_GetPathElementsResponseV0_Elements$Type;
declare class GetStatusRequest$Type extends MessageType<GetStatusRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetStatusRequest
 */
export declare const GetStatusRequest: GetStatusRequest$Type;
declare class GetStatusRequest_GetStatusRequestV0$Type extends MessageType<GetStatusRequest_GetStatusRequestV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetStatusRequest.GetStatusRequestV0
 */
export declare const GetStatusRequest_GetStatusRequestV0: GetStatusRequest_GetStatusRequestV0$Type;
declare class GetStatusResponse$Type extends MessageType<GetStatusResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetStatusResponse
 */
export declare const GetStatusResponse: GetStatusResponse$Type;
declare class GetStatusResponse_GetStatusResponseV0$Type extends MessageType<GetStatusResponse_GetStatusResponseV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetStatusResponse.GetStatusResponseV0
 */
export declare const GetStatusResponse_GetStatusResponseV0: GetStatusResponse_GetStatusResponseV0$Type;
declare class GetStatusResponse_GetStatusResponseV0_Version$Type extends MessageType<GetStatusResponse_GetStatusResponseV0_Version> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetStatusResponse.GetStatusResponseV0.Version
 */
export declare const GetStatusResponse_GetStatusResponseV0_Version: GetStatusResponse_GetStatusResponseV0_Version$Type;
declare class GetStatusResponse_GetStatusResponseV0_Version_Software$Type extends MessageType<GetStatusResponse_GetStatusResponseV0_Version_Software> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetStatusResponse.GetStatusResponseV0.Version.Software
 */
export declare const GetStatusResponse_GetStatusResponseV0_Version_Software: GetStatusResponse_GetStatusResponseV0_Version_Software$Type;
declare class GetStatusResponse_GetStatusResponseV0_Version_Protocol$Type extends MessageType<GetStatusResponse_GetStatusResponseV0_Version_Protocol> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetStatusResponse.GetStatusResponseV0.Version.Protocol
 */
export declare const GetStatusResponse_GetStatusResponseV0_Version_Protocol: GetStatusResponse_GetStatusResponseV0_Version_Protocol$Type;
declare class GetStatusResponse_GetStatusResponseV0_Version_Protocol_Tenderdash$Type extends MessageType<GetStatusResponse_GetStatusResponseV0_Version_Protocol_Tenderdash> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetStatusResponse.GetStatusResponseV0.Version.Protocol.Tenderdash
 */
export declare const GetStatusResponse_GetStatusResponseV0_Version_Protocol_Tenderdash: GetStatusResponse_GetStatusResponseV0_Version_Protocol_Tenderdash$Type;
declare class GetStatusResponse_GetStatusResponseV0_Version_Protocol_Drive$Type extends MessageType<GetStatusResponse_GetStatusResponseV0_Version_Protocol_Drive> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetStatusResponse.GetStatusResponseV0.Version.Protocol.Drive
 */
export declare const GetStatusResponse_GetStatusResponseV0_Version_Protocol_Drive: GetStatusResponse_GetStatusResponseV0_Version_Protocol_Drive$Type;
declare class GetStatusResponse_GetStatusResponseV0_Time$Type extends MessageType<GetStatusResponse_GetStatusResponseV0_Time> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetStatusResponse.GetStatusResponseV0.Time
 */
export declare const GetStatusResponse_GetStatusResponseV0_Time: GetStatusResponse_GetStatusResponseV0_Time$Type;
declare class GetStatusResponse_GetStatusResponseV0_Node$Type extends MessageType<GetStatusResponse_GetStatusResponseV0_Node> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetStatusResponse.GetStatusResponseV0.Node
 */
export declare const GetStatusResponse_GetStatusResponseV0_Node: GetStatusResponse_GetStatusResponseV0_Node$Type;
declare class GetStatusResponse_GetStatusResponseV0_Chain$Type extends MessageType<GetStatusResponse_GetStatusResponseV0_Chain> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetStatusResponse.GetStatusResponseV0.Chain
 */
export declare const GetStatusResponse_GetStatusResponseV0_Chain: GetStatusResponse_GetStatusResponseV0_Chain$Type;
declare class GetStatusResponse_GetStatusResponseV0_Network$Type extends MessageType<GetStatusResponse_GetStatusResponseV0_Network> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetStatusResponse.GetStatusResponseV0.Network
 */
export declare const GetStatusResponse_GetStatusResponseV0_Network: GetStatusResponse_GetStatusResponseV0_Network$Type;
declare class GetStatusResponse_GetStatusResponseV0_StateSync$Type extends MessageType<GetStatusResponse_GetStatusResponseV0_StateSync> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetStatusResponse.GetStatusResponseV0.StateSync
 */
export declare const GetStatusResponse_GetStatusResponseV0_StateSync: GetStatusResponse_GetStatusResponseV0_StateSync$Type;
declare class GetCurrentQuorumsInfoRequest$Type extends MessageType<GetCurrentQuorumsInfoRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetCurrentQuorumsInfoRequest
 */
export declare const GetCurrentQuorumsInfoRequest: GetCurrentQuorumsInfoRequest$Type;
declare class GetCurrentQuorumsInfoRequest_GetCurrentQuorumsInfoRequestV0$Type extends MessageType<GetCurrentQuorumsInfoRequest_GetCurrentQuorumsInfoRequestV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetCurrentQuorumsInfoRequest.GetCurrentQuorumsInfoRequestV0
 */
export declare const GetCurrentQuorumsInfoRequest_GetCurrentQuorumsInfoRequestV0: GetCurrentQuorumsInfoRequest_GetCurrentQuorumsInfoRequestV0$Type;
declare class GetCurrentQuorumsInfoResponse$Type extends MessageType<GetCurrentQuorumsInfoResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetCurrentQuorumsInfoResponse
 */
export declare const GetCurrentQuorumsInfoResponse: GetCurrentQuorumsInfoResponse$Type;
declare class GetCurrentQuorumsInfoResponse_ValidatorV0$Type extends MessageType<GetCurrentQuorumsInfoResponse_ValidatorV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetCurrentQuorumsInfoResponse.ValidatorV0
 */
export declare const GetCurrentQuorumsInfoResponse_ValidatorV0: GetCurrentQuorumsInfoResponse_ValidatorV0$Type;
declare class GetCurrentQuorumsInfoResponse_ValidatorSetV0$Type extends MessageType<GetCurrentQuorumsInfoResponse_ValidatorSetV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetCurrentQuorumsInfoResponse.ValidatorSetV0
 */
export declare const GetCurrentQuorumsInfoResponse_ValidatorSetV0: GetCurrentQuorumsInfoResponse_ValidatorSetV0$Type;
declare class GetCurrentQuorumsInfoResponse_GetCurrentQuorumsInfoResponseV0$Type extends MessageType<GetCurrentQuorumsInfoResponse_GetCurrentQuorumsInfoResponseV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetCurrentQuorumsInfoResponse.GetCurrentQuorumsInfoResponseV0
 */
export declare const GetCurrentQuorumsInfoResponse_GetCurrentQuorumsInfoResponseV0: GetCurrentQuorumsInfoResponse_GetCurrentQuorumsInfoResponseV0$Type;
declare class GetIdentityTokenBalancesRequest$Type extends MessageType<GetIdentityTokenBalancesRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentityTokenBalancesRequest
 */
export declare const GetIdentityTokenBalancesRequest: GetIdentityTokenBalancesRequest$Type;
declare class GetIdentityTokenBalancesRequest_GetIdentityTokenBalancesRequestV0$Type extends MessageType<GetIdentityTokenBalancesRequest_GetIdentityTokenBalancesRequestV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentityTokenBalancesRequest.GetIdentityTokenBalancesRequestV0
 */
export declare const GetIdentityTokenBalancesRequest_GetIdentityTokenBalancesRequestV0: GetIdentityTokenBalancesRequest_GetIdentityTokenBalancesRequestV0$Type;
declare class GetIdentityTokenBalancesResponse$Type extends MessageType<GetIdentityTokenBalancesResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentityTokenBalancesResponse
 */
export declare const GetIdentityTokenBalancesResponse: GetIdentityTokenBalancesResponse$Type;
declare class GetIdentityTokenBalancesResponse_GetIdentityTokenBalancesResponseV0$Type extends MessageType<GetIdentityTokenBalancesResponse_GetIdentityTokenBalancesResponseV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentityTokenBalancesResponse.GetIdentityTokenBalancesResponseV0
 */
export declare const GetIdentityTokenBalancesResponse_GetIdentityTokenBalancesResponseV0: GetIdentityTokenBalancesResponse_GetIdentityTokenBalancesResponseV0$Type;
declare class GetIdentityTokenBalancesResponse_GetIdentityTokenBalancesResponseV0_TokenBalanceEntry$Type extends MessageType<GetIdentityTokenBalancesResponse_GetIdentityTokenBalancesResponseV0_TokenBalanceEntry> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentityTokenBalancesResponse.GetIdentityTokenBalancesResponseV0.TokenBalanceEntry
 */
export declare const GetIdentityTokenBalancesResponse_GetIdentityTokenBalancesResponseV0_TokenBalanceEntry: GetIdentityTokenBalancesResponse_GetIdentityTokenBalancesResponseV0_TokenBalanceEntry$Type;
declare class GetIdentityTokenBalancesResponse_GetIdentityTokenBalancesResponseV0_TokenBalances$Type extends MessageType<GetIdentityTokenBalancesResponse_GetIdentityTokenBalancesResponseV0_TokenBalances> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentityTokenBalancesResponse.GetIdentityTokenBalancesResponseV0.TokenBalances
 */
export declare const GetIdentityTokenBalancesResponse_GetIdentityTokenBalancesResponseV0_TokenBalances: GetIdentityTokenBalancesResponse_GetIdentityTokenBalancesResponseV0_TokenBalances$Type;
declare class GetIdentitiesTokenBalancesRequest$Type extends MessageType<GetIdentitiesTokenBalancesRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentitiesTokenBalancesRequest
 */
export declare const GetIdentitiesTokenBalancesRequest: GetIdentitiesTokenBalancesRequest$Type;
declare class GetIdentitiesTokenBalancesRequest_GetIdentitiesTokenBalancesRequestV0$Type extends MessageType<GetIdentitiesTokenBalancesRequest_GetIdentitiesTokenBalancesRequestV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentitiesTokenBalancesRequest.GetIdentitiesTokenBalancesRequestV0
 */
export declare const GetIdentitiesTokenBalancesRequest_GetIdentitiesTokenBalancesRequestV0: GetIdentitiesTokenBalancesRequest_GetIdentitiesTokenBalancesRequestV0$Type;
declare class GetIdentitiesTokenBalancesResponse$Type extends MessageType<GetIdentitiesTokenBalancesResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentitiesTokenBalancesResponse
 */
export declare const GetIdentitiesTokenBalancesResponse: GetIdentitiesTokenBalancesResponse$Type;
declare class GetIdentitiesTokenBalancesResponse_GetIdentitiesTokenBalancesResponseV0$Type extends MessageType<GetIdentitiesTokenBalancesResponse_GetIdentitiesTokenBalancesResponseV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentitiesTokenBalancesResponse.GetIdentitiesTokenBalancesResponseV0
 */
export declare const GetIdentitiesTokenBalancesResponse_GetIdentitiesTokenBalancesResponseV0: GetIdentitiesTokenBalancesResponse_GetIdentitiesTokenBalancesResponseV0$Type;
declare class GetIdentitiesTokenBalancesResponse_GetIdentitiesTokenBalancesResponseV0_IdentityTokenBalanceEntry$Type extends MessageType<GetIdentitiesTokenBalancesResponse_GetIdentitiesTokenBalancesResponseV0_IdentityTokenBalanceEntry> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentitiesTokenBalancesResponse.GetIdentitiesTokenBalancesResponseV0.IdentityTokenBalanceEntry
 */
export declare const GetIdentitiesTokenBalancesResponse_GetIdentitiesTokenBalancesResponseV0_IdentityTokenBalanceEntry: GetIdentitiesTokenBalancesResponse_GetIdentitiesTokenBalancesResponseV0_IdentityTokenBalanceEntry$Type;
declare class GetIdentitiesTokenBalancesResponse_GetIdentitiesTokenBalancesResponseV0_IdentityTokenBalances$Type extends MessageType<GetIdentitiesTokenBalancesResponse_GetIdentitiesTokenBalancesResponseV0_IdentityTokenBalances> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentitiesTokenBalancesResponse.GetIdentitiesTokenBalancesResponseV0.IdentityTokenBalances
 */
export declare const GetIdentitiesTokenBalancesResponse_GetIdentitiesTokenBalancesResponseV0_IdentityTokenBalances: GetIdentitiesTokenBalancesResponse_GetIdentitiesTokenBalancesResponseV0_IdentityTokenBalances$Type;
declare class GetIdentityTokenInfosRequest$Type extends MessageType<GetIdentityTokenInfosRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentityTokenInfosRequest
 */
export declare const GetIdentityTokenInfosRequest: GetIdentityTokenInfosRequest$Type;
declare class GetIdentityTokenInfosRequest_GetIdentityTokenInfosRequestV0$Type extends MessageType<GetIdentityTokenInfosRequest_GetIdentityTokenInfosRequestV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentityTokenInfosRequest.GetIdentityTokenInfosRequestV0
 */
export declare const GetIdentityTokenInfosRequest_GetIdentityTokenInfosRequestV0: GetIdentityTokenInfosRequest_GetIdentityTokenInfosRequestV0$Type;
declare class GetIdentityTokenInfosResponse$Type extends MessageType<GetIdentityTokenInfosResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentityTokenInfosResponse
 */
export declare const GetIdentityTokenInfosResponse: GetIdentityTokenInfosResponse$Type;
declare class GetIdentityTokenInfosResponse_GetIdentityTokenInfosResponseV0$Type extends MessageType<GetIdentityTokenInfosResponse_GetIdentityTokenInfosResponseV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentityTokenInfosResponse.GetIdentityTokenInfosResponseV0
 */
export declare const GetIdentityTokenInfosResponse_GetIdentityTokenInfosResponseV0: GetIdentityTokenInfosResponse_GetIdentityTokenInfosResponseV0$Type;
declare class GetIdentityTokenInfosResponse_GetIdentityTokenInfosResponseV0_TokenIdentityInfoEntry$Type extends MessageType<GetIdentityTokenInfosResponse_GetIdentityTokenInfosResponseV0_TokenIdentityInfoEntry> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentityTokenInfosResponse.GetIdentityTokenInfosResponseV0.TokenIdentityInfoEntry
 */
export declare const GetIdentityTokenInfosResponse_GetIdentityTokenInfosResponseV0_TokenIdentityInfoEntry: GetIdentityTokenInfosResponse_GetIdentityTokenInfosResponseV0_TokenIdentityInfoEntry$Type;
declare class GetIdentityTokenInfosResponse_GetIdentityTokenInfosResponseV0_TokenInfoEntry$Type extends MessageType<GetIdentityTokenInfosResponse_GetIdentityTokenInfosResponseV0_TokenInfoEntry> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentityTokenInfosResponse.GetIdentityTokenInfosResponseV0.TokenInfoEntry
 */
export declare const GetIdentityTokenInfosResponse_GetIdentityTokenInfosResponseV0_TokenInfoEntry: GetIdentityTokenInfosResponse_GetIdentityTokenInfosResponseV0_TokenInfoEntry$Type;
declare class GetIdentityTokenInfosResponse_GetIdentityTokenInfosResponseV0_TokenInfos$Type extends MessageType<GetIdentityTokenInfosResponse_GetIdentityTokenInfosResponseV0_TokenInfos> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentityTokenInfosResponse.GetIdentityTokenInfosResponseV0.TokenInfos
 */
export declare const GetIdentityTokenInfosResponse_GetIdentityTokenInfosResponseV0_TokenInfos: GetIdentityTokenInfosResponse_GetIdentityTokenInfosResponseV0_TokenInfos$Type;
declare class GetIdentitiesTokenInfosRequest$Type extends MessageType<GetIdentitiesTokenInfosRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentitiesTokenInfosRequest
 */
export declare const GetIdentitiesTokenInfosRequest: GetIdentitiesTokenInfosRequest$Type;
declare class GetIdentitiesTokenInfosRequest_GetIdentitiesTokenInfosRequestV0$Type extends MessageType<GetIdentitiesTokenInfosRequest_GetIdentitiesTokenInfosRequestV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentitiesTokenInfosRequest.GetIdentitiesTokenInfosRequestV0
 */
export declare const GetIdentitiesTokenInfosRequest_GetIdentitiesTokenInfosRequestV0: GetIdentitiesTokenInfosRequest_GetIdentitiesTokenInfosRequestV0$Type;
declare class GetIdentitiesTokenInfosResponse$Type extends MessageType<GetIdentitiesTokenInfosResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentitiesTokenInfosResponse
 */
export declare const GetIdentitiesTokenInfosResponse: GetIdentitiesTokenInfosResponse$Type;
declare class GetIdentitiesTokenInfosResponse_GetIdentitiesTokenInfosResponseV0$Type extends MessageType<GetIdentitiesTokenInfosResponse_GetIdentitiesTokenInfosResponseV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentitiesTokenInfosResponse.GetIdentitiesTokenInfosResponseV0
 */
export declare const GetIdentitiesTokenInfosResponse_GetIdentitiesTokenInfosResponseV0: GetIdentitiesTokenInfosResponse_GetIdentitiesTokenInfosResponseV0$Type;
declare class GetIdentitiesTokenInfosResponse_GetIdentitiesTokenInfosResponseV0_TokenIdentityInfoEntry$Type extends MessageType<GetIdentitiesTokenInfosResponse_GetIdentitiesTokenInfosResponseV0_TokenIdentityInfoEntry> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentitiesTokenInfosResponse.GetIdentitiesTokenInfosResponseV0.TokenIdentityInfoEntry
 */
export declare const GetIdentitiesTokenInfosResponse_GetIdentitiesTokenInfosResponseV0_TokenIdentityInfoEntry: GetIdentitiesTokenInfosResponse_GetIdentitiesTokenInfosResponseV0_TokenIdentityInfoEntry$Type;
declare class GetIdentitiesTokenInfosResponse_GetIdentitiesTokenInfosResponseV0_TokenInfoEntry$Type extends MessageType<GetIdentitiesTokenInfosResponse_GetIdentitiesTokenInfosResponseV0_TokenInfoEntry> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentitiesTokenInfosResponse.GetIdentitiesTokenInfosResponseV0.TokenInfoEntry
 */
export declare const GetIdentitiesTokenInfosResponse_GetIdentitiesTokenInfosResponseV0_TokenInfoEntry: GetIdentitiesTokenInfosResponse_GetIdentitiesTokenInfosResponseV0_TokenInfoEntry$Type;
declare class GetIdentitiesTokenInfosResponse_GetIdentitiesTokenInfosResponseV0_IdentityTokenInfos$Type extends MessageType<GetIdentitiesTokenInfosResponse_GetIdentitiesTokenInfosResponseV0_IdentityTokenInfos> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetIdentitiesTokenInfosResponse.GetIdentitiesTokenInfosResponseV0.IdentityTokenInfos
 */
export declare const GetIdentitiesTokenInfosResponse_GetIdentitiesTokenInfosResponseV0_IdentityTokenInfos: GetIdentitiesTokenInfosResponse_GetIdentitiesTokenInfosResponseV0_IdentityTokenInfos$Type;
declare class GetTokenStatusesRequest$Type extends MessageType<GetTokenStatusesRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetTokenStatusesRequest
 */
export declare const GetTokenStatusesRequest: GetTokenStatusesRequest$Type;
declare class GetTokenStatusesRequest_GetTokenStatusesRequestV0$Type extends MessageType<GetTokenStatusesRequest_GetTokenStatusesRequestV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetTokenStatusesRequest.GetTokenStatusesRequestV0
 */
export declare const GetTokenStatusesRequest_GetTokenStatusesRequestV0: GetTokenStatusesRequest_GetTokenStatusesRequestV0$Type;
declare class GetTokenStatusesResponse$Type extends MessageType<GetTokenStatusesResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetTokenStatusesResponse
 */
export declare const GetTokenStatusesResponse: GetTokenStatusesResponse$Type;
declare class GetTokenStatusesResponse_GetTokenStatusesResponseV0$Type extends MessageType<GetTokenStatusesResponse_GetTokenStatusesResponseV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetTokenStatusesResponse.GetTokenStatusesResponseV0
 */
export declare const GetTokenStatusesResponse_GetTokenStatusesResponseV0: GetTokenStatusesResponse_GetTokenStatusesResponseV0$Type;
declare class GetTokenStatusesResponse_GetTokenStatusesResponseV0_TokenStatusEntry$Type extends MessageType<GetTokenStatusesResponse_GetTokenStatusesResponseV0_TokenStatusEntry> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetTokenStatusesResponse.GetTokenStatusesResponseV0.TokenStatusEntry
 */
export declare const GetTokenStatusesResponse_GetTokenStatusesResponseV0_TokenStatusEntry: GetTokenStatusesResponse_GetTokenStatusesResponseV0_TokenStatusEntry$Type;
declare class GetTokenStatusesResponse_GetTokenStatusesResponseV0_TokenStatuses$Type extends MessageType<GetTokenStatusesResponse_GetTokenStatusesResponseV0_TokenStatuses> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetTokenStatusesResponse.GetTokenStatusesResponseV0.TokenStatuses
 */
export declare const GetTokenStatusesResponse_GetTokenStatusesResponseV0_TokenStatuses: GetTokenStatusesResponse_GetTokenStatusesResponseV0_TokenStatuses$Type;
declare class GetTokenPreProgrammedDistributionsRequest$Type extends MessageType<GetTokenPreProgrammedDistributionsRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetTokenPreProgrammedDistributionsRequest
 */
export declare const GetTokenPreProgrammedDistributionsRequest: GetTokenPreProgrammedDistributionsRequest$Type;
declare class GetTokenPreProgrammedDistributionsRequest_GetTokenPreProgrammedDistributionsRequestV0$Type extends MessageType<GetTokenPreProgrammedDistributionsRequest_GetTokenPreProgrammedDistributionsRequestV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetTokenPreProgrammedDistributionsRequest.GetTokenPreProgrammedDistributionsRequestV0
 */
export declare const GetTokenPreProgrammedDistributionsRequest_GetTokenPreProgrammedDistributionsRequestV0: GetTokenPreProgrammedDistributionsRequest_GetTokenPreProgrammedDistributionsRequestV0$Type;
declare class GetTokenPreProgrammedDistributionsRequest_GetTokenPreProgrammedDistributionsRequestV0_StartAtInfo$Type extends MessageType<GetTokenPreProgrammedDistributionsRequest_GetTokenPreProgrammedDistributionsRequestV0_StartAtInfo> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetTokenPreProgrammedDistributionsRequest.GetTokenPreProgrammedDistributionsRequestV0.StartAtInfo
 */
export declare const GetTokenPreProgrammedDistributionsRequest_GetTokenPreProgrammedDistributionsRequestV0_StartAtInfo: GetTokenPreProgrammedDistributionsRequest_GetTokenPreProgrammedDistributionsRequestV0_StartAtInfo$Type;
declare class GetTokenPreProgrammedDistributionsResponse$Type extends MessageType<GetTokenPreProgrammedDistributionsResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetTokenPreProgrammedDistributionsResponse
 */
export declare const GetTokenPreProgrammedDistributionsResponse: GetTokenPreProgrammedDistributionsResponse$Type;
declare class GetTokenPreProgrammedDistributionsResponse_GetTokenPreProgrammedDistributionsResponseV0$Type extends MessageType<GetTokenPreProgrammedDistributionsResponse_GetTokenPreProgrammedDistributionsResponseV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetTokenPreProgrammedDistributionsResponse.GetTokenPreProgrammedDistributionsResponseV0
 */
export declare const GetTokenPreProgrammedDistributionsResponse_GetTokenPreProgrammedDistributionsResponseV0: GetTokenPreProgrammedDistributionsResponse_GetTokenPreProgrammedDistributionsResponseV0$Type;
declare class GetTokenPreProgrammedDistributionsResponse_GetTokenPreProgrammedDistributionsResponseV0_TokenDistributionEntry$Type extends MessageType<GetTokenPreProgrammedDistributionsResponse_GetTokenPreProgrammedDistributionsResponseV0_TokenDistributionEntry> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetTokenPreProgrammedDistributionsResponse.GetTokenPreProgrammedDistributionsResponseV0.TokenDistributionEntry
 */
export declare const GetTokenPreProgrammedDistributionsResponse_GetTokenPreProgrammedDistributionsResponseV0_TokenDistributionEntry: GetTokenPreProgrammedDistributionsResponse_GetTokenPreProgrammedDistributionsResponseV0_TokenDistributionEntry$Type;
declare class GetTokenPreProgrammedDistributionsResponse_GetTokenPreProgrammedDistributionsResponseV0_TokenTimedDistributionEntry$Type extends MessageType<GetTokenPreProgrammedDistributionsResponse_GetTokenPreProgrammedDistributionsResponseV0_TokenTimedDistributionEntry> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetTokenPreProgrammedDistributionsResponse.GetTokenPreProgrammedDistributionsResponseV0.TokenTimedDistributionEntry
 */
export declare const GetTokenPreProgrammedDistributionsResponse_GetTokenPreProgrammedDistributionsResponseV0_TokenTimedDistributionEntry: GetTokenPreProgrammedDistributionsResponse_GetTokenPreProgrammedDistributionsResponseV0_TokenTimedDistributionEntry$Type;
declare class GetTokenPreProgrammedDistributionsResponse_GetTokenPreProgrammedDistributionsResponseV0_TokenDistributions$Type extends MessageType<GetTokenPreProgrammedDistributionsResponse_GetTokenPreProgrammedDistributionsResponseV0_TokenDistributions> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetTokenPreProgrammedDistributionsResponse.GetTokenPreProgrammedDistributionsResponseV0.TokenDistributions
 */
export declare const GetTokenPreProgrammedDistributionsResponse_GetTokenPreProgrammedDistributionsResponseV0_TokenDistributions: GetTokenPreProgrammedDistributionsResponse_GetTokenPreProgrammedDistributionsResponseV0_TokenDistributions$Type;
declare class GetTokenTotalSupplyRequest$Type extends MessageType<GetTokenTotalSupplyRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetTokenTotalSupplyRequest
 */
export declare const GetTokenTotalSupplyRequest: GetTokenTotalSupplyRequest$Type;
declare class GetTokenTotalSupplyRequest_GetTokenTotalSupplyRequestV0$Type extends MessageType<GetTokenTotalSupplyRequest_GetTokenTotalSupplyRequestV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetTokenTotalSupplyRequest.GetTokenTotalSupplyRequestV0
 */
export declare const GetTokenTotalSupplyRequest_GetTokenTotalSupplyRequestV0: GetTokenTotalSupplyRequest_GetTokenTotalSupplyRequestV0$Type;
declare class GetTokenTotalSupplyResponse$Type extends MessageType<GetTokenTotalSupplyResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetTokenTotalSupplyResponse
 */
export declare const GetTokenTotalSupplyResponse: GetTokenTotalSupplyResponse$Type;
declare class GetTokenTotalSupplyResponse_GetTokenTotalSupplyResponseV0$Type extends MessageType<GetTokenTotalSupplyResponse_GetTokenTotalSupplyResponseV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetTokenTotalSupplyResponse.GetTokenTotalSupplyResponseV0
 */
export declare const GetTokenTotalSupplyResponse_GetTokenTotalSupplyResponseV0: GetTokenTotalSupplyResponse_GetTokenTotalSupplyResponseV0$Type;
declare class GetTokenTotalSupplyResponse_GetTokenTotalSupplyResponseV0_TokenTotalSupplyEntry$Type extends MessageType<GetTokenTotalSupplyResponse_GetTokenTotalSupplyResponseV0_TokenTotalSupplyEntry> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetTokenTotalSupplyResponse.GetTokenTotalSupplyResponseV0.TokenTotalSupplyEntry
 */
export declare const GetTokenTotalSupplyResponse_GetTokenTotalSupplyResponseV0_TokenTotalSupplyEntry: GetTokenTotalSupplyResponse_GetTokenTotalSupplyResponseV0_TokenTotalSupplyEntry$Type;
declare class GetGroupInfoRequest$Type extends MessageType<GetGroupInfoRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetGroupInfoRequest
 */
export declare const GetGroupInfoRequest: GetGroupInfoRequest$Type;
declare class GetGroupInfoRequest_GetGroupInfoRequestV0$Type extends MessageType<GetGroupInfoRequest_GetGroupInfoRequestV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetGroupInfoRequest.GetGroupInfoRequestV0
 */
export declare const GetGroupInfoRequest_GetGroupInfoRequestV0: GetGroupInfoRequest_GetGroupInfoRequestV0$Type;
declare class GetGroupInfoResponse$Type extends MessageType<GetGroupInfoResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetGroupInfoResponse
 */
export declare const GetGroupInfoResponse: GetGroupInfoResponse$Type;
declare class GetGroupInfoResponse_GetGroupInfoResponseV0$Type extends MessageType<GetGroupInfoResponse_GetGroupInfoResponseV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetGroupInfoResponse.GetGroupInfoResponseV0
 */
export declare const GetGroupInfoResponse_GetGroupInfoResponseV0: GetGroupInfoResponse_GetGroupInfoResponseV0$Type;
declare class GetGroupInfoResponse_GetGroupInfoResponseV0_GroupMemberEntry$Type extends MessageType<GetGroupInfoResponse_GetGroupInfoResponseV0_GroupMemberEntry> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetGroupInfoResponse.GetGroupInfoResponseV0.GroupMemberEntry
 */
export declare const GetGroupInfoResponse_GetGroupInfoResponseV0_GroupMemberEntry: GetGroupInfoResponse_GetGroupInfoResponseV0_GroupMemberEntry$Type;
declare class GetGroupInfoResponse_GetGroupInfoResponseV0_GroupInfoEntry$Type extends MessageType<GetGroupInfoResponse_GetGroupInfoResponseV0_GroupInfoEntry> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetGroupInfoResponse.GetGroupInfoResponseV0.GroupInfoEntry
 */
export declare const GetGroupInfoResponse_GetGroupInfoResponseV0_GroupInfoEntry: GetGroupInfoResponse_GetGroupInfoResponseV0_GroupInfoEntry$Type;
declare class GetGroupInfoResponse_GetGroupInfoResponseV0_GroupInfo$Type extends MessageType<GetGroupInfoResponse_GetGroupInfoResponseV0_GroupInfo> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetGroupInfoResponse.GetGroupInfoResponseV0.GroupInfo
 */
export declare const GetGroupInfoResponse_GetGroupInfoResponseV0_GroupInfo: GetGroupInfoResponse_GetGroupInfoResponseV0_GroupInfo$Type;
declare class GetGroupInfosRequest$Type extends MessageType<GetGroupInfosRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetGroupInfosRequest
 */
export declare const GetGroupInfosRequest: GetGroupInfosRequest$Type;
declare class GetGroupInfosRequest_StartAtGroupContractPosition$Type extends MessageType<GetGroupInfosRequest_StartAtGroupContractPosition> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetGroupInfosRequest.StartAtGroupContractPosition
 */
export declare const GetGroupInfosRequest_StartAtGroupContractPosition: GetGroupInfosRequest_StartAtGroupContractPosition$Type;
declare class GetGroupInfosRequest_GetGroupInfosRequestV0$Type extends MessageType<GetGroupInfosRequest_GetGroupInfosRequestV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetGroupInfosRequest.GetGroupInfosRequestV0
 */
export declare const GetGroupInfosRequest_GetGroupInfosRequestV0: GetGroupInfosRequest_GetGroupInfosRequestV0$Type;
declare class GetGroupInfosResponse$Type extends MessageType<GetGroupInfosResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetGroupInfosResponse
 */
export declare const GetGroupInfosResponse: GetGroupInfosResponse$Type;
declare class GetGroupInfosResponse_GetGroupInfosResponseV0$Type extends MessageType<GetGroupInfosResponse_GetGroupInfosResponseV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetGroupInfosResponse.GetGroupInfosResponseV0
 */
export declare const GetGroupInfosResponse_GetGroupInfosResponseV0: GetGroupInfosResponse_GetGroupInfosResponseV0$Type;
declare class GetGroupInfosResponse_GetGroupInfosResponseV0_GroupMemberEntry$Type extends MessageType<GetGroupInfosResponse_GetGroupInfosResponseV0_GroupMemberEntry> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetGroupInfosResponse.GetGroupInfosResponseV0.GroupMemberEntry
 */
export declare const GetGroupInfosResponse_GetGroupInfosResponseV0_GroupMemberEntry: GetGroupInfosResponse_GetGroupInfosResponseV0_GroupMemberEntry$Type;
declare class GetGroupInfosResponse_GetGroupInfosResponseV0_GroupPositionInfoEntry$Type extends MessageType<GetGroupInfosResponse_GetGroupInfosResponseV0_GroupPositionInfoEntry> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetGroupInfosResponse.GetGroupInfosResponseV0.GroupPositionInfoEntry
 */
export declare const GetGroupInfosResponse_GetGroupInfosResponseV0_GroupPositionInfoEntry: GetGroupInfosResponse_GetGroupInfosResponseV0_GroupPositionInfoEntry$Type;
declare class GetGroupInfosResponse_GetGroupInfosResponseV0_GroupInfos$Type extends MessageType<GetGroupInfosResponse_GetGroupInfosResponseV0_GroupInfos> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetGroupInfosResponse.GetGroupInfosResponseV0.GroupInfos
 */
export declare const GetGroupInfosResponse_GetGroupInfosResponseV0_GroupInfos: GetGroupInfosResponse_GetGroupInfosResponseV0_GroupInfos$Type;
declare class GetGroupActionsRequest$Type extends MessageType<GetGroupActionsRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetGroupActionsRequest
 */
export declare const GetGroupActionsRequest: GetGroupActionsRequest$Type;
declare class GetGroupActionsRequest_StartAtActionId$Type extends MessageType<GetGroupActionsRequest_StartAtActionId> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetGroupActionsRequest.StartAtActionId
 */
export declare const GetGroupActionsRequest_StartAtActionId: GetGroupActionsRequest_StartAtActionId$Type;
declare class GetGroupActionsRequest_GetGroupActionsRequestV0$Type extends MessageType<GetGroupActionsRequest_GetGroupActionsRequestV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetGroupActionsRequest.GetGroupActionsRequestV0
 */
export declare const GetGroupActionsRequest_GetGroupActionsRequestV0: GetGroupActionsRequest_GetGroupActionsRequestV0$Type;
declare class GetGroupActionsResponse$Type extends MessageType<GetGroupActionsResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetGroupActionsResponse
 */
export declare const GetGroupActionsResponse: GetGroupActionsResponse$Type;
declare class GetGroupActionsResponse_GetGroupActionsResponseV0$Type extends MessageType<GetGroupActionsResponse_GetGroupActionsResponseV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0
 */
export declare const GetGroupActionsResponse_GetGroupActionsResponseV0: GetGroupActionsResponse_GetGroupActionsResponseV0$Type;
declare class GetGroupActionsResponse_GetGroupActionsResponseV0_MintEvent$Type extends MessageType<GetGroupActionsResponse_GetGroupActionsResponseV0_MintEvent> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.MintEvent
 */
export declare const GetGroupActionsResponse_GetGroupActionsResponseV0_MintEvent: GetGroupActionsResponse_GetGroupActionsResponseV0_MintEvent$Type;
declare class GetGroupActionsResponse_GetGroupActionsResponseV0_BurnEvent$Type extends MessageType<GetGroupActionsResponse_GetGroupActionsResponseV0_BurnEvent> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.BurnEvent
 */
export declare const GetGroupActionsResponse_GetGroupActionsResponseV0_BurnEvent: GetGroupActionsResponse_GetGroupActionsResponseV0_BurnEvent$Type;
declare class GetGroupActionsResponse_GetGroupActionsResponseV0_FreezeEvent$Type extends MessageType<GetGroupActionsResponse_GetGroupActionsResponseV0_FreezeEvent> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.FreezeEvent
 */
export declare const GetGroupActionsResponse_GetGroupActionsResponseV0_FreezeEvent: GetGroupActionsResponse_GetGroupActionsResponseV0_FreezeEvent$Type;
declare class GetGroupActionsResponse_GetGroupActionsResponseV0_UnfreezeEvent$Type extends MessageType<GetGroupActionsResponse_GetGroupActionsResponseV0_UnfreezeEvent> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.UnfreezeEvent
 */
export declare const GetGroupActionsResponse_GetGroupActionsResponseV0_UnfreezeEvent: GetGroupActionsResponse_GetGroupActionsResponseV0_UnfreezeEvent$Type;
declare class GetGroupActionsResponse_GetGroupActionsResponseV0_DestroyFrozenFundsEvent$Type extends MessageType<GetGroupActionsResponse_GetGroupActionsResponseV0_DestroyFrozenFundsEvent> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.DestroyFrozenFundsEvent
 */
export declare const GetGroupActionsResponse_GetGroupActionsResponseV0_DestroyFrozenFundsEvent: GetGroupActionsResponse_GetGroupActionsResponseV0_DestroyFrozenFundsEvent$Type;
declare class GetGroupActionsResponse_GetGroupActionsResponseV0_SharedEncryptedNote$Type extends MessageType<GetGroupActionsResponse_GetGroupActionsResponseV0_SharedEncryptedNote> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.SharedEncryptedNote
 */
export declare const GetGroupActionsResponse_GetGroupActionsResponseV0_SharedEncryptedNote: GetGroupActionsResponse_GetGroupActionsResponseV0_SharedEncryptedNote$Type;
declare class GetGroupActionsResponse_GetGroupActionsResponseV0_PersonalEncryptedNote$Type extends MessageType<GetGroupActionsResponse_GetGroupActionsResponseV0_PersonalEncryptedNote> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.PersonalEncryptedNote
 */
export declare const GetGroupActionsResponse_GetGroupActionsResponseV0_PersonalEncryptedNote: GetGroupActionsResponse_GetGroupActionsResponseV0_PersonalEncryptedNote$Type;
declare class GetGroupActionsResponse_GetGroupActionsResponseV0_EmergencyActionEvent$Type extends MessageType<GetGroupActionsResponse_GetGroupActionsResponseV0_EmergencyActionEvent> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.EmergencyActionEvent
 */
export declare const GetGroupActionsResponse_GetGroupActionsResponseV0_EmergencyActionEvent: GetGroupActionsResponse_GetGroupActionsResponseV0_EmergencyActionEvent$Type;
declare class GetGroupActionsResponse_GetGroupActionsResponseV0_TokenConfigUpdateEvent$Type extends MessageType<GetGroupActionsResponse_GetGroupActionsResponseV0_TokenConfigUpdateEvent> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.TokenConfigUpdateEvent
 */
export declare const GetGroupActionsResponse_GetGroupActionsResponseV0_TokenConfigUpdateEvent: GetGroupActionsResponse_GetGroupActionsResponseV0_TokenConfigUpdateEvent$Type;
declare class GetGroupActionsResponse_GetGroupActionsResponseV0_GroupActionEvent$Type extends MessageType<GetGroupActionsResponse_GetGroupActionsResponseV0_GroupActionEvent> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.GroupActionEvent
 */
export declare const GetGroupActionsResponse_GetGroupActionsResponseV0_GroupActionEvent: GetGroupActionsResponse_GetGroupActionsResponseV0_GroupActionEvent$Type;
declare class GetGroupActionsResponse_GetGroupActionsResponseV0_DocumentEvent$Type extends MessageType<GetGroupActionsResponse_GetGroupActionsResponseV0_DocumentEvent> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.DocumentEvent
 */
export declare const GetGroupActionsResponse_GetGroupActionsResponseV0_DocumentEvent: GetGroupActionsResponse_GetGroupActionsResponseV0_DocumentEvent$Type;
declare class GetGroupActionsResponse_GetGroupActionsResponseV0_DocumentCreateEvent$Type extends MessageType<GetGroupActionsResponse_GetGroupActionsResponseV0_DocumentCreateEvent> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.DocumentCreateEvent
 */
export declare const GetGroupActionsResponse_GetGroupActionsResponseV0_DocumentCreateEvent: GetGroupActionsResponse_GetGroupActionsResponseV0_DocumentCreateEvent$Type;
declare class GetGroupActionsResponse_GetGroupActionsResponseV0_ContractUpdateEvent$Type extends MessageType<GetGroupActionsResponse_GetGroupActionsResponseV0_ContractUpdateEvent> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.ContractUpdateEvent
 */
export declare const GetGroupActionsResponse_GetGroupActionsResponseV0_ContractUpdateEvent: GetGroupActionsResponse_GetGroupActionsResponseV0_ContractUpdateEvent$Type;
declare class GetGroupActionsResponse_GetGroupActionsResponseV0_ContractEvent$Type extends MessageType<GetGroupActionsResponse_GetGroupActionsResponseV0_ContractEvent> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.ContractEvent
 */
export declare const GetGroupActionsResponse_GetGroupActionsResponseV0_ContractEvent: GetGroupActionsResponse_GetGroupActionsResponseV0_ContractEvent$Type;
declare class GetGroupActionsResponse_GetGroupActionsResponseV0_TokenEvent$Type extends MessageType<GetGroupActionsResponse_GetGroupActionsResponseV0_TokenEvent> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.TokenEvent
 */
export declare const GetGroupActionsResponse_GetGroupActionsResponseV0_TokenEvent: GetGroupActionsResponse_GetGroupActionsResponseV0_TokenEvent$Type;
declare class GetGroupActionsResponse_GetGroupActionsResponseV0_GroupActionEntry$Type extends MessageType<GetGroupActionsResponse_GetGroupActionsResponseV0_GroupActionEntry> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.GroupActionEntry
 */
export declare const GetGroupActionsResponse_GetGroupActionsResponseV0_GroupActionEntry: GetGroupActionsResponse_GetGroupActionsResponseV0_GroupActionEntry$Type;
declare class GetGroupActionsResponse_GetGroupActionsResponseV0_GroupActions$Type extends MessageType<GetGroupActionsResponse_GetGroupActionsResponseV0_GroupActions> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetGroupActionsResponse.GetGroupActionsResponseV0.GroupActions
 */
export declare const GetGroupActionsResponse_GetGroupActionsResponseV0_GroupActions: GetGroupActionsResponse_GetGroupActionsResponseV0_GroupActions$Type;
declare class GetGroupActionSignersRequest$Type extends MessageType<GetGroupActionSignersRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetGroupActionSignersRequest
 */
export declare const GetGroupActionSignersRequest: GetGroupActionSignersRequest$Type;
declare class GetGroupActionSignersRequest_GetGroupActionSignersRequestV0$Type extends MessageType<GetGroupActionSignersRequest_GetGroupActionSignersRequestV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetGroupActionSignersRequest.GetGroupActionSignersRequestV0
 */
export declare const GetGroupActionSignersRequest_GetGroupActionSignersRequestV0: GetGroupActionSignersRequest_GetGroupActionSignersRequestV0$Type;
declare class GetGroupActionSignersResponse$Type extends MessageType<GetGroupActionSignersResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetGroupActionSignersResponse
 */
export declare const GetGroupActionSignersResponse: GetGroupActionSignersResponse$Type;
declare class GetGroupActionSignersResponse_GetGroupActionSignersResponseV0$Type extends MessageType<GetGroupActionSignersResponse_GetGroupActionSignersResponseV0> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetGroupActionSignersResponse.GetGroupActionSignersResponseV0
 */
export declare const GetGroupActionSignersResponse_GetGroupActionSignersResponseV0: GetGroupActionSignersResponse_GetGroupActionSignersResponseV0$Type;
declare class GetGroupActionSignersResponse_GetGroupActionSignersResponseV0_GroupActionSigner$Type extends MessageType<GetGroupActionSignersResponse_GetGroupActionSignersResponseV0_GroupActionSigner> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetGroupActionSignersResponse.GetGroupActionSignersResponseV0.GroupActionSigner
 */
export declare const GetGroupActionSignersResponse_GetGroupActionSignersResponseV0_GroupActionSigner: GetGroupActionSignersResponse_GetGroupActionSignersResponseV0_GroupActionSigner$Type;
declare class GetGroupActionSignersResponse_GetGroupActionSignersResponseV0_GroupActionSigners$Type extends MessageType<GetGroupActionSignersResponse_GetGroupActionSignersResponseV0_GroupActionSigners> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetGroupActionSignersResponse.GetGroupActionSignersResponseV0.GroupActionSigners
 */
export declare const GetGroupActionSignersResponse_GetGroupActionSignersResponseV0_GroupActionSigners: GetGroupActionSignersResponse_GetGroupActionSignersResponseV0_GroupActionSigners$Type;
/**
 * @generated ServiceType for protobuf service org.dash.platform.dapi.v0.Platform
 */
export declare const Platform: ServiceType;
export {};
