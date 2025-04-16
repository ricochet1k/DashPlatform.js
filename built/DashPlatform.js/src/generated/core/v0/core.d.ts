import { ServiceType } from "@protobuf-ts/runtime-rpc";
import { MessageType } from "@protobuf-ts/runtime";
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetBlockchainStatusRequest
 */
export interface GetBlockchainStatusRequest {
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetBlockchainStatusResponse
 */
export interface GetBlockchainStatusResponse {
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.GetBlockchainStatusResponse.Version version = 1;
     */
    version?: GetBlockchainStatusResponse_Version;
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.GetBlockchainStatusResponse.Time time = 2;
     */
    time?: GetBlockchainStatusResponse_Time;
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.GetBlockchainStatusResponse.Status status = 3;
     */
    status: GetBlockchainStatusResponse_Status;
    /**
     * @generated from protobuf field: double sync_progress = 4;
     */
    syncProgress: number;
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.GetBlockchainStatusResponse.Chain chain = 5;
     */
    chain?: GetBlockchainStatusResponse_Chain;
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.GetBlockchainStatusResponse.Network network = 7;
     */
    network?: GetBlockchainStatusResponse_Network;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetBlockchainStatusResponse.Version
 */
export interface GetBlockchainStatusResponse_Version {
    /**
     * @generated from protobuf field: uint32 protocol = 1;
     */
    protocol: number;
    /**
     * @generated from protobuf field: uint32 software = 2;
     */
    software: number;
    /**
     * @generated from protobuf field: string agent = 3;
     */
    agent: string;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetBlockchainStatusResponse.Time
 */
export interface GetBlockchainStatusResponse_Time {
    /**
     * @generated from protobuf field: uint32 now = 1;
     */
    now: number;
    /**
     * @generated from protobuf field: int32 offset = 2;
     */
    offset: number;
    /**
     * @generated from protobuf field: uint32 median = 3;
     */
    median: number;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetBlockchainStatusResponse.Chain
 */
export interface GetBlockchainStatusResponse_Chain {
    /**
     * @generated from protobuf field: string name = 1;
     */
    name: string;
    /**
     * @generated from protobuf field: uint32 headers_count = 2;
     */
    headersCount: number;
    /**
     * @generated from protobuf field: uint32 blocks_count = 3;
     */
    blocksCount: number;
    /**
     * @generated from protobuf field: bytes best_block_hash = 4;
     */
    bestBlockHash: Uint8Array;
    /**
     * @generated from protobuf field: double difficulty = 5;
     */
    difficulty: number;
    /**
     * @generated from protobuf field: bytes chain_work = 6;
     */
    chainWork: Uint8Array;
    /**
     * @generated from protobuf field: bool is_synced = 7;
     */
    isSynced: boolean;
    /**
     * @generated from protobuf field: double sync_progress = 8;
     */
    syncProgress: number;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetBlockchainStatusResponse.NetworkFee
 */
export interface GetBlockchainStatusResponse_NetworkFee {
    /**
     * @generated from protobuf field: double relay = 1;
     */
    relay: number;
    /**
     * @generated from protobuf field: double incremental = 2;
     */
    incremental: number;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetBlockchainStatusResponse.Network
 */
export interface GetBlockchainStatusResponse_Network {
    /**
     * @generated from protobuf field: uint32 peers_count = 1;
     */
    peersCount: number;
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.GetBlockchainStatusResponse.NetworkFee fee = 2;
     */
    fee?: GetBlockchainStatusResponse_NetworkFee;
}
/**
 * @generated from protobuf enum org.dash.platform.dapi.v0.GetBlockchainStatusResponse.Status
 */
export declare enum GetBlockchainStatusResponse_Status {
    /**
     * @generated from protobuf enum value: NOT_STARTED = 0;
     */
    NOT_STARTED = 0,
    /**
     * @generated from protobuf enum value: SYNCING = 1;
     */
    SYNCING = 1,
    /**
     * @generated from protobuf enum value: READY = 2;
     */
    READY = 2,
    /**
     * @generated from protobuf enum value: ERROR = 3;
     */
    ERROR = 3
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetMasternodeStatusRequest
 */
export interface GetMasternodeStatusRequest {
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetMasternodeStatusResponse
 */
export interface GetMasternodeStatusResponse {
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.GetMasternodeStatusResponse.Status status = 1;
     */
    status: GetMasternodeStatusResponse_Status;
    /**
     * @generated from protobuf field: bytes pro_tx_hash = 2;
     */
    proTxHash: Uint8Array;
    /**
     * @generated from protobuf field: uint32 pose_penalty = 3;
     */
    posePenalty: number;
    /**
     * @generated from protobuf field: bool is_synced = 4;
     */
    isSynced: boolean;
    /**
     * @generated from protobuf field: double sync_progress = 5;
     */
    syncProgress: number;
}
/**
 * @generated from protobuf enum org.dash.platform.dapi.v0.GetMasternodeStatusResponse.Status
 */
export declare enum GetMasternodeStatusResponse_Status {
    /**
     * @generated from protobuf enum value: UNKNOWN = 0;
     */
    UNKNOWN = 0,
    /**
     * @generated from protobuf enum value: WAITING_FOR_PROTX = 1;
     */
    WAITING_FOR_PROTX = 1,
    /**
     * @generated from protobuf enum value: POSE_BANNED = 2;
     */
    POSE_BANNED = 2,
    /**
     * @generated from protobuf enum value: REMOVED = 3;
     */
    REMOVED = 3,
    /**
     * @generated from protobuf enum value: OPERATOR_KEY_CHANGED = 4;
     */
    OPERATOR_KEY_CHANGED = 4,
    /**
     * @generated from protobuf enum value: PROTX_IP_CHANGED = 5;
     */
    PROTX_IP_CHANGED = 5,
    /**
     * @generated from protobuf enum value: READY = 6;
     */
    READY = 6,
    /**
     * @generated from protobuf enum value: ERROR = 7;
     */
    ERROR = 7
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetBlockRequest
 */
export interface GetBlockRequest {
    /**
     * @generated from protobuf oneof: block
     */
    block: {
        oneofKind: "height";
        /**
         * @generated from protobuf field: uint32 height = 1;
         */
        height: number;
    } | {
        oneofKind: "hash";
        /**
         * @generated from protobuf field: string hash = 2;
         */
        hash: string;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetBlockResponse
 */
export interface GetBlockResponse {
    /**
     * @generated from protobuf field: bytes block = 1;
     */
    block: Uint8Array;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetBestBlockHeightRequest
 */
export interface GetBestBlockHeightRequest {
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetBestBlockHeightResponse
 */
export interface GetBestBlockHeightResponse {
    /**
     * @generated from protobuf field: uint32 height = 1;
     */
    height: number;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.BroadcastTransactionRequest
 */
export interface BroadcastTransactionRequest {
    /**
     * @generated from protobuf field: bytes transaction = 1;
     */
    transaction: Uint8Array;
    /**
     * @generated from protobuf field: bool allow_high_fees = 2;
     */
    allowHighFees: boolean;
    /**
     * @generated from protobuf field: bool bypass_limits = 3;
     */
    bypassLimits: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.BroadcastTransactionResponse
 */
export interface BroadcastTransactionResponse {
    /**
     * @generated from protobuf field: string transaction_id = 1;
     */
    transactionId: string;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetTransactionRequest
 */
export interface GetTransactionRequest {
    /**
     * @generated from protobuf field: string id = 1;
     */
    id: string;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetTransactionResponse
 */
export interface GetTransactionResponse {
    /**
     * @generated from protobuf field: bytes transaction = 1;
     */
    transaction: Uint8Array;
    /**
     * @generated from protobuf field: bytes block_hash = 2;
     */
    blockHash: Uint8Array;
    /**
     * @generated from protobuf field: uint32 height = 3;
     */
    height: number;
    /**
     * @generated from protobuf field: uint32 confirmations = 4;
     */
    confirmations: number;
    /**
     * @generated from protobuf field: bool is_instant_locked = 5;
     */
    isInstantLocked: boolean;
    /**
     * @generated from protobuf field: bool is_chain_locked = 6;
     */
    isChainLocked: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.BlockHeadersWithChainLocksRequest
 */
export interface BlockHeadersWithChainLocksRequest {
    /**
     * @generated from protobuf oneof: from_block
     */
    fromBlock: {
        oneofKind: "fromBlockHash";
        /**
         * @generated from protobuf field: bytes from_block_hash = 1;
         */
        fromBlockHash: Uint8Array;
    } | {
        oneofKind: "fromBlockHeight";
        /**
         * @generated from protobuf field: uint32 from_block_height = 2;
         */
        fromBlockHeight: number;
    } | {
        oneofKind: undefined;
    };
    /**
     * @generated from protobuf field: uint32 count = 3;
     */
    count: number;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.BlockHeadersWithChainLocksResponse
 */
export interface BlockHeadersWithChainLocksResponse {
    /**
     * @generated from protobuf oneof: responses
     */
    responses: {
        oneofKind: "blockHeaders";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.BlockHeaders block_headers = 1;
         */
        blockHeaders: BlockHeaders;
    } | {
        oneofKind: "chainLock";
        /**
         * @generated from protobuf field: bytes chain_lock = 2;
         */
        chainLock: Uint8Array;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.BlockHeaders
 */
export interface BlockHeaders {
    /**
     * @generated from protobuf field: repeated bytes headers = 1;
     */
    headers: Uint8Array[];
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetEstimatedTransactionFeeRequest
 */
export interface GetEstimatedTransactionFeeRequest {
    /**
     * @generated from protobuf field: uint32 blocks = 1;
     */
    blocks: number;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.GetEstimatedTransactionFeeResponse
 */
export interface GetEstimatedTransactionFeeResponse {
    /**
     * @generated from protobuf field: double fee = 1;
     */
    fee: number;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.TransactionsWithProofsRequest
 */
export interface TransactionsWithProofsRequest {
    /**
     * @generated from protobuf field: org.dash.platform.dapi.v0.BloomFilter bloom_filter = 1;
     */
    bloomFilter?: BloomFilter;
    /**
     * @generated from protobuf oneof: from_block
     */
    fromBlock: {
        oneofKind: "fromBlockHash";
        /**
         * @generated from protobuf field: bytes from_block_hash = 2;
         */
        fromBlockHash: Uint8Array;
    } | {
        oneofKind: "fromBlockHeight";
        /**
         * @generated from protobuf field: uint32 from_block_height = 3;
         */
        fromBlockHeight: number;
    } | {
        oneofKind: undefined;
    };
    /**
     * @generated from protobuf field: uint32 count = 4;
     */
    count: number;
    /**
     * @generated from protobuf field: bool send_transaction_hashes = 5;
     */
    sendTransactionHashes: boolean;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.BloomFilter
 */
export interface BloomFilter {
    /**
     * @generated from protobuf field: bytes v_data = 1;
     */
    vData: Uint8Array;
    /**
     * @generated from protobuf field: uint32 n_hash_funcs = 2;
     */
    nHashFuncs: number;
    /**
     * @generated from protobuf field: uint32 n_tweak = 3;
     */
    nTweak: number;
    /**
     * @generated from protobuf field: uint32 n_flags = 4;
     */
    nFlags: number;
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.TransactionsWithProofsResponse
 */
export interface TransactionsWithProofsResponse {
    /**
     * @generated from protobuf oneof: responses
     */
    responses: {
        oneofKind: "rawTransactions";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.RawTransactions raw_transactions = 1;
         */
        rawTransactions: RawTransactions;
    } | {
        oneofKind: "instantSendLockMessages";
        /**
         * @generated from protobuf field: org.dash.platform.dapi.v0.InstantSendLockMessages instant_send_lock_messages = 2;
         */
        instantSendLockMessages: InstantSendLockMessages;
    } | {
        oneofKind: "rawMerkleBlock";
        /**
         * @generated from protobuf field: bytes raw_merkle_block = 3;
         */
        rawMerkleBlock: Uint8Array;
    } | {
        oneofKind: undefined;
    };
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.RawTransactions
 */
export interface RawTransactions {
    /**
     * @generated from protobuf field: repeated bytes transactions = 1;
     */
    transactions: Uint8Array[];
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.InstantSendLockMessages
 */
export interface InstantSendLockMessages {
    /**
     * @generated from protobuf field: repeated bytes messages = 1;
     */
    messages: Uint8Array[];
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.MasternodeListRequest
 */
export interface MasternodeListRequest {
}
/**
 * @generated from protobuf message org.dash.platform.dapi.v0.MasternodeListResponse
 */
export interface MasternodeListResponse {
    /**
     * @generated from protobuf field: bytes masternode_list_diff = 1;
     */
    masternodeListDiff: Uint8Array;
}
declare class GetBlockchainStatusRequest$Type extends MessageType<GetBlockchainStatusRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetBlockchainStatusRequest
 */
export declare const GetBlockchainStatusRequest: GetBlockchainStatusRequest$Type;
declare class GetBlockchainStatusResponse$Type extends MessageType<GetBlockchainStatusResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetBlockchainStatusResponse
 */
export declare const GetBlockchainStatusResponse: GetBlockchainStatusResponse$Type;
declare class GetBlockchainStatusResponse_Version$Type extends MessageType<GetBlockchainStatusResponse_Version> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetBlockchainStatusResponse.Version
 */
export declare const GetBlockchainStatusResponse_Version: GetBlockchainStatusResponse_Version$Type;
declare class GetBlockchainStatusResponse_Time$Type extends MessageType<GetBlockchainStatusResponse_Time> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetBlockchainStatusResponse.Time
 */
export declare const GetBlockchainStatusResponse_Time: GetBlockchainStatusResponse_Time$Type;
declare class GetBlockchainStatusResponse_Chain$Type extends MessageType<GetBlockchainStatusResponse_Chain> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetBlockchainStatusResponse.Chain
 */
export declare const GetBlockchainStatusResponse_Chain: GetBlockchainStatusResponse_Chain$Type;
declare class GetBlockchainStatusResponse_NetworkFee$Type extends MessageType<GetBlockchainStatusResponse_NetworkFee> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetBlockchainStatusResponse.NetworkFee
 */
export declare const GetBlockchainStatusResponse_NetworkFee: GetBlockchainStatusResponse_NetworkFee$Type;
declare class GetBlockchainStatusResponse_Network$Type extends MessageType<GetBlockchainStatusResponse_Network> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetBlockchainStatusResponse.Network
 */
export declare const GetBlockchainStatusResponse_Network: GetBlockchainStatusResponse_Network$Type;
declare class GetMasternodeStatusRequest$Type extends MessageType<GetMasternodeStatusRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetMasternodeStatusRequest
 */
export declare const GetMasternodeStatusRequest: GetMasternodeStatusRequest$Type;
declare class GetMasternodeStatusResponse$Type extends MessageType<GetMasternodeStatusResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetMasternodeStatusResponse
 */
export declare const GetMasternodeStatusResponse: GetMasternodeStatusResponse$Type;
declare class GetBlockRequest$Type extends MessageType<GetBlockRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetBlockRequest
 */
export declare const GetBlockRequest: GetBlockRequest$Type;
declare class GetBlockResponse$Type extends MessageType<GetBlockResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetBlockResponse
 */
export declare const GetBlockResponse: GetBlockResponse$Type;
declare class GetBestBlockHeightRequest$Type extends MessageType<GetBestBlockHeightRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetBestBlockHeightRequest
 */
export declare const GetBestBlockHeightRequest: GetBestBlockHeightRequest$Type;
declare class GetBestBlockHeightResponse$Type extends MessageType<GetBestBlockHeightResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetBestBlockHeightResponse
 */
export declare const GetBestBlockHeightResponse: GetBestBlockHeightResponse$Type;
declare class BroadcastTransactionRequest$Type extends MessageType<BroadcastTransactionRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.BroadcastTransactionRequest
 */
export declare const BroadcastTransactionRequest: BroadcastTransactionRequest$Type;
declare class BroadcastTransactionResponse$Type extends MessageType<BroadcastTransactionResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.BroadcastTransactionResponse
 */
export declare const BroadcastTransactionResponse: BroadcastTransactionResponse$Type;
declare class GetTransactionRequest$Type extends MessageType<GetTransactionRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetTransactionRequest
 */
export declare const GetTransactionRequest: GetTransactionRequest$Type;
declare class GetTransactionResponse$Type extends MessageType<GetTransactionResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetTransactionResponse
 */
export declare const GetTransactionResponse: GetTransactionResponse$Type;
declare class BlockHeadersWithChainLocksRequest$Type extends MessageType<BlockHeadersWithChainLocksRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.BlockHeadersWithChainLocksRequest
 */
export declare const BlockHeadersWithChainLocksRequest: BlockHeadersWithChainLocksRequest$Type;
declare class BlockHeadersWithChainLocksResponse$Type extends MessageType<BlockHeadersWithChainLocksResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.BlockHeadersWithChainLocksResponse
 */
export declare const BlockHeadersWithChainLocksResponse: BlockHeadersWithChainLocksResponse$Type;
declare class BlockHeaders$Type extends MessageType<BlockHeaders> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.BlockHeaders
 */
export declare const BlockHeaders: BlockHeaders$Type;
declare class GetEstimatedTransactionFeeRequest$Type extends MessageType<GetEstimatedTransactionFeeRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetEstimatedTransactionFeeRequest
 */
export declare const GetEstimatedTransactionFeeRequest: GetEstimatedTransactionFeeRequest$Type;
declare class GetEstimatedTransactionFeeResponse$Type extends MessageType<GetEstimatedTransactionFeeResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.GetEstimatedTransactionFeeResponse
 */
export declare const GetEstimatedTransactionFeeResponse: GetEstimatedTransactionFeeResponse$Type;
declare class TransactionsWithProofsRequest$Type extends MessageType<TransactionsWithProofsRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.TransactionsWithProofsRequest
 */
export declare const TransactionsWithProofsRequest: TransactionsWithProofsRequest$Type;
declare class BloomFilter$Type extends MessageType<BloomFilter> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.BloomFilter
 */
export declare const BloomFilter: BloomFilter$Type;
declare class TransactionsWithProofsResponse$Type extends MessageType<TransactionsWithProofsResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.TransactionsWithProofsResponse
 */
export declare const TransactionsWithProofsResponse: TransactionsWithProofsResponse$Type;
declare class RawTransactions$Type extends MessageType<RawTransactions> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.RawTransactions
 */
export declare const RawTransactions: RawTransactions$Type;
declare class InstantSendLockMessages$Type extends MessageType<InstantSendLockMessages> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.InstantSendLockMessages
 */
export declare const InstantSendLockMessages: InstantSendLockMessages$Type;
declare class MasternodeListRequest$Type extends MessageType<MasternodeListRequest> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.MasternodeListRequest
 */
export declare const MasternodeListRequest: MasternodeListRequest$Type;
declare class MasternodeListResponse$Type extends MessageType<MasternodeListResponse> {
    constructor();
}
/**
 * @generated MessageType for protobuf message org.dash.platform.dapi.v0.MasternodeListResponse
 */
export declare const MasternodeListResponse: MasternodeListResponse$Type;
/**
 * @generated ServiceType for protobuf service org.dash.platform.dapi.v0.Core
 */
export declare const Core: ServiceType;
export {};
