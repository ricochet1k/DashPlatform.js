import type { RpcTransport } from "@protobuf-ts/runtime-rpc";
import type { ServiceInfo } from "@protobuf-ts/runtime-rpc";
import type { MasternodeListResponse } from "./core.ts";
import type { MasternodeListRequest } from "./core.ts";
import type { TransactionsWithProofsResponse } from "./core.ts";
import type { TransactionsWithProofsRequest } from "./core.ts";
import type { BlockHeadersWithChainLocksResponse } from "./core.ts";
import type { BlockHeadersWithChainLocksRequest } from "./core.ts";
import type { ServerStreamingCall } from "@protobuf-ts/runtime-rpc";
import type { GetEstimatedTransactionFeeResponse } from "./core.ts";
import type { GetEstimatedTransactionFeeRequest } from "./core.ts";
import type { GetTransactionResponse } from "./core.ts";
import type { GetTransactionRequest } from "./core.ts";
import type { BroadcastTransactionResponse } from "./core.ts";
import type { BroadcastTransactionRequest } from "./core.ts";
import type { GetBestBlockHeightResponse } from "./core.ts";
import type { GetBestBlockHeightRequest } from "./core.ts";
import type { GetBlockResponse } from "./core.ts";
import type { GetBlockRequest } from "./core.ts";
import type { GetMasternodeStatusResponse } from "./core.ts";
import type { GetMasternodeStatusRequest } from "./core.ts";
import type { GetBlockchainStatusResponse } from "./core.ts";
import type { GetBlockchainStatusRequest } from "./core.ts";
import type { UnaryCall } from "@protobuf-ts/runtime-rpc";
import type { RpcOptions } from "@protobuf-ts/runtime-rpc";
/**
 * @generated from protobuf service org.dash.platform.dapi.v0.Core
 */
export interface ICoreClient {
    /**
     * @generated from protobuf rpc: getBlockchainStatus(org.dash.platform.dapi.v0.GetBlockchainStatusRequest) returns (org.dash.platform.dapi.v0.GetBlockchainStatusResponse);
     */
    getBlockchainStatus(input: GetBlockchainStatusRequest, options?: RpcOptions): UnaryCall<GetBlockchainStatusRequest, GetBlockchainStatusResponse>;
    /**
     * @generated from protobuf rpc: getMasternodeStatus(org.dash.platform.dapi.v0.GetMasternodeStatusRequest) returns (org.dash.platform.dapi.v0.GetMasternodeStatusResponse);
     */
    getMasternodeStatus(input: GetMasternodeStatusRequest, options?: RpcOptions): UnaryCall<GetMasternodeStatusRequest, GetMasternodeStatusResponse>;
    /**
     * @generated from protobuf rpc: getBlock(org.dash.platform.dapi.v0.GetBlockRequest) returns (org.dash.platform.dapi.v0.GetBlockResponse);
     */
    getBlock(input: GetBlockRequest, options?: RpcOptions): UnaryCall<GetBlockRequest, GetBlockResponse>;
    /**
     * @generated from protobuf rpc: getBestBlockHeight(org.dash.platform.dapi.v0.GetBestBlockHeightRequest) returns (org.dash.platform.dapi.v0.GetBestBlockHeightResponse);
     */
    getBestBlockHeight(input: GetBestBlockHeightRequest, options?: RpcOptions): UnaryCall<GetBestBlockHeightRequest, GetBestBlockHeightResponse>;
    /**
     * @generated from protobuf rpc: broadcastTransaction(org.dash.platform.dapi.v0.BroadcastTransactionRequest) returns (org.dash.platform.dapi.v0.BroadcastTransactionResponse);
     */
    broadcastTransaction(input: BroadcastTransactionRequest, options?: RpcOptions): UnaryCall<BroadcastTransactionRequest, BroadcastTransactionResponse>;
    /**
     * @generated from protobuf rpc: getTransaction(org.dash.platform.dapi.v0.GetTransactionRequest) returns (org.dash.platform.dapi.v0.GetTransactionResponse);
     */
    getTransaction(input: GetTransactionRequest, options?: RpcOptions): UnaryCall<GetTransactionRequest, GetTransactionResponse>;
    /**
     * @generated from protobuf rpc: getEstimatedTransactionFee(org.dash.platform.dapi.v0.GetEstimatedTransactionFeeRequest) returns (org.dash.platform.dapi.v0.GetEstimatedTransactionFeeResponse);
     */
    getEstimatedTransactionFee(input: GetEstimatedTransactionFeeRequest, options?: RpcOptions): UnaryCall<GetEstimatedTransactionFeeRequest, GetEstimatedTransactionFeeResponse>;
    /**
     * @generated from protobuf rpc: subscribeToBlockHeadersWithChainLocks(org.dash.platform.dapi.v0.BlockHeadersWithChainLocksRequest) returns (stream org.dash.platform.dapi.v0.BlockHeadersWithChainLocksResponse);
     */
    subscribeToBlockHeadersWithChainLocks(input: BlockHeadersWithChainLocksRequest, options?: RpcOptions): ServerStreamingCall<BlockHeadersWithChainLocksRequest, BlockHeadersWithChainLocksResponse>;
    /**
     * @generated from protobuf rpc: subscribeToTransactionsWithProofs(org.dash.platform.dapi.v0.TransactionsWithProofsRequest) returns (stream org.dash.platform.dapi.v0.TransactionsWithProofsResponse);
     */
    subscribeToTransactionsWithProofs(input: TransactionsWithProofsRequest, options?: RpcOptions): ServerStreamingCall<TransactionsWithProofsRequest, TransactionsWithProofsResponse>;
    /**
     * @generated from protobuf rpc: subscribeToMasternodeList(org.dash.platform.dapi.v0.MasternodeListRequest) returns (stream org.dash.platform.dapi.v0.MasternodeListResponse);
     */
    subscribeToMasternodeList(input: MasternodeListRequest, options?: RpcOptions): ServerStreamingCall<MasternodeListRequest, MasternodeListResponse>;
}
/**
 * @generated from protobuf service org.dash.platform.dapi.v0.Core
 */
export declare class CoreClient implements ICoreClient, ServiceInfo {
    private readonly _transport;
    typeName: string;
    methods: import("@protobuf-ts/runtime-rpc").MethodInfo<any, any>[];
    options: {
        [extensionName: string]: import("@protobuf-ts/runtime").JsonValue;
    };
    constructor(_transport: RpcTransport);
    /**
     * @generated from protobuf rpc: getBlockchainStatus(org.dash.platform.dapi.v0.GetBlockchainStatusRequest) returns (org.dash.platform.dapi.v0.GetBlockchainStatusResponse);
     */
    getBlockchainStatus(input: GetBlockchainStatusRequest, options?: RpcOptions): UnaryCall<GetBlockchainStatusRequest, GetBlockchainStatusResponse>;
    /**
     * @generated from protobuf rpc: getMasternodeStatus(org.dash.platform.dapi.v0.GetMasternodeStatusRequest) returns (org.dash.platform.dapi.v0.GetMasternodeStatusResponse);
     */
    getMasternodeStatus(input: GetMasternodeStatusRequest, options?: RpcOptions): UnaryCall<GetMasternodeStatusRequest, GetMasternodeStatusResponse>;
    /**
     * @generated from protobuf rpc: getBlock(org.dash.platform.dapi.v0.GetBlockRequest) returns (org.dash.platform.dapi.v0.GetBlockResponse);
     */
    getBlock(input: GetBlockRequest, options?: RpcOptions): UnaryCall<GetBlockRequest, GetBlockResponse>;
    /**
     * @generated from protobuf rpc: getBestBlockHeight(org.dash.platform.dapi.v0.GetBestBlockHeightRequest) returns (org.dash.platform.dapi.v0.GetBestBlockHeightResponse);
     */
    getBestBlockHeight(input: GetBestBlockHeightRequest, options?: RpcOptions): UnaryCall<GetBestBlockHeightRequest, GetBestBlockHeightResponse>;
    /**
     * @generated from protobuf rpc: broadcastTransaction(org.dash.platform.dapi.v0.BroadcastTransactionRequest) returns (org.dash.platform.dapi.v0.BroadcastTransactionResponse);
     */
    broadcastTransaction(input: BroadcastTransactionRequest, options?: RpcOptions): UnaryCall<BroadcastTransactionRequest, BroadcastTransactionResponse>;
    /**
     * @generated from protobuf rpc: getTransaction(org.dash.platform.dapi.v0.GetTransactionRequest) returns (org.dash.platform.dapi.v0.GetTransactionResponse);
     */
    getTransaction(input: GetTransactionRequest, options?: RpcOptions): UnaryCall<GetTransactionRequest, GetTransactionResponse>;
    /**
     * @generated from protobuf rpc: getEstimatedTransactionFee(org.dash.platform.dapi.v0.GetEstimatedTransactionFeeRequest) returns (org.dash.platform.dapi.v0.GetEstimatedTransactionFeeResponse);
     */
    getEstimatedTransactionFee(input: GetEstimatedTransactionFeeRequest, options?: RpcOptions): UnaryCall<GetEstimatedTransactionFeeRequest, GetEstimatedTransactionFeeResponse>;
    /**
     * @generated from protobuf rpc: subscribeToBlockHeadersWithChainLocks(org.dash.platform.dapi.v0.BlockHeadersWithChainLocksRequest) returns (stream org.dash.platform.dapi.v0.BlockHeadersWithChainLocksResponse);
     */
    subscribeToBlockHeadersWithChainLocks(input: BlockHeadersWithChainLocksRequest, options?: RpcOptions): ServerStreamingCall<BlockHeadersWithChainLocksRequest, BlockHeadersWithChainLocksResponse>;
    /**
     * @generated from protobuf rpc: subscribeToTransactionsWithProofs(org.dash.platform.dapi.v0.TransactionsWithProofsRequest) returns (stream org.dash.platform.dapi.v0.TransactionsWithProofsResponse);
     */
    subscribeToTransactionsWithProofs(input: TransactionsWithProofsRequest, options?: RpcOptions): ServerStreamingCall<TransactionsWithProofsRequest, TransactionsWithProofsResponse>;
    /**
     * @generated from protobuf rpc: subscribeToMasternodeList(org.dash.platform.dapi.v0.MasternodeListRequest) returns (stream org.dash.platform.dapi.v0.MasternodeListResponse);
     */
    subscribeToMasternodeList(input: MasternodeListRequest, options?: RpcOptions): ServerStreamingCall<MasternodeListRequest, MasternodeListResponse>;
}
