// Original file: ../../platform/packages/dapi-grpc/protos/core/v0/core.proto

import type * as grpc from '@grpc/grpc-js'
import type { MethodDefinition } from '@grpc/proto-loader'
import type { BlockHeadersWithChainLocksRequest as _org_dash_platform_dapi_v0_BlockHeadersWithChainLocksRequest, BlockHeadersWithChainLocksRequest__Output as _org_dash_platform_dapi_v0_BlockHeadersWithChainLocksRequest__Output } from '../../../../../org/dash/platform/dapi/v0/BlockHeadersWithChainLocksRequest';
import type { BlockHeadersWithChainLocksResponse as _org_dash_platform_dapi_v0_BlockHeadersWithChainLocksResponse, BlockHeadersWithChainLocksResponse__Output as _org_dash_platform_dapi_v0_BlockHeadersWithChainLocksResponse__Output } from '../../../../../org/dash/platform/dapi/v0/BlockHeadersWithChainLocksResponse';
import type { BroadcastTransactionRequest as _org_dash_platform_dapi_v0_BroadcastTransactionRequest, BroadcastTransactionRequest__Output as _org_dash_platform_dapi_v0_BroadcastTransactionRequest__Output } from '../../../../../org/dash/platform/dapi/v0/BroadcastTransactionRequest';
import type { BroadcastTransactionResponse as _org_dash_platform_dapi_v0_BroadcastTransactionResponse, BroadcastTransactionResponse__Output as _org_dash_platform_dapi_v0_BroadcastTransactionResponse__Output } from '../../../../../org/dash/platform/dapi/v0/BroadcastTransactionResponse';
import type { GetBestBlockHeightRequest as _org_dash_platform_dapi_v0_GetBestBlockHeightRequest, GetBestBlockHeightRequest__Output as _org_dash_platform_dapi_v0_GetBestBlockHeightRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetBestBlockHeightRequest';
import type { GetBestBlockHeightResponse as _org_dash_platform_dapi_v0_GetBestBlockHeightResponse, GetBestBlockHeightResponse__Output as _org_dash_platform_dapi_v0_GetBestBlockHeightResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetBestBlockHeightResponse';
import type { GetBlockRequest as _org_dash_platform_dapi_v0_GetBlockRequest, GetBlockRequest__Output as _org_dash_platform_dapi_v0_GetBlockRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetBlockRequest';
import type { GetBlockResponse as _org_dash_platform_dapi_v0_GetBlockResponse, GetBlockResponse__Output as _org_dash_platform_dapi_v0_GetBlockResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetBlockResponse';
import type { GetBlockchainStatusRequest as _org_dash_platform_dapi_v0_GetBlockchainStatusRequest, GetBlockchainStatusRequest__Output as _org_dash_platform_dapi_v0_GetBlockchainStatusRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetBlockchainStatusRequest';
import type { GetBlockchainStatusResponse as _org_dash_platform_dapi_v0_GetBlockchainStatusResponse, GetBlockchainStatusResponse__Output as _org_dash_platform_dapi_v0_GetBlockchainStatusResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetBlockchainStatusResponse';
import type { GetEstimatedTransactionFeeRequest as _org_dash_platform_dapi_v0_GetEstimatedTransactionFeeRequest, GetEstimatedTransactionFeeRequest__Output as _org_dash_platform_dapi_v0_GetEstimatedTransactionFeeRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetEstimatedTransactionFeeRequest';
import type { GetEstimatedTransactionFeeResponse as _org_dash_platform_dapi_v0_GetEstimatedTransactionFeeResponse, GetEstimatedTransactionFeeResponse__Output as _org_dash_platform_dapi_v0_GetEstimatedTransactionFeeResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetEstimatedTransactionFeeResponse';
import type { GetMasternodeStatusRequest as _org_dash_platform_dapi_v0_GetMasternodeStatusRequest, GetMasternodeStatusRequest__Output as _org_dash_platform_dapi_v0_GetMasternodeStatusRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetMasternodeStatusRequest';
import type { GetMasternodeStatusResponse as _org_dash_platform_dapi_v0_GetMasternodeStatusResponse, GetMasternodeStatusResponse__Output as _org_dash_platform_dapi_v0_GetMasternodeStatusResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetMasternodeStatusResponse';
import type { GetTransactionRequest as _org_dash_platform_dapi_v0_GetTransactionRequest, GetTransactionRequest__Output as _org_dash_platform_dapi_v0_GetTransactionRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetTransactionRequest';
import type { GetTransactionResponse as _org_dash_platform_dapi_v0_GetTransactionResponse, GetTransactionResponse__Output as _org_dash_platform_dapi_v0_GetTransactionResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetTransactionResponse';
import type { MasternodeListRequest as _org_dash_platform_dapi_v0_MasternodeListRequest, MasternodeListRequest__Output as _org_dash_platform_dapi_v0_MasternodeListRequest__Output } from '../../../../../org/dash/platform/dapi/v0/MasternodeListRequest';
import type { MasternodeListResponse as _org_dash_platform_dapi_v0_MasternodeListResponse, MasternodeListResponse__Output as _org_dash_platform_dapi_v0_MasternodeListResponse__Output } from '../../../../../org/dash/platform/dapi/v0/MasternodeListResponse';
import type { TransactionsWithProofsRequest as _org_dash_platform_dapi_v0_TransactionsWithProofsRequest, TransactionsWithProofsRequest__Output as _org_dash_platform_dapi_v0_TransactionsWithProofsRequest__Output } from '../../../../../org/dash/platform/dapi/v0/TransactionsWithProofsRequest';
import type { TransactionsWithProofsResponse as _org_dash_platform_dapi_v0_TransactionsWithProofsResponse, TransactionsWithProofsResponse__Output as _org_dash_platform_dapi_v0_TransactionsWithProofsResponse__Output } from '../../../../../org/dash/platform/dapi/v0/TransactionsWithProofsResponse';

export interface CoreClient extends grpc.Client {
  broadcastTransaction(argument: _org_dash_platform_dapi_v0_BroadcastTransactionRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_BroadcastTransactionResponse__Output>): grpc.ClientUnaryCall;
  broadcastTransaction(argument: _org_dash_platform_dapi_v0_BroadcastTransactionRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_BroadcastTransactionResponse__Output>): grpc.ClientUnaryCall;
  broadcastTransaction(argument: _org_dash_platform_dapi_v0_BroadcastTransactionRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_BroadcastTransactionResponse__Output>): grpc.ClientUnaryCall;
  broadcastTransaction(argument: _org_dash_platform_dapi_v0_BroadcastTransactionRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_BroadcastTransactionResponse__Output>): grpc.ClientUnaryCall;
  
  getBestBlockHeight(argument: _org_dash_platform_dapi_v0_GetBestBlockHeightRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetBestBlockHeightResponse__Output>): grpc.ClientUnaryCall;
  getBestBlockHeight(argument: _org_dash_platform_dapi_v0_GetBestBlockHeightRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetBestBlockHeightResponse__Output>): grpc.ClientUnaryCall;
  getBestBlockHeight(argument: _org_dash_platform_dapi_v0_GetBestBlockHeightRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetBestBlockHeightResponse__Output>): grpc.ClientUnaryCall;
  getBestBlockHeight(argument: _org_dash_platform_dapi_v0_GetBestBlockHeightRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetBestBlockHeightResponse__Output>): grpc.ClientUnaryCall;
  
  getBlock(argument: _org_dash_platform_dapi_v0_GetBlockRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetBlockResponse__Output>): grpc.ClientUnaryCall;
  getBlock(argument: _org_dash_platform_dapi_v0_GetBlockRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetBlockResponse__Output>): grpc.ClientUnaryCall;
  getBlock(argument: _org_dash_platform_dapi_v0_GetBlockRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetBlockResponse__Output>): grpc.ClientUnaryCall;
  getBlock(argument: _org_dash_platform_dapi_v0_GetBlockRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetBlockResponse__Output>): grpc.ClientUnaryCall;
  
  getBlockchainStatus(argument: _org_dash_platform_dapi_v0_GetBlockchainStatusRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetBlockchainStatusResponse__Output>): grpc.ClientUnaryCall;
  getBlockchainStatus(argument: _org_dash_platform_dapi_v0_GetBlockchainStatusRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetBlockchainStatusResponse__Output>): grpc.ClientUnaryCall;
  getBlockchainStatus(argument: _org_dash_platform_dapi_v0_GetBlockchainStatusRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetBlockchainStatusResponse__Output>): grpc.ClientUnaryCall;
  getBlockchainStatus(argument: _org_dash_platform_dapi_v0_GetBlockchainStatusRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetBlockchainStatusResponse__Output>): grpc.ClientUnaryCall;
  
  getEstimatedTransactionFee(argument: _org_dash_platform_dapi_v0_GetEstimatedTransactionFeeRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetEstimatedTransactionFeeResponse__Output>): grpc.ClientUnaryCall;
  getEstimatedTransactionFee(argument: _org_dash_platform_dapi_v0_GetEstimatedTransactionFeeRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetEstimatedTransactionFeeResponse__Output>): grpc.ClientUnaryCall;
  getEstimatedTransactionFee(argument: _org_dash_platform_dapi_v0_GetEstimatedTransactionFeeRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetEstimatedTransactionFeeResponse__Output>): grpc.ClientUnaryCall;
  getEstimatedTransactionFee(argument: _org_dash_platform_dapi_v0_GetEstimatedTransactionFeeRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetEstimatedTransactionFeeResponse__Output>): grpc.ClientUnaryCall;
  
  getMasternodeStatus(argument: _org_dash_platform_dapi_v0_GetMasternodeStatusRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetMasternodeStatusResponse__Output>): grpc.ClientUnaryCall;
  getMasternodeStatus(argument: _org_dash_platform_dapi_v0_GetMasternodeStatusRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetMasternodeStatusResponse__Output>): grpc.ClientUnaryCall;
  getMasternodeStatus(argument: _org_dash_platform_dapi_v0_GetMasternodeStatusRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetMasternodeStatusResponse__Output>): grpc.ClientUnaryCall;
  getMasternodeStatus(argument: _org_dash_platform_dapi_v0_GetMasternodeStatusRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetMasternodeStatusResponse__Output>): grpc.ClientUnaryCall;
  
  getTransaction(argument: _org_dash_platform_dapi_v0_GetTransactionRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetTransactionResponse__Output>): grpc.ClientUnaryCall;
  getTransaction(argument: _org_dash_platform_dapi_v0_GetTransactionRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetTransactionResponse__Output>): grpc.ClientUnaryCall;
  getTransaction(argument: _org_dash_platform_dapi_v0_GetTransactionRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetTransactionResponse__Output>): grpc.ClientUnaryCall;
  getTransaction(argument: _org_dash_platform_dapi_v0_GetTransactionRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetTransactionResponse__Output>): grpc.ClientUnaryCall;
  
  subscribeToBlockHeadersWithChainLocks(argument: _org_dash_platform_dapi_v0_BlockHeadersWithChainLocksRequest, metadata: grpc.Metadata, options?: grpc.CallOptions): grpc.ClientReadableStream<_org_dash_platform_dapi_v0_BlockHeadersWithChainLocksResponse__Output>;
  subscribeToBlockHeadersWithChainLocks(argument: _org_dash_platform_dapi_v0_BlockHeadersWithChainLocksRequest, options?: grpc.CallOptions): grpc.ClientReadableStream<_org_dash_platform_dapi_v0_BlockHeadersWithChainLocksResponse__Output>;
  
  subscribeToMasternodeList(argument: _org_dash_platform_dapi_v0_MasternodeListRequest, metadata: grpc.Metadata, options?: grpc.CallOptions): grpc.ClientReadableStream<_org_dash_platform_dapi_v0_MasternodeListResponse__Output>;
  subscribeToMasternodeList(argument: _org_dash_platform_dapi_v0_MasternodeListRequest, options?: grpc.CallOptions): grpc.ClientReadableStream<_org_dash_platform_dapi_v0_MasternodeListResponse__Output>;
  
  subscribeToTransactionsWithProofs(argument: _org_dash_platform_dapi_v0_TransactionsWithProofsRequest, metadata: grpc.Metadata, options?: grpc.CallOptions): grpc.ClientReadableStream<_org_dash_platform_dapi_v0_TransactionsWithProofsResponse__Output>;
  subscribeToTransactionsWithProofs(argument: _org_dash_platform_dapi_v0_TransactionsWithProofsRequest, options?: grpc.CallOptions): grpc.ClientReadableStream<_org_dash_platform_dapi_v0_TransactionsWithProofsResponse__Output>;
  
}

export interface CoreHandlers extends grpc.UntypedServiceImplementation {
  broadcastTransaction: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_BroadcastTransactionRequest__Output, _org_dash_platform_dapi_v0_BroadcastTransactionResponse>;
  
  getBestBlockHeight: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetBestBlockHeightRequest__Output, _org_dash_platform_dapi_v0_GetBestBlockHeightResponse>;
  
  getBlock: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetBlockRequest__Output, _org_dash_platform_dapi_v0_GetBlockResponse>;
  
  getBlockchainStatus: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetBlockchainStatusRequest__Output, _org_dash_platform_dapi_v0_GetBlockchainStatusResponse>;
  
  getEstimatedTransactionFee: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetEstimatedTransactionFeeRequest__Output, _org_dash_platform_dapi_v0_GetEstimatedTransactionFeeResponse>;
  
  getMasternodeStatus: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetMasternodeStatusRequest__Output, _org_dash_platform_dapi_v0_GetMasternodeStatusResponse>;
  
  getTransaction: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetTransactionRequest__Output, _org_dash_platform_dapi_v0_GetTransactionResponse>;
  
  subscribeToBlockHeadersWithChainLocks: grpc.handleServerStreamingCall<_org_dash_platform_dapi_v0_BlockHeadersWithChainLocksRequest__Output, _org_dash_platform_dapi_v0_BlockHeadersWithChainLocksResponse>;
  
  subscribeToMasternodeList: grpc.handleServerStreamingCall<_org_dash_platform_dapi_v0_MasternodeListRequest__Output, _org_dash_platform_dapi_v0_MasternodeListResponse>;
  
  subscribeToTransactionsWithProofs: grpc.handleServerStreamingCall<_org_dash_platform_dapi_v0_TransactionsWithProofsRequest__Output, _org_dash_platform_dapi_v0_TransactionsWithProofsResponse>;
  
}

export interface CoreDefinition extends grpc.ServiceDefinition {
  broadcastTransaction: MethodDefinition<_org_dash_platform_dapi_v0_BroadcastTransactionRequest, _org_dash_platform_dapi_v0_BroadcastTransactionResponse, _org_dash_platform_dapi_v0_BroadcastTransactionRequest__Output, _org_dash_platform_dapi_v0_BroadcastTransactionResponse__Output>
  getBestBlockHeight: MethodDefinition<_org_dash_platform_dapi_v0_GetBestBlockHeightRequest, _org_dash_platform_dapi_v0_GetBestBlockHeightResponse, _org_dash_platform_dapi_v0_GetBestBlockHeightRequest__Output, _org_dash_platform_dapi_v0_GetBestBlockHeightResponse__Output>
  getBlock: MethodDefinition<_org_dash_platform_dapi_v0_GetBlockRequest, _org_dash_platform_dapi_v0_GetBlockResponse, _org_dash_platform_dapi_v0_GetBlockRequest__Output, _org_dash_platform_dapi_v0_GetBlockResponse__Output>
  getBlockchainStatus: MethodDefinition<_org_dash_platform_dapi_v0_GetBlockchainStatusRequest, _org_dash_platform_dapi_v0_GetBlockchainStatusResponse, _org_dash_platform_dapi_v0_GetBlockchainStatusRequest__Output, _org_dash_platform_dapi_v0_GetBlockchainStatusResponse__Output>
  getEstimatedTransactionFee: MethodDefinition<_org_dash_platform_dapi_v0_GetEstimatedTransactionFeeRequest, _org_dash_platform_dapi_v0_GetEstimatedTransactionFeeResponse, _org_dash_platform_dapi_v0_GetEstimatedTransactionFeeRequest__Output, _org_dash_platform_dapi_v0_GetEstimatedTransactionFeeResponse__Output>
  getMasternodeStatus: MethodDefinition<_org_dash_platform_dapi_v0_GetMasternodeStatusRequest, _org_dash_platform_dapi_v0_GetMasternodeStatusResponse, _org_dash_platform_dapi_v0_GetMasternodeStatusRequest__Output, _org_dash_platform_dapi_v0_GetMasternodeStatusResponse__Output>
  getTransaction: MethodDefinition<_org_dash_platform_dapi_v0_GetTransactionRequest, _org_dash_platform_dapi_v0_GetTransactionResponse, _org_dash_platform_dapi_v0_GetTransactionRequest__Output, _org_dash_platform_dapi_v0_GetTransactionResponse__Output>
  subscribeToBlockHeadersWithChainLocks: MethodDefinition<_org_dash_platform_dapi_v0_BlockHeadersWithChainLocksRequest, _org_dash_platform_dapi_v0_BlockHeadersWithChainLocksResponse, _org_dash_platform_dapi_v0_BlockHeadersWithChainLocksRequest__Output, _org_dash_platform_dapi_v0_BlockHeadersWithChainLocksResponse__Output>
  subscribeToMasternodeList: MethodDefinition<_org_dash_platform_dapi_v0_MasternodeListRequest, _org_dash_platform_dapi_v0_MasternodeListResponse, _org_dash_platform_dapi_v0_MasternodeListRequest__Output, _org_dash_platform_dapi_v0_MasternodeListResponse__Output>
  subscribeToTransactionsWithProofs: MethodDefinition<_org_dash_platform_dapi_v0_TransactionsWithProofsRequest, _org_dash_platform_dapi_v0_TransactionsWithProofsResponse, _org_dash_platform_dapi_v0_TransactionsWithProofsRequest__Output, _org_dash_platform_dapi_v0_TransactionsWithProofsResponse__Output>
}
