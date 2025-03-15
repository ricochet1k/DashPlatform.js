import type * as grpc from '@grpc/grpc-js';
import type { MessageTypeDefinition } from '@grpc/proto-loader';

import type { CoreClient as _org_dash_platform_dapi_v0_CoreClient, CoreDefinition as _org_dash_platform_dapi_v0_CoreDefinition } from './org/dash/platform/dapi/v0/Core';

type SubtypeConstructor<Constructor extends new (...args: any) => any, Subtype> = {
  new(...args: ConstructorParameters<Constructor>): Subtype;
};

export interface ProtoGrpcType {
  org: {
    dash: {
      platform: {
        dapi: {
          v0: {
            BlockHeaders: MessageTypeDefinition
            BlockHeadersWithChainLocksRequest: MessageTypeDefinition
            BlockHeadersWithChainLocksResponse: MessageTypeDefinition
            BloomFilter: MessageTypeDefinition
            BroadcastTransactionRequest: MessageTypeDefinition
            BroadcastTransactionResponse: MessageTypeDefinition
            Core: SubtypeConstructor<typeof grpc.Client, _org_dash_platform_dapi_v0_CoreClient> & { service: _org_dash_platform_dapi_v0_CoreDefinition }
            GetBestBlockHeightRequest: MessageTypeDefinition
            GetBestBlockHeightResponse: MessageTypeDefinition
            GetBlockRequest: MessageTypeDefinition
            GetBlockResponse: MessageTypeDefinition
            GetBlockchainStatusRequest: MessageTypeDefinition
            GetBlockchainStatusResponse: MessageTypeDefinition
            GetEstimatedTransactionFeeRequest: MessageTypeDefinition
            GetEstimatedTransactionFeeResponse: MessageTypeDefinition
            GetMasternodeStatusRequest: MessageTypeDefinition
            GetMasternodeStatusResponse: MessageTypeDefinition
            GetTransactionRequest: MessageTypeDefinition
            GetTransactionResponse: MessageTypeDefinition
            InstantSendLockMessages: MessageTypeDefinition
            MasternodeListRequest: MessageTypeDefinition
            MasternodeListResponse: MessageTypeDefinition
            RawTransactions: MessageTypeDefinition
            TransactionsWithProofsRequest: MessageTypeDefinition
            TransactionsWithProofsResponse: MessageTypeDefinition
          }
        }
      }
    }
  }
}

