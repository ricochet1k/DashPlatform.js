import type * as grpc from '@grpc/grpc-js';
import type { EnumTypeDefinition, MessageTypeDefinition } from '@grpc/proto-loader';

import type { PlatformClient as _org_dash_platform_dapi_v0_PlatformClient, PlatformDefinition as _org_dash_platform_dapi_v0_PlatformDefinition } from './org/dash/platform/dapi/v0/Platform';

type SubtypeConstructor<Constructor extends new (...args: any) => any, Subtype> = {
  new(...args: ConstructorParameters<Constructor>): Subtype;
};

export interface ProtoGrpcType {
  google: {
    protobuf: {
      BoolValue: MessageTypeDefinition
      BytesValue: MessageTypeDefinition
      DoubleValue: MessageTypeDefinition
      FloatValue: MessageTypeDefinition
      Int32Value: MessageTypeDefinition
      Int64Value: MessageTypeDefinition
      ListValue: MessageTypeDefinition
      NullValue: EnumTypeDefinition
      StringValue: MessageTypeDefinition
      Struct: MessageTypeDefinition
      Timestamp: MessageTypeDefinition
      UInt32Value: MessageTypeDefinition
      UInt64Value: MessageTypeDefinition
      Value: MessageTypeDefinition
    }
  }
  org: {
    dash: {
      platform: {
        dapi: {
          v0: {
            AllKeys: MessageTypeDefinition
            BroadcastStateTransitionRequest: MessageTypeDefinition
            BroadcastStateTransitionResponse: MessageTypeDefinition
            GetConsensusParamsRequest: MessageTypeDefinition
            GetConsensusParamsResponse: MessageTypeDefinition
            GetContestedResourceIdentityVotesRequest: MessageTypeDefinition
            GetContestedResourceIdentityVotesResponse: MessageTypeDefinition
            GetContestedResourceVoteStateRequest: MessageTypeDefinition
            GetContestedResourceVoteStateResponse: MessageTypeDefinition
            GetContestedResourceVotersForIdentityRequest: MessageTypeDefinition
            GetContestedResourceVotersForIdentityResponse: MessageTypeDefinition
            GetContestedResourcesRequest: MessageTypeDefinition
            GetContestedResourcesResponse: MessageTypeDefinition
            GetCurrentQuorumsInfoRequest: MessageTypeDefinition
            GetCurrentQuorumsInfoResponse: MessageTypeDefinition
            GetDataContractHistoryRequest: MessageTypeDefinition
            GetDataContractHistoryResponse: MessageTypeDefinition
            GetDataContractRequest: MessageTypeDefinition
            GetDataContractResponse: MessageTypeDefinition
            GetDataContractsRequest: MessageTypeDefinition
            GetDataContractsResponse: MessageTypeDefinition
            GetDocumentsRequest: MessageTypeDefinition
            GetDocumentsResponse: MessageTypeDefinition
            GetEpochsInfoRequest: MessageTypeDefinition
            GetEpochsInfoResponse: MessageTypeDefinition
            GetEvonodesProposedEpochBlocksByIdsRequest: MessageTypeDefinition
            GetEvonodesProposedEpochBlocksByRangeRequest: MessageTypeDefinition
            GetEvonodesProposedEpochBlocksResponse: MessageTypeDefinition
            GetGroupActionSignersRequest: MessageTypeDefinition
            GetGroupActionSignersResponse: MessageTypeDefinition
            GetGroupActionsRequest: MessageTypeDefinition
            GetGroupActionsResponse: MessageTypeDefinition
            GetGroupInfoRequest: MessageTypeDefinition
            GetGroupInfoResponse: MessageTypeDefinition
            GetGroupInfosRequest: MessageTypeDefinition
            GetGroupInfosResponse: MessageTypeDefinition
            GetIdentitiesBalancesRequest: MessageTypeDefinition
            GetIdentitiesBalancesResponse: MessageTypeDefinition
            GetIdentitiesContractKeysRequest: MessageTypeDefinition
            GetIdentitiesContractKeysResponse: MessageTypeDefinition
            GetIdentitiesTokenBalancesRequest: MessageTypeDefinition
            GetIdentitiesTokenBalancesResponse: MessageTypeDefinition
            GetIdentitiesTokenInfosRequest: MessageTypeDefinition
            GetIdentitiesTokenInfosResponse: MessageTypeDefinition
            GetIdentityBalanceAndRevisionRequest: MessageTypeDefinition
            GetIdentityBalanceAndRevisionResponse: MessageTypeDefinition
            GetIdentityBalanceRequest: MessageTypeDefinition
            GetIdentityBalanceResponse: MessageTypeDefinition
            GetIdentityByPublicKeyHashRequest: MessageTypeDefinition
            GetIdentityByPublicKeyHashResponse: MessageTypeDefinition
            GetIdentityContractNonceRequest: MessageTypeDefinition
            GetIdentityContractNonceResponse: MessageTypeDefinition
            GetIdentityKeysRequest: MessageTypeDefinition
            GetIdentityKeysResponse: MessageTypeDefinition
            GetIdentityNonceRequest: MessageTypeDefinition
            GetIdentityNonceResponse: MessageTypeDefinition
            GetIdentityRequest: MessageTypeDefinition
            GetIdentityResponse: MessageTypeDefinition
            GetIdentityTokenBalancesRequest: MessageTypeDefinition
            GetIdentityTokenBalancesResponse: MessageTypeDefinition
            GetIdentityTokenInfosRequest: MessageTypeDefinition
            GetIdentityTokenInfosResponse: MessageTypeDefinition
            GetPathElementsRequest: MessageTypeDefinition
            GetPathElementsResponse: MessageTypeDefinition
            GetPrefundedSpecializedBalanceRequest: MessageTypeDefinition
            GetPrefundedSpecializedBalanceResponse: MessageTypeDefinition
            GetProofsRequest: MessageTypeDefinition
            GetProofsResponse: MessageTypeDefinition
            GetProtocolVersionUpgradeStateRequest: MessageTypeDefinition
            GetProtocolVersionUpgradeStateResponse: MessageTypeDefinition
            GetProtocolVersionUpgradeVoteStatusRequest: MessageTypeDefinition
            GetProtocolVersionUpgradeVoteStatusResponse: MessageTypeDefinition
            GetStatusRequest: MessageTypeDefinition
            GetStatusResponse: MessageTypeDefinition
            GetTokenPreProgrammedDistributionsRequest: MessageTypeDefinition
            GetTokenPreProgrammedDistributionsResponse: MessageTypeDefinition
            GetTokenStatusesRequest: MessageTypeDefinition
            GetTokenStatusesResponse: MessageTypeDefinition
            GetTokenTotalSupplyRequest: MessageTypeDefinition
            GetTokenTotalSupplyResponse: MessageTypeDefinition
            GetTotalCreditsInPlatformRequest: MessageTypeDefinition
            GetTotalCreditsInPlatformResponse: MessageTypeDefinition
            GetVotePollsByEndDateRequest: MessageTypeDefinition
            GetVotePollsByEndDateResponse: MessageTypeDefinition
            KeyPurpose: EnumTypeDefinition
            KeyRequestType: MessageTypeDefinition
            Platform: SubtypeConstructor<typeof grpc.Client, _org_dash_platform_dapi_v0_PlatformClient> & { service: _org_dash_platform_dapi_v0_PlatformDefinition }
            Proof: MessageTypeDefinition
            ResponseMetadata: MessageTypeDefinition
            SearchKey: MessageTypeDefinition
            SecurityLevelMap: MessageTypeDefinition
            SpecificKeys: MessageTypeDefinition
            StateTransitionBroadcastError: MessageTypeDefinition
            WaitForStateTransitionResultRequest: MessageTypeDefinition
            WaitForStateTransitionResultResponse: MessageTypeDefinition
          }
        }
      }
    }
  }
}

