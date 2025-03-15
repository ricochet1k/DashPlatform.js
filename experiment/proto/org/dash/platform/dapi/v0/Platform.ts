// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

import type * as grpc from '@grpc/grpc-js'
import type { MethodDefinition } from '@grpc/proto-loader'
import type { BroadcastStateTransitionRequest as _org_dash_platform_dapi_v0_BroadcastStateTransitionRequest, BroadcastStateTransitionRequest__Output as _org_dash_platform_dapi_v0_BroadcastStateTransitionRequest__Output } from '../../../../../org/dash/platform/dapi/v0/BroadcastStateTransitionRequest';
import type { BroadcastStateTransitionResponse as _org_dash_platform_dapi_v0_BroadcastStateTransitionResponse, BroadcastStateTransitionResponse__Output as _org_dash_platform_dapi_v0_BroadcastStateTransitionResponse__Output } from '../../../../../org/dash/platform/dapi/v0/BroadcastStateTransitionResponse';
import type { GetConsensusParamsRequest as _org_dash_platform_dapi_v0_GetConsensusParamsRequest, GetConsensusParamsRequest__Output as _org_dash_platform_dapi_v0_GetConsensusParamsRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetConsensusParamsRequest';
import type { GetConsensusParamsResponse as _org_dash_platform_dapi_v0_GetConsensusParamsResponse, GetConsensusParamsResponse__Output as _org_dash_platform_dapi_v0_GetConsensusParamsResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetConsensusParamsResponse';
import type { GetContestedResourceIdentityVotesRequest as _org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesRequest, GetContestedResourceIdentityVotesRequest__Output as _org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetContestedResourceIdentityVotesRequest';
import type { GetContestedResourceIdentityVotesResponse as _org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesResponse, GetContestedResourceIdentityVotesResponse__Output as _org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetContestedResourceIdentityVotesResponse';
import type { GetContestedResourceVoteStateRequest as _org_dash_platform_dapi_v0_GetContestedResourceVoteStateRequest, GetContestedResourceVoteStateRequest__Output as _org_dash_platform_dapi_v0_GetContestedResourceVoteStateRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetContestedResourceVoteStateRequest';
import type { GetContestedResourceVoteStateResponse as _org_dash_platform_dapi_v0_GetContestedResourceVoteStateResponse, GetContestedResourceVoteStateResponse__Output as _org_dash_platform_dapi_v0_GetContestedResourceVoteStateResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetContestedResourceVoteStateResponse';
import type { GetContestedResourceVotersForIdentityRequest as _org_dash_platform_dapi_v0_GetContestedResourceVotersForIdentityRequest, GetContestedResourceVotersForIdentityRequest__Output as _org_dash_platform_dapi_v0_GetContestedResourceVotersForIdentityRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetContestedResourceVotersForIdentityRequest';
import type { GetContestedResourceVotersForIdentityResponse as _org_dash_platform_dapi_v0_GetContestedResourceVotersForIdentityResponse, GetContestedResourceVotersForIdentityResponse__Output as _org_dash_platform_dapi_v0_GetContestedResourceVotersForIdentityResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetContestedResourceVotersForIdentityResponse';
import type { GetContestedResourcesRequest as _org_dash_platform_dapi_v0_GetContestedResourcesRequest, GetContestedResourcesRequest__Output as _org_dash_platform_dapi_v0_GetContestedResourcesRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetContestedResourcesRequest';
import type { GetContestedResourcesResponse as _org_dash_platform_dapi_v0_GetContestedResourcesResponse, GetContestedResourcesResponse__Output as _org_dash_platform_dapi_v0_GetContestedResourcesResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetContestedResourcesResponse';
import type { GetCurrentQuorumsInfoRequest as _org_dash_platform_dapi_v0_GetCurrentQuorumsInfoRequest, GetCurrentQuorumsInfoRequest__Output as _org_dash_platform_dapi_v0_GetCurrentQuorumsInfoRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetCurrentQuorumsInfoRequest';
import type { GetCurrentQuorumsInfoResponse as _org_dash_platform_dapi_v0_GetCurrentQuorumsInfoResponse, GetCurrentQuorumsInfoResponse__Output as _org_dash_platform_dapi_v0_GetCurrentQuorumsInfoResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetCurrentQuorumsInfoResponse';
import type { GetDataContractHistoryRequest as _org_dash_platform_dapi_v0_GetDataContractHistoryRequest, GetDataContractHistoryRequest__Output as _org_dash_platform_dapi_v0_GetDataContractHistoryRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetDataContractHistoryRequest';
import type { GetDataContractHistoryResponse as _org_dash_platform_dapi_v0_GetDataContractHistoryResponse, GetDataContractHistoryResponse__Output as _org_dash_platform_dapi_v0_GetDataContractHistoryResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetDataContractHistoryResponse';
import type { GetDataContractRequest as _org_dash_platform_dapi_v0_GetDataContractRequest, GetDataContractRequest__Output as _org_dash_platform_dapi_v0_GetDataContractRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetDataContractRequest';
import type { GetDataContractResponse as _org_dash_platform_dapi_v0_GetDataContractResponse, GetDataContractResponse__Output as _org_dash_platform_dapi_v0_GetDataContractResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetDataContractResponse';
import type { GetDataContractsRequest as _org_dash_platform_dapi_v0_GetDataContractsRequest, GetDataContractsRequest__Output as _org_dash_platform_dapi_v0_GetDataContractsRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetDataContractsRequest';
import type { GetDataContractsResponse as _org_dash_platform_dapi_v0_GetDataContractsResponse, GetDataContractsResponse__Output as _org_dash_platform_dapi_v0_GetDataContractsResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetDataContractsResponse';
import type { GetDocumentsRequest as _org_dash_platform_dapi_v0_GetDocumentsRequest, GetDocumentsRequest__Output as _org_dash_platform_dapi_v0_GetDocumentsRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetDocumentsRequest';
import type { GetDocumentsResponse as _org_dash_platform_dapi_v0_GetDocumentsResponse, GetDocumentsResponse__Output as _org_dash_platform_dapi_v0_GetDocumentsResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetDocumentsResponse';
import type { GetEpochsInfoRequest as _org_dash_platform_dapi_v0_GetEpochsInfoRequest, GetEpochsInfoRequest__Output as _org_dash_platform_dapi_v0_GetEpochsInfoRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetEpochsInfoRequest';
import type { GetEpochsInfoResponse as _org_dash_platform_dapi_v0_GetEpochsInfoResponse, GetEpochsInfoResponse__Output as _org_dash_platform_dapi_v0_GetEpochsInfoResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetEpochsInfoResponse';
import type { GetEvonodesProposedEpochBlocksByIdsRequest as _org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksByIdsRequest, GetEvonodesProposedEpochBlocksByIdsRequest__Output as _org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksByIdsRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetEvonodesProposedEpochBlocksByIdsRequest';
import type { GetEvonodesProposedEpochBlocksByRangeRequest as _org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksByRangeRequest, GetEvonodesProposedEpochBlocksByRangeRequest__Output as _org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksByRangeRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetEvonodesProposedEpochBlocksByRangeRequest';
import type { GetEvonodesProposedEpochBlocksResponse as _org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksResponse, GetEvonodesProposedEpochBlocksResponse__Output as _org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetEvonodesProposedEpochBlocksResponse';
import type { GetGroupActionSignersRequest as _org_dash_platform_dapi_v0_GetGroupActionSignersRequest, GetGroupActionSignersRequest__Output as _org_dash_platform_dapi_v0_GetGroupActionSignersRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetGroupActionSignersRequest';
import type { GetGroupActionSignersResponse as _org_dash_platform_dapi_v0_GetGroupActionSignersResponse, GetGroupActionSignersResponse__Output as _org_dash_platform_dapi_v0_GetGroupActionSignersResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetGroupActionSignersResponse';
import type { GetGroupActionsRequest as _org_dash_platform_dapi_v0_GetGroupActionsRequest, GetGroupActionsRequest__Output as _org_dash_platform_dapi_v0_GetGroupActionsRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetGroupActionsRequest';
import type { GetGroupActionsResponse as _org_dash_platform_dapi_v0_GetGroupActionsResponse, GetGroupActionsResponse__Output as _org_dash_platform_dapi_v0_GetGroupActionsResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetGroupActionsResponse';
import type { GetGroupInfoRequest as _org_dash_platform_dapi_v0_GetGroupInfoRequest, GetGroupInfoRequest__Output as _org_dash_platform_dapi_v0_GetGroupInfoRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetGroupInfoRequest';
import type { GetGroupInfoResponse as _org_dash_platform_dapi_v0_GetGroupInfoResponse, GetGroupInfoResponse__Output as _org_dash_platform_dapi_v0_GetGroupInfoResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetGroupInfoResponse';
import type { GetGroupInfosRequest as _org_dash_platform_dapi_v0_GetGroupInfosRequest, GetGroupInfosRequest__Output as _org_dash_platform_dapi_v0_GetGroupInfosRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetGroupInfosRequest';
import type { GetGroupInfosResponse as _org_dash_platform_dapi_v0_GetGroupInfosResponse, GetGroupInfosResponse__Output as _org_dash_platform_dapi_v0_GetGroupInfosResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetGroupInfosResponse';
import type { GetIdentitiesBalancesRequest as _org_dash_platform_dapi_v0_GetIdentitiesBalancesRequest, GetIdentitiesBalancesRequest__Output as _org_dash_platform_dapi_v0_GetIdentitiesBalancesRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetIdentitiesBalancesRequest';
import type { GetIdentitiesBalancesResponse as _org_dash_platform_dapi_v0_GetIdentitiesBalancesResponse, GetIdentitiesBalancesResponse__Output as _org_dash_platform_dapi_v0_GetIdentitiesBalancesResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetIdentitiesBalancesResponse';
import type { GetIdentitiesContractKeysRequest as _org_dash_platform_dapi_v0_GetIdentitiesContractKeysRequest, GetIdentitiesContractKeysRequest__Output as _org_dash_platform_dapi_v0_GetIdentitiesContractKeysRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetIdentitiesContractKeysRequest';
import type { GetIdentitiesContractKeysResponse as _org_dash_platform_dapi_v0_GetIdentitiesContractKeysResponse, GetIdentitiesContractKeysResponse__Output as _org_dash_platform_dapi_v0_GetIdentitiesContractKeysResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetIdentitiesContractKeysResponse';
import type { GetIdentitiesTokenBalancesRequest as _org_dash_platform_dapi_v0_GetIdentitiesTokenBalancesRequest, GetIdentitiesTokenBalancesRequest__Output as _org_dash_platform_dapi_v0_GetIdentitiesTokenBalancesRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetIdentitiesTokenBalancesRequest';
import type { GetIdentitiesTokenBalancesResponse as _org_dash_platform_dapi_v0_GetIdentitiesTokenBalancesResponse, GetIdentitiesTokenBalancesResponse__Output as _org_dash_platform_dapi_v0_GetIdentitiesTokenBalancesResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetIdentitiesTokenBalancesResponse';
import type { GetIdentitiesTokenInfosRequest as _org_dash_platform_dapi_v0_GetIdentitiesTokenInfosRequest, GetIdentitiesTokenInfosRequest__Output as _org_dash_platform_dapi_v0_GetIdentitiesTokenInfosRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetIdentitiesTokenInfosRequest';
import type { GetIdentitiesTokenInfosResponse as _org_dash_platform_dapi_v0_GetIdentitiesTokenInfosResponse, GetIdentitiesTokenInfosResponse__Output as _org_dash_platform_dapi_v0_GetIdentitiesTokenInfosResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetIdentitiesTokenInfosResponse';
import type { GetIdentityBalanceAndRevisionRequest as _org_dash_platform_dapi_v0_GetIdentityBalanceAndRevisionRequest, GetIdentityBalanceAndRevisionRequest__Output as _org_dash_platform_dapi_v0_GetIdentityBalanceAndRevisionRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetIdentityBalanceAndRevisionRequest';
import type { GetIdentityBalanceAndRevisionResponse as _org_dash_platform_dapi_v0_GetIdentityBalanceAndRevisionResponse, GetIdentityBalanceAndRevisionResponse__Output as _org_dash_platform_dapi_v0_GetIdentityBalanceAndRevisionResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetIdentityBalanceAndRevisionResponse';
import type { GetIdentityBalanceRequest as _org_dash_platform_dapi_v0_GetIdentityBalanceRequest, GetIdentityBalanceRequest__Output as _org_dash_platform_dapi_v0_GetIdentityBalanceRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetIdentityBalanceRequest';
import type { GetIdentityBalanceResponse as _org_dash_platform_dapi_v0_GetIdentityBalanceResponse, GetIdentityBalanceResponse__Output as _org_dash_platform_dapi_v0_GetIdentityBalanceResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetIdentityBalanceResponse';
import type { GetIdentityByPublicKeyHashRequest as _org_dash_platform_dapi_v0_GetIdentityByPublicKeyHashRequest, GetIdentityByPublicKeyHashRequest__Output as _org_dash_platform_dapi_v0_GetIdentityByPublicKeyHashRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetIdentityByPublicKeyHashRequest';
import type { GetIdentityByPublicKeyHashResponse as _org_dash_platform_dapi_v0_GetIdentityByPublicKeyHashResponse, GetIdentityByPublicKeyHashResponse__Output as _org_dash_platform_dapi_v0_GetIdentityByPublicKeyHashResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetIdentityByPublicKeyHashResponse';
import type { GetIdentityContractNonceRequest as _org_dash_platform_dapi_v0_GetIdentityContractNonceRequest, GetIdentityContractNonceRequest__Output as _org_dash_platform_dapi_v0_GetIdentityContractNonceRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetIdentityContractNonceRequest';
import type { GetIdentityContractNonceResponse as _org_dash_platform_dapi_v0_GetIdentityContractNonceResponse, GetIdentityContractNonceResponse__Output as _org_dash_platform_dapi_v0_GetIdentityContractNonceResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetIdentityContractNonceResponse';
import type { GetIdentityKeysRequest as _org_dash_platform_dapi_v0_GetIdentityKeysRequest, GetIdentityKeysRequest__Output as _org_dash_platform_dapi_v0_GetIdentityKeysRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetIdentityKeysRequest';
import type { GetIdentityKeysResponse as _org_dash_platform_dapi_v0_GetIdentityKeysResponse, GetIdentityKeysResponse__Output as _org_dash_platform_dapi_v0_GetIdentityKeysResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetIdentityKeysResponse';
import type { GetIdentityNonceRequest as _org_dash_platform_dapi_v0_GetIdentityNonceRequest, GetIdentityNonceRequest__Output as _org_dash_platform_dapi_v0_GetIdentityNonceRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetIdentityNonceRequest';
import type { GetIdentityNonceResponse as _org_dash_platform_dapi_v0_GetIdentityNonceResponse, GetIdentityNonceResponse__Output as _org_dash_platform_dapi_v0_GetIdentityNonceResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetIdentityNonceResponse';
import type { GetIdentityRequest as _org_dash_platform_dapi_v0_GetIdentityRequest, GetIdentityRequest__Output as _org_dash_platform_dapi_v0_GetIdentityRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetIdentityRequest';
import type { GetIdentityResponse as _org_dash_platform_dapi_v0_GetIdentityResponse, GetIdentityResponse__Output as _org_dash_platform_dapi_v0_GetIdentityResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetIdentityResponse';
import type { GetIdentityTokenBalancesRequest as _org_dash_platform_dapi_v0_GetIdentityTokenBalancesRequest, GetIdentityTokenBalancesRequest__Output as _org_dash_platform_dapi_v0_GetIdentityTokenBalancesRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetIdentityTokenBalancesRequest';
import type { GetIdentityTokenBalancesResponse as _org_dash_platform_dapi_v0_GetIdentityTokenBalancesResponse, GetIdentityTokenBalancesResponse__Output as _org_dash_platform_dapi_v0_GetIdentityTokenBalancesResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetIdentityTokenBalancesResponse';
import type { GetIdentityTokenInfosRequest as _org_dash_platform_dapi_v0_GetIdentityTokenInfosRequest, GetIdentityTokenInfosRequest__Output as _org_dash_platform_dapi_v0_GetIdentityTokenInfosRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetIdentityTokenInfosRequest';
import type { GetIdentityTokenInfosResponse as _org_dash_platform_dapi_v0_GetIdentityTokenInfosResponse, GetIdentityTokenInfosResponse__Output as _org_dash_platform_dapi_v0_GetIdentityTokenInfosResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetIdentityTokenInfosResponse';
import type { GetPathElementsRequest as _org_dash_platform_dapi_v0_GetPathElementsRequest, GetPathElementsRequest__Output as _org_dash_platform_dapi_v0_GetPathElementsRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetPathElementsRequest';
import type { GetPathElementsResponse as _org_dash_platform_dapi_v0_GetPathElementsResponse, GetPathElementsResponse__Output as _org_dash_platform_dapi_v0_GetPathElementsResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetPathElementsResponse';
import type { GetPrefundedSpecializedBalanceRequest as _org_dash_platform_dapi_v0_GetPrefundedSpecializedBalanceRequest, GetPrefundedSpecializedBalanceRequest__Output as _org_dash_platform_dapi_v0_GetPrefundedSpecializedBalanceRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetPrefundedSpecializedBalanceRequest';
import type { GetPrefundedSpecializedBalanceResponse as _org_dash_platform_dapi_v0_GetPrefundedSpecializedBalanceResponse, GetPrefundedSpecializedBalanceResponse__Output as _org_dash_platform_dapi_v0_GetPrefundedSpecializedBalanceResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetPrefundedSpecializedBalanceResponse';
import type { GetProofsRequest as _org_dash_platform_dapi_v0_GetProofsRequest, GetProofsRequest__Output as _org_dash_platform_dapi_v0_GetProofsRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetProofsRequest';
import type { GetProofsResponse as _org_dash_platform_dapi_v0_GetProofsResponse, GetProofsResponse__Output as _org_dash_platform_dapi_v0_GetProofsResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetProofsResponse';
import type { GetProtocolVersionUpgradeStateRequest as _org_dash_platform_dapi_v0_GetProtocolVersionUpgradeStateRequest, GetProtocolVersionUpgradeStateRequest__Output as _org_dash_platform_dapi_v0_GetProtocolVersionUpgradeStateRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetProtocolVersionUpgradeStateRequest';
import type { GetProtocolVersionUpgradeStateResponse as _org_dash_platform_dapi_v0_GetProtocolVersionUpgradeStateResponse, GetProtocolVersionUpgradeStateResponse__Output as _org_dash_platform_dapi_v0_GetProtocolVersionUpgradeStateResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetProtocolVersionUpgradeStateResponse';
import type { GetProtocolVersionUpgradeVoteStatusRequest as _org_dash_platform_dapi_v0_GetProtocolVersionUpgradeVoteStatusRequest, GetProtocolVersionUpgradeVoteStatusRequest__Output as _org_dash_platform_dapi_v0_GetProtocolVersionUpgradeVoteStatusRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetProtocolVersionUpgradeVoteStatusRequest';
import type { GetProtocolVersionUpgradeVoteStatusResponse as _org_dash_platform_dapi_v0_GetProtocolVersionUpgradeVoteStatusResponse, GetProtocolVersionUpgradeVoteStatusResponse__Output as _org_dash_platform_dapi_v0_GetProtocolVersionUpgradeVoteStatusResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetProtocolVersionUpgradeVoteStatusResponse';
import type { GetStatusRequest as _org_dash_platform_dapi_v0_GetStatusRequest, GetStatusRequest__Output as _org_dash_platform_dapi_v0_GetStatusRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetStatusRequest';
import type { GetStatusResponse as _org_dash_platform_dapi_v0_GetStatusResponse, GetStatusResponse__Output as _org_dash_platform_dapi_v0_GetStatusResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetStatusResponse';
import type { GetTokenPreProgrammedDistributionsRequest as _org_dash_platform_dapi_v0_GetTokenPreProgrammedDistributionsRequest, GetTokenPreProgrammedDistributionsRequest__Output as _org_dash_platform_dapi_v0_GetTokenPreProgrammedDistributionsRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetTokenPreProgrammedDistributionsRequest';
import type { GetTokenPreProgrammedDistributionsResponse as _org_dash_platform_dapi_v0_GetTokenPreProgrammedDistributionsResponse, GetTokenPreProgrammedDistributionsResponse__Output as _org_dash_platform_dapi_v0_GetTokenPreProgrammedDistributionsResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetTokenPreProgrammedDistributionsResponse';
import type { GetTokenStatusesRequest as _org_dash_platform_dapi_v0_GetTokenStatusesRequest, GetTokenStatusesRequest__Output as _org_dash_platform_dapi_v0_GetTokenStatusesRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetTokenStatusesRequest';
import type { GetTokenStatusesResponse as _org_dash_platform_dapi_v0_GetTokenStatusesResponse, GetTokenStatusesResponse__Output as _org_dash_platform_dapi_v0_GetTokenStatusesResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetTokenStatusesResponse';
import type { GetTokenTotalSupplyRequest as _org_dash_platform_dapi_v0_GetTokenTotalSupplyRequest, GetTokenTotalSupplyRequest__Output as _org_dash_platform_dapi_v0_GetTokenTotalSupplyRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetTokenTotalSupplyRequest';
import type { GetTokenTotalSupplyResponse as _org_dash_platform_dapi_v0_GetTokenTotalSupplyResponse, GetTokenTotalSupplyResponse__Output as _org_dash_platform_dapi_v0_GetTokenTotalSupplyResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetTokenTotalSupplyResponse';
import type { GetTotalCreditsInPlatformRequest as _org_dash_platform_dapi_v0_GetTotalCreditsInPlatformRequest, GetTotalCreditsInPlatformRequest__Output as _org_dash_platform_dapi_v0_GetTotalCreditsInPlatformRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetTotalCreditsInPlatformRequest';
import type { GetTotalCreditsInPlatformResponse as _org_dash_platform_dapi_v0_GetTotalCreditsInPlatformResponse, GetTotalCreditsInPlatformResponse__Output as _org_dash_platform_dapi_v0_GetTotalCreditsInPlatformResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetTotalCreditsInPlatformResponse';
import type { GetVotePollsByEndDateRequest as _org_dash_platform_dapi_v0_GetVotePollsByEndDateRequest, GetVotePollsByEndDateRequest__Output as _org_dash_platform_dapi_v0_GetVotePollsByEndDateRequest__Output } from '../../../../../org/dash/platform/dapi/v0/GetVotePollsByEndDateRequest';
import type { GetVotePollsByEndDateResponse as _org_dash_platform_dapi_v0_GetVotePollsByEndDateResponse, GetVotePollsByEndDateResponse__Output as _org_dash_platform_dapi_v0_GetVotePollsByEndDateResponse__Output } from '../../../../../org/dash/platform/dapi/v0/GetVotePollsByEndDateResponse';
import type { WaitForStateTransitionResultRequest as _org_dash_platform_dapi_v0_WaitForStateTransitionResultRequest, WaitForStateTransitionResultRequest__Output as _org_dash_platform_dapi_v0_WaitForStateTransitionResultRequest__Output } from '../../../../../org/dash/platform/dapi/v0/WaitForStateTransitionResultRequest';
import type { WaitForStateTransitionResultResponse as _org_dash_platform_dapi_v0_WaitForStateTransitionResultResponse, WaitForStateTransitionResultResponse__Output as _org_dash_platform_dapi_v0_WaitForStateTransitionResultResponse__Output } from '../../../../../org/dash/platform/dapi/v0/WaitForStateTransitionResultResponse';

export interface PlatformClient extends grpc.Client {
  broadcastStateTransition(argument: _org_dash_platform_dapi_v0_BroadcastStateTransitionRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_BroadcastStateTransitionResponse__Output>): grpc.ClientUnaryCall;
  broadcastStateTransition(argument: _org_dash_platform_dapi_v0_BroadcastStateTransitionRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_BroadcastStateTransitionResponse__Output>): grpc.ClientUnaryCall;
  broadcastStateTransition(argument: _org_dash_platform_dapi_v0_BroadcastStateTransitionRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_BroadcastStateTransitionResponse__Output>): grpc.ClientUnaryCall;
  broadcastStateTransition(argument: _org_dash_platform_dapi_v0_BroadcastStateTransitionRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_BroadcastStateTransitionResponse__Output>): grpc.ClientUnaryCall;
  
  getConsensusParams(argument: _org_dash_platform_dapi_v0_GetConsensusParamsRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetConsensusParamsResponse__Output>): grpc.ClientUnaryCall;
  getConsensusParams(argument: _org_dash_platform_dapi_v0_GetConsensusParamsRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetConsensusParamsResponse__Output>): grpc.ClientUnaryCall;
  getConsensusParams(argument: _org_dash_platform_dapi_v0_GetConsensusParamsRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetConsensusParamsResponse__Output>): grpc.ClientUnaryCall;
  getConsensusParams(argument: _org_dash_platform_dapi_v0_GetConsensusParamsRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetConsensusParamsResponse__Output>): grpc.ClientUnaryCall;
  
  getContestedResourceIdentityVotes(argument: _org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesResponse__Output>): grpc.ClientUnaryCall;
  getContestedResourceIdentityVotes(argument: _org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesResponse__Output>): grpc.ClientUnaryCall;
  getContestedResourceIdentityVotes(argument: _org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesResponse__Output>): grpc.ClientUnaryCall;
  getContestedResourceIdentityVotes(argument: _org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesResponse__Output>): grpc.ClientUnaryCall;
  
  getContestedResourceVoteState(argument: _org_dash_platform_dapi_v0_GetContestedResourceVoteStateRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetContestedResourceVoteStateResponse__Output>): grpc.ClientUnaryCall;
  getContestedResourceVoteState(argument: _org_dash_platform_dapi_v0_GetContestedResourceVoteStateRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetContestedResourceVoteStateResponse__Output>): grpc.ClientUnaryCall;
  getContestedResourceVoteState(argument: _org_dash_platform_dapi_v0_GetContestedResourceVoteStateRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetContestedResourceVoteStateResponse__Output>): grpc.ClientUnaryCall;
  getContestedResourceVoteState(argument: _org_dash_platform_dapi_v0_GetContestedResourceVoteStateRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetContestedResourceVoteStateResponse__Output>): grpc.ClientUnaryCall;
  
  getContestedResourceVotersForIdentity(argument: _org_dash_platform_dapi_v0_GetContestedResourceVotersForIdentityRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetContestedResourceVotersForIdentityResponse__Output>): grpc.ClientUnaryCall;
  getContestedResourceVotersForIdentity(argument: _org_dash_platform_dapi_v0_GetContestedResourceVotersForIdentityRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetContestedResourceVotersForIdentityResponse__Output>): grpc.ClientUnaryCall;
  getContestedResourceVotersForIdentity(argument: _org_dash_platform_dapi_v0_GetContestedResourceVotersForIdentityRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetContestedResourceVotersForIdentityResponse__Output>): grpc.ClientUnaryCall;
  getContestedResourceVotersForIdentity(argument: _org_dash_platform_dapi_v0_GetContestedResourceVotersForIdentityRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetContestedResourceVotersForIdentityResponse__Output>): grpc.ClientUnaryCall;
  
  getContestedResources(argument: _org_dash_platform_dapi_v0_GetContestedResourcesRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetContestedResourcesResponse__Output>): grpc.ClientUnaryCall;
  getContestedResources(argument: _org_dash_platform_dapi_v0_GetContestedResourcesRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetContestedResourcesResponse__Output>): grpc.ClientUnaryCall;
  getContestedResources(argument: _org_dash_platform_dapi_v0_GetContestedResourcesRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetContestedResourcesResponse__Output>): grpc.ClientUnaryCall;
  getContestedResources(argument: _org_dash_platform_dapi_v0_GetContestedResourcesRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetContestedResourcesResponse__Output>): grpc.ClientUnaryCall;
  
  getCurrentQuorumsInfo(argument: _org_dash_platform_dapi_v0_GetCurrentQuorumsInfoRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetCurrentQuorumsInfoResponse__Output>): grpc.ClientUnaryCall;
  getCurrentQuorumsInfo(argument: _org_dash_platform_dapi_v0_GetCurrentQuorumsInfoRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetCurrentQuorumsInfoResponse__Output>): grpc.ClientUnaryCall;
  getCurrentQuorumsInfo(argument: _org_dash_platform_dapi_v0_GetCurrentQuorumsInfoRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetCurrentQuorumsInfoResponse__Output>): grpc.ClientUnaryCall;
  getCurrentQuorumsInfo(argument: _org_dash_platform_dapi_v0_GetCurrentQuorumsInfoRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetCurrentQuorumsInfoResponse__Output>): grpc.ClientUnaryCall;
  
  getDataContract(argument: _org_dash_platform_dapi_v0_GetDataContractRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetDataContractResponse__Output>): grpc.ClientUnaryCall;
  getDataContract(argument: _org_dash_platform_dapi_v0_GetDataContractRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetDataContractResponse__Output>): grpc.ClientUnaryCall;
  getDataContract(argument: _org_dash_platform_dapi_v0_GetDataContractRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetDataContractResponse__Output>): grpc.ClientUnaryCall;
  getDataContract(argument: _org_dash_platform_dapi_v0_GetDataContractRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetDataContractResponse__Output>): grpc.ClientUnaryCall;
  
  getDataContractHistory(argument: _org_dash_platform_dapi_v0_GetDataContractHistoryRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetDataContractHistoryResponse__Output>): grpc.ClientUnaryCall;
  getDataContractHistory(argument: _org_dash_platform_dapi_v0_GetDataContractHistoryRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetDataContractHistoryResponse__Output>): grpc.ClientUnaryCall;
  getDataContractHistory(argument: _org_dash_platform_dapi_v0_GetDataContractHistoryRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetDataContractHistoryResponse__Output>): grpc.ClientUnaryCall;
  getDataContractHistory(argument: _org_dash_platform_dapi_v0_GetDataContractHistoryRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetDataContractHistoryResponse__Output>): grpc.ClientUnaryCall;
  
  getDataContracts(argument: _org_dash_platform_dapi_v0_GetDataContractsRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetDataContractsResponse__Output>): grpc.ClientUnaryCall;
  getDataContracts(argument: _org_dash_platform_dapi_v0_GetDataContractsRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetDataContractsResponse__Output>): grpc.ClientUnaryCall;
  getDataContracts(argument: _org_dash_platform_dapi_v0_GetDataContractsRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetDataContractsResponse__Output>): grpc.ClientUnaryCall;
  getDataContracts(argument: _org_dash_platform_dapi_v0_GetDataContractsRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetDataContractsResponse__Output>): grpc.ClientUnaryCall;
  
  getDocuments(argument: _org_dash_platform_dapi_v0_GetDocumentsRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetDocumentsResponse__Output>): grpc.ClientUnaryCall;
  getDocuments(argument: _org_dash_platform_dapi_v0_GetDocumentsRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetDocumentsResponse__Output>): grpc.ClientUnaryCall;
  getDocuments(argument: _org_dash_platform_dapi_v0_GetDocumentsRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetDocumentsResponse__Output>): grpc.ClientUnaryCall;
  getDocuments(argument: _org_dash_platform_dapi_v0_GetDocumentsRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetDocumentsResponse__Output>): grpc.ClientUnaryCall;
  
  getEpochsInfo(argument: _org_dash_platform_dapi_v0_GetEpochsInfoRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetEpochsInfoResponse__Output>): grpc.ClientUnaryCall;
  getEpochsInfo(argument: _org_dash_platform_dapi_v0_GetEpochsInfoRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetEpochsInfoResponse__Output>): grpc.ClientUnaryCall;
  getEpochsInfo(argument: _org_dash_platform_dapi_v0_GetEpochsInfoRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetEpochsInfoResponse__Output>): grpc.ClientUnaryCall;
  getEpochsInfo(argument: _org_dash_platform_dapi_v0_GetEpochsInfoRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetEpochsInfoResponse__Output>): grpc.ClientUnaryCall;
  
  getEvonodesProposedEpochBlocksByIds(argument: _org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksByIdsRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksResponse__Output>): grpc.ClientUnaryCall;
  getEvonodesProposedEpochBlocksByIds(argument: _org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksByIdsRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksResponse__Output>): grpc.ClientUnaryCall;
  getEvonodesProposedEpochBlocksByIds(argument: _org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksByIdsRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksResponse__Output>): grpc.ClientUnaryCall;
  getEvonodesProposedEpochBlocksByIds(argument: _org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksByIdsRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksResponse__Output>): grpc.ClientUnaryCall;
  
  getEvonodesProposedEpochBlocksByRange(argument: _org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksByRangeRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksResponse__Output>): grpc.ClientUnaryCall;
  getEvonodesProposedEpochBlocksByRange(argument: _org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksByRangeRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksResponse__Output>): grpc.ClientUnaryCall;
  getEvonodesProposedEpochBlocksByRange(argument: _org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksByRangeRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksResponse__Output>): grpc.ClientUnaryCall;
  getEvonodesProposedEpochBlocksByRange(argument: _org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksByRangeRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksResponse__Output>): grpc.ClientUnaryCall;
  
  getGroupActionSigners(argument: _org_dash_platform_dapi_v0_GetGroupActionSignersRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetGroupActionSignersResponse__Output>): grpc.ClientUnaryCall;
  getGroupActionSigners(argument: _org_dash_platform_dapi_v0_GetGroupActionSignersRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetGroupActionSignersResponse__Output>): grpc.ClientUnaryCall;
  getGroupActionSigners(argument: _org_dash_platform_dapi_v0_GetGroupActionSignersRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetGroupActionSignersResponse__Output>): grpc.ClientUnaryCall;
  getGroupActionSigners(argument: _org_dash_platform_dapi_v0_GetGroupActionSignersRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetGroupActionSignersResponse__Output>): grpc.ClientUnaryCall;
  
  getGroupActions(argument: _org_dash_platform_dapi_v0_GetGroupActionsRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetGroupActionsResponse__Output>): grpc.ClientUnaryCall;
  getGroupActions(argument: _org_dash_platform_dapi_v0_GetGroupActionsRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetGroupActionsResponse__Output>): grpc.ClientUnaryCall;
  getGroupActions(argument: _org_dash_platform_dapi_v0_GetGroupActionsRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetGroupActionsResponse__Output>): grpc.ClientUnaryCall;
  getGroupActions(argument: _org_dash_platform_dapi_v0_GetGroupActionsRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetGroupActionsResponse__Output>): grpc.ClientUnaryCall;
  
  getGroupInfo(argument: _org_dash_platform_dapi_v0_GetGroupInfoRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetGroupInfoResponse__Output>): grpc.ClientUnaryCall;
  getGroupInfo(argument: _org_dash_platform_dapi_v0_GetGroupInfoRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetGroupInfoResponse__Output>): grpc.ClientUnaryCall;
  getGroupInfo(argument: _org_dash_platform_dapi_v0_GetGroupInfoRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetGroupInfoResponse__Output>): grpc.ClientUnaryCall;
  getGroupInfo(argument: _org_dash_platform_dapi_v0_GetGroupInfoRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetGroupInfoResponse__Output>): grpc.ClientUnaryCall;
  
  getGroupInfos(argument: _org_dash_platform_dapi_v0_GetGroupInfosRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetGroupInfosResponse__Output>): grpc.ClientUnaryCall;
  getGroupInfos(argument: _org_dash_platform_dapi_v0_GetGroupInfosRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetGroupInfosResponse__Output>): grpc.ClientUnaryCall;
  getGroupInfos(argument: _org_dash_platform_dapi_v0_GetGroupInfosRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetGroupInfosResponse__Output>): grpc.ClientUnaryCall;
  getGroupInfos(argument: _org_dash_platform_dapi_v0_GetGroupInfosRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetGroupInfosResponse__Output>): grpc.ClientUnaryCall;
  
  getIdentitiesBalances(argument: _org_dash_platform_dapi_v0_GetIdentitiesBalancesRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentitiesBalancesResponse__Output>): grpc.ClientUnaryCall;
  getIdentitiesBalances(argument: _org_dash_platform_dapi_v0_GetIdentitiesBalancesRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentitiesBalancesResponse__Output>): grpc.ClientUnaryCall;
  getIdentitiesBalances(argument: _org_dash_platform_dapi_v0_GetIdentitiesBalancesRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentitiesBalancesResponse__Output>): grpc.ClientUnaryCall;
  getIdentitiesBalances(argument: _org_dash_platform_dapi_v0_GetIdentitiesBalancesRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentitiesBalancesResponse__Output>): grpc.ClientUnaryCall;
  
  getIdentitiesContractKeys(argument: _org_dash_platform_dapi_v0_GetIdentitiesContractKeysRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentitiesContractKeysResponse__Output>): grpc.ClientUnaryCall;
  getIdentitiesContractKeys(argument: _org_dash_platform_dapi_v0_GetIdentitiesContractKeysRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentitiesContractKeysResponse__Output>): grpc.ClientUnaryCall;
  getIdentitiesContractKeys(argument: _org_dash_platform_dapi_v0_GetIdentitiesContractKeysRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentitiesContractKeysResponse__Output>): grpc.ClientUnaryCall;
  getIdentitiesContractKeys(argument: _org_dash_platform_dapi_v0_GetIdentitiesContractKeysRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentitiesContractKeysResponse__Output>): grpc.ClientUnaryCall;
  
  getIdentitiesTokenBalances(argument: _org_dash_platform_dapi_v0_GetIdentitiesTokenBalancesRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentitiesTokenBalancesResponse__Output>): grpc.ClientUnaryCall;
  getIdentitiesTokenBalances(argument: _org_dash_platform_dapi_v0_GetIdentitiesTokenBalancesRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentitiesTokenBalancesResponse__Output>): grpc.ClientUnaryCall;
  getIdentitiesTokenBalances(argument: _org_dash_platform_dapi_v0_GetIdentitiesTokenBalancesRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentitiesTokenBalancesResponse__Output>): grpc.ClientUnaryCall;
  getIdentitiesTokenBalances(argument: _org_dash_platform_dapi_v0_GetIdentitiesTokenBalancesRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentitiesTokenBalancesResponse__Output>): grpc.ClientUnaryCall;
  
  getIdentitiesTokenInfos(argument: _org_dash_platform_dapi_v0_GetIdentitiesTokenInfosRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentitiesTokenInfosResponse__Output>): grpc.ClientUnaryCall;
  getIdentitiesTokenInfos(argument: _org_dash_platform_dapi_v0_GetIdentitiesTokenInfosRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentitiesTokenInfosResponse__Output>): grpc.ClientUnaryCall;
  getIdentitiesTokenInfos(argument: _org_dash_platform_dapi_v0_GetIdentitiesTokenInfosRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentitiesTokenInfosResponse__Output>): grpc.ClientUnaryCall;
  getIdentitiesTokenInfos(argument: _org_dash_platform_dapi_v0_GetIdentitiesTokenInfosRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentitiesTokenInfosResponse__Output>): grpc.ClientUnaryCall;
  
  getIdentity(argument: _org_dash_platform_dapi_v0_GetIdentityRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentityResponse__Output>): grpc.ClientUnaryCall;
  getIdentity(argument: _org_dash_platform_dapi_v0_GetIdentityRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentityResponse__Output>): grpc.ClientUnaryCall;
  getIdentity(argument: _org_dash_platform_dapi_v0_GetIdentityRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentityResponse__Output>): grpc.ClientUnaryCall;
  getIdentity(argument: _org_dash_platform_dapi_v0_GetIdentityRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentityResponse__Output>): grpc.ClientUnaryCall;
  
  getIdentityBalance(argument: _org_dash_platform_dapi_v0_GetIdentityBalanceRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentityBalanceResponse__Output>): grpc.ClientUnaryCall;
  getIdentityBalance(argument: _org_dash_platform_dapi_v0_GetIdentityBalanceRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentityBalanceResponse__Output>): grpc.ClientUnaryCall;
  getIdentityBalance(argument: _org_dash_platform_dapi_v0_GetIdentityBalanceRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentityBalanceResponse__Output>): grpc.ClientUnaryCall;
  getIdentityBalance(argument: _org_dash_platform_dapi_v0_GetIdentityBalanceRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentityBalanceResponse__Output>): grpc.ClientUnaryCall;
  
  getIdentityBalanceAndRevision(argument: _org_dash_platform_dapi_v0_GetIdentityBalanceAndRevisionRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentityBalanceAndRevisionResponse__Output>): grpc.ClientUnaryCall;
  getIdentityBalanceAndRevision(argument: _org_dash_platform_dapi_v0_GetIdentityBalanceAndRevisionRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentityBalanceAndRevisionResponse__Output>): grpc.ClientUnaryCall;
  getIdentityBalanceAndRevision(argument: _org_dash_platform_dapi_v0_GetIdentityBalanceAndRevisionRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentityBalanceAndRevisionResponse__Output>): grpc.ClientUnaryCall;
  getIdentityBalanceAndRevision(argument: _org_dash_platform_dapi_v0_GetIdentityBalanceAndRevisionRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentityBalanceAndRevisionResponse__Output>): grpc.ClientUnaryCall;
  
  getIdentityByPublicKeyHash(argument: _org_dash_platform_dapi_v0_GetIdentityByPublicKeyHashRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentityByPublicKeyHashResponse__Output>): grpc.ClientUnaryCall;
  getIdentityByPublicKeyHash(argument: _org_dash_platform_dapi_v0_GetIdentityByPublicKeyHashRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentityByPublicKeyHashResponse__Output>): grpc.ClientUnaryCall;
  getIdentityByPublicKeyHash(argument: _org_dash_platform_dapi_v0_GetIdentityByPublicKeyHashRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentityByPublicKeyHashResponse__Output>): grpc.ClientUnaryCall;
  getIdentityByPublicKeyHash(argument: _org_dash_platform_dapi_v0_GetIdentityByPublicKeyHashRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentityByPublicKeyHashResponse__Output>): grpc.ClientUnaryCall;
  
  getIdentityContractNonce(argument: _org_dash_platform_dapi_v0_GetIdentityContractNonceRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentityContractNonceResponse__Output>): grpc.ClientUnaryCall;
  getIdentityContractNonce(argument: _org_dash_platform_dapi_v0_GetIdentityContractNonceRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentityContractNonceResponse__Output>): grpc.ClientUnaryCall;
  getIdentityContractNonce(argument: _org_dash_platform_dapi_v0_GetIdentityContractNonceRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentityContractNonceResponse__Output>): grpc.ClientUnaryCall;
  getIdentityContractNonce(argument: _org_dash_platform_dapi_v0_GetIdentityContractNonceRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentityContractNonceResponse__Output>): grpc.ClientUnaryCall;
  
  getIdentityKeys(argument: _org_dash_platform_dapi_v0_GetIdentityKeysRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentityKeysResponse__Output>): grpc.ClientUnaryCall;
  getIdentityKeys(argument: _org_dash_platform_dapi_v0_GetIdentityKeysRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentityKeysResponse__Output>): grpc.ClientUnaryCall;
  getIdentityKeys(argument: _org_dash_platform_dapi_v0_GetIdentityKeysRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentityKeysResponse__Output>): grpc.ClientUnaryCall;
  getIdentityKeys(argument: _org_dash_platform_dapi_v0_GetIdentityKeysRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentityKeysResponse__Output>): grpc.ClientUnaryCall;
  
  getIdentityNonce(argument: _org_dash_platform_dapi_v0_GetIdentityNonceRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentityNonceResponse__Output>): grpc.ClientUnaryCall;
  getIdentityNonce(argument: _org_dash_platform_dapi_v0_GetIdentityNonceRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentityNonceResponse__Output>): grpc.ClientUnaryCall;
  getIdentityNonce(argument: _org_dash_platform_dapi_v0_GetIdentityNonceRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentityNonceResponse__Output>): grpc.ClientUnaryCall;
  getIdentityNonce(argument: _org_dash_platform_dapi_v0_GetIdentityNonceRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentityNonceResponse__Output>): grpc.ClientUnaryCall;
  
  getIdentityTokenBalances(argument: _org_dash_platform_dapi_v0_GetIdentityTokenBalancesRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentityTokenBalancesResponse__Output>): grpc.ClientUnaryCall;
  getIdentityTokenBalances(argument: _org_dash_platform_dapi_v0_GetIdentityTokenBalancesRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentityTokenBalancesResponse__Output>): grpc.ClientUnaryCall;
  getIdentityTokenBalances(argument: _org_dash_platform_dapi_v0_GetIdentityTokenBalancesRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentityTokenBalancesResponse__Output>): grpc.ClientUnaryCall;
  getIdentityTokenBalances(argument: _org_dash_platform_dapi_v0_GetIdentityTokenBalancesRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentityTokenBalancesResponse__Output>): grpc.ClientUnaryCall;
  
  getIdentityTokenInfos(argument: _org_dash_platform_dapi_v0_GetIdentityTokenInfosRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentityTokenInfosResponse__Output>): grpc.ClientUnaryCall;
  getIdentityTokenInfos(argument: _org_dash_platform_dapi_v0_GetIdentityTokenInfosRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentityTokenInfosResponse__Output>): grpc.ClientUnaryCall;
  getIdentityTokenInfos(argument: _org_dash_platform_dapi_v0_GetIdentityTokenInfosRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentityTokenInfosResponse__Output>): grpc.ClientUnaryCall;
  getIdentityTokenInfos(argument: _org_dash_platform_dapi_v0_GetIdentityTokenInfosRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetIdentityTokenInfosResponse__Output>): grpc.ClientUnaryCall;
  
  getPathElements(argument: _org_dash_platform_dapi_v0_GetPathElementsRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetPathElementsResponse__Output>): grpc.ClientUnaryCall;
  getPathElements(argument: _org_dash_platform_dapi_v0_GetPathElementsRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetPathElementsResponse__Output>): grpc.ClientUnaryCall;
  getPathElements(argument: _org_dash_platform_dapi_v0_GetPathElementsRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetPathElementsResponse__Output>): grpc.ClientUnaryCall;
  getPathElements(argument: _org_dash_platform_dapi_v0_GetPathElementsRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetPathElementsResponse__Output>): grpc.ClientUnaryCall;
  
  getPrefundedSpecializedBalance(argument: _org_dash_platform_dapi_v0_GetPrefundedSpecializedBalanceRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetPrefundedSpecializedBalanceResponse__Output>): grpc.ClientUnaryCall;
  getPrefundedSpecializedBalance(argument: _org_dash_platform_dapi_v0_GetPrefundedSpecializedBalanceRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetPrefundedSpecializedBalanceResponse__Output>): grpc.ClientUnaryCall;
  getPrefundedSpecializedBalance(argument: _org_dash_platform_dapi_v0_GetPrefundedSpecializedBalanceRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetPrefundedSpecializedBalanceResponse__Output>): grpc.ClientUnaryCall;
  getPrefundedSpecializedBalance(argument: _org_dash_platform_dapi_v0_GetPrefundedSpecializedBalanceRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetPrefundedSpecializedBalanceResponse__Output>): grpc.ClientUnaryCall;
  
  getProofs(argument: _org_dash_platform_dapi_v0_GetProofsRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetProofsResponse__Output>): grpc.ClientUnaryCall;
  getProofs(argument: _org_dash_platform_dapi_v0_GetProofsRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetProofsResponse__Output>): grpc.ClientUnaryCall;
  getProofs(argument: _org_dash_platform_dapi_v0_GetProofsRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetProofsResponse__Output>): grpc.ClientUnaryCall;
  getProofs(argument: _org_dash_platform_dapi_v0_GetProofsRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetProofsResponse__Output>): grpc.ClientUnaryCall;
  
  getProtocolVersionUpgradeState(argument: _org_dash_platform_dapi_v0_GetProtocolVersionUpgradeStateRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetProtocolVersionUpgradeStateResponse__Output>): grpc.ClientUnaryCall;
  getProtocolVersionUpgradeState(argument: _org_dash_platform_dapi_v0_GetProtocolVersionUpgradeStateRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetProtocolVersionUpgradeStateResponse__Output>): grpc.ClientUnaryCall;
  getProtocolVersionUpgradeState(argument: _org_dash_platform_dapi_v0_GetProtocolVersionUpgradeStateRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetProtocolVersionUpgradeStateResponse__Output>): grpc.ClientUnaryCall;
  getProtocolVersionUpgradeState(argument: _org_dash_platform_dapi_v0_GetProtocolVersionUpgradeStateRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetProtocolVersionUpgradeStateResponse__Output>): grpc.ClientUnaryCall;
  
  getProtocolVersionUpgradeVoteStatus(argument: _org_dash_platform_dapi_v0_GetProtocolVersionUpgradeVoteStatusRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetProtocolVersionUpgradeVoteStatusResponse__Output>): grpc.ClientUnaryCall;
  getProtocolVersionUpgradeVoteStatus(argument: _org_dash_platform_dapi_v0_GetProtocolVersionUpgradeVoteStatusRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetProtocolVersionUpgradeVoteStatusResponse__Output>): grpc.ClientUnaryCall;
  getProtocolVersionUpgradeVoteStatus(argument: _org_dash_platform_dapi_v0_GetProtocolVersionUpgradeVoteStatusRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetProtocolVersionUpgradeVoteStatusResponse__Output>): grpc.ClientUnaryCall;
  getProtocolVersionUpgradeVoteStatus(argument: _org_dash_platform_dapi_v0_GetProtocolVersionUpgradeVoteStatusRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetProtocolVersionUpgradeVoteStatusResponse__Output>): grpc.ClientUnaryCall;
  
  getStatus(argument: _org_dash_platform_dapi_v0_GetStatusRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetStatusResponse__Output>): grpc.ClientUnaryCall;
  getStatus(argument: _org_dash_platform_dapi_v0_GetStatusRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetStatusResponse__Output>): grpc.ClientUnaryCall;
  getStatus(argument: _org_dash_platform_dapi_v0_GetStatusRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetStatusResponse__Output>): grpc.ClientUnaryCall;
  getStatus(argument: _org_dash_platform_dapi_v0_GetStatusRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetStatusResponse__Output>): grpc.ClientUnaryCall;
  
  getTokenPreProgrammedDistributions(argument: _org_dash_platform_dapi_v0_GetTokenPreProgrammedDistributionsRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetTokenPreProgrammedDistributionsResponse__Output>): grpc.ClientUnaryCall;
  getTokenPreProgrammedDistributions(argument: _org_dash_platform_dapi_v0_GetTokenPreProgrammedDistributionsRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetTokenPreProgrammedDistributionsResponse__Output>): grpc.ClientUnaryCall;
  getTokenPreProgrammedDistributions(argument: _org_dash_platform_dapi_v0_GetTokenPreProgrammedDistributionsRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetTokenPreProgrammedDistributionsResponse__Output>): grpc.ClientUnaryCall;
  getTokenPreProgrammedDistributions(argument: _org_dash_platform_dapi_v0_GetTokenPreProgrammedDistributionsRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetTokenPreProgrammedDistributionsResponse__Output>): grpc.ClientUnaryCall;
  
  getTokenStatuses(argument: _org_dash_platform_dapi_v0_GetTokenStatusesRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetTokenStatusesResponse__Output>): grpc.ClientUnaryCall;
  getTokenStatuses(argument: _org_dash_platform_dapi_v0_GetTokenStatusesRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetTokenStatusesResponse__Output>): grpc.ClientUnaryCall;
  getTokenStatuses(argument: _org_dash_platform_dapi_v0_GetTokenStatusesRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetTokenStatusesResponse__Output>): grpc.ClientUnaryCall;
  getTokenStatuses(argument: _org_dash_platform_dapi_v0_GetTokenStatusesRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetTokenStatusesResponse__Output>): grpc.ClientUnaryCall;
  
  getTokenTotalSupply(argument: _org_dash_platform_dapi_v0_GetTokenTotalSupplyRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetTokenTotalSupplyResponse__Output>): grpc.ClientUnaryCall;
  getTokenTotalSupply(argument: _org_dash_platform_dapi_v0_GetTokenTotalSupplyRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetTokenTotalSupplyResponse__Output>): grpc.ClientUnaryCall;
  getTokenTotalSupply(argument: _org_dash_platform_dapi_v0_GetTokenTotalSupplyRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetTokenTotalSupplyResponse__Output>): grpc.ClientUnaryCall;
  getTokenTotalSupply(argument: _org_dash_platform_dapi_v0_GetTokenTotalSupplyRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetTokenTotalSupplyResponse__Output>): grpc.ClientUnaryCall;
  
  getTotalCreditsInPlatform(argument: _org_dash_platform_dapi_v0_GetTotalCreditsInPlatformRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetTotalCreditsInPlatformResponse__Output>): grpc.ClientUnaryCall;
  getTotalCreditsInPlatform(argument: _org_dash_platform_dapi_v0_GetTotalCreditsInPlatformRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetTotalCreditsInPlatformResponse__Output>): grpc.ClientUnaryCall;
  getTotalCreditsInPlatform(argument: _org_dash_platform_dapi_v0_GetTotalCreditsInPlatformRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetTotalCreditsInPlatformResponse__Output>): grpc.ClientUnaryCall;
  getTotalCreditsInPlatform(argument: _org_dash_platform_dapi_v0_GetTotalCreditsInPlatformRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetTotalCreditsInPlatformResponse__Output>): grpc.ClientUnaryCall;
  
  getVotePollsByEndDate(argument: _org_dash_platform_dapi_v0_GetVotePollsByEndDateRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetVotePollsByEndDateResponse__Output>): grpc.ClientUnaryCall;
  getVotePollsByEndDate(argument: _org_dash_platform_dapi_v0_GetVotePollsByEndDateRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetVotePollsByEndDateResponse__Output>): grpc.ClientUnaryCall;
  getVotePollsByEndDate(argument: _org_dash_platform_dapi_v0_GetVotePollsByEndDateRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetVotePollsByEndDateResponse__Output>): grpc.ClientUnaryCall;
  getVotePollsByEndDate(argument: _org_dash_platform_dapi_v0_GetVotePollsByEndDateRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_GetVotePollsByEndDateResponse__Output>): grpc.ClientUnaryCall;
  
  waitForStateTransitionResult(argument: _org_dash_platform_dapi_v0_WaitForStateTransitionResultRequest, metadata: grpc.Metadata, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_WaitForStateTransitionResultResponse__Output>): grpc.ClientUnaryCall;
  waitForStateTransitionResult(argument: _org_dash_platform_dapi_v0_WaitForStateTransitionResultRequest, metadata: grpc.Metadata, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_WaitForStateTransitionResultResponse__Output>): grpc.ClientUnaryCall;
  waitForStateTransitionResult(argument: _org_dash_platform_dapi_v0_WaitForStateTransitionResultRequest, options: grpc.CallOptions, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_WaitForStateTransitionResultResponse__Output>): grpc.ClientUnaryCall;
  waitForStateTransitionResult(argument: _org_dash_platform_dapi_v0_WaitForStateTransitionResultRequest, callback: grpc.requestCallback<_org_dash_platform_dapi_v0_WaitForStateTransitionResultResponse__Output>): grpc.ClientUnaryCall;
  
}

export interface PlatformHandlers extends grpc.UntypedServiceImplementation {
  broadcastStateTransition: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_BroadcastStateTransitionRequest__Output, _org_dash_platform_dapi_v0_BroadcastStateTransitionResponse>;
  
  getConsensusParams: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetConsensusParamsRequest__Output, _org_dash_platform_dapi_v0_GetConsensusParamsResponse>;
  
  getContestedResourceIdentityVotes: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesRequest__Output, _org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesResponse>;
  
  getContestedResourceVoteState: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetContestedResourceVoteStateRequest__Output, _org_dash_platform_dapi_v0_GetContestedResourceVoteStateResponse>;
  
  getContestedResourceVotersForIdentity: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetContestedResourceVotersForIdentityRequest__Output, _org_dash_platform_dapi_v0_GetContestedResourceVotersForIdentityResponse>;
  
  getContestedResources: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetContestedResourcesRequest__Output, _org_dash_platform_dapi_v0_GetContestedResourcesResponse>;
  
  getCurrentQuorumsInfo: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetCurrentQuorumsInfoRequest__Output, _org_dash_platform_dapi_v0_GetCurrentQuorumsInfoResponse>;
  
  getDataContract: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetDataContractRequest__Output, _org_dash_platform_dapi_v0_GetDataContractResponse>;
  
  getDataContractHistory: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetDataContractHistoryRequest__Output, _org_dash_platform_dapi_v0_GetDataContractHistoryResponse>;
  
  getDataContracts: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetDataContractsRequest__Output, _org_dash_platform_dapi_v0_GetDataContractsResponse>;
  
  getDocuments: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetDocumentsRequest__Output, _org_dash_platform_dapi_v0_GetDocumentsResponse>;
  
  getEpochsInfo: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetEpochsInfoRequest__Output, _org_dash_platform_dapi_v0_GetEpochsInfoResponse>;
  
  getEvonodesProposedEpochBlocksByIds: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksByIdsRequest__Output, _org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksResponse>;
  
  getEvonodesProposedEpochBlocksByRange: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksByRangeRequest__Output, _org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksResponse>;
  
  getGroupActionSigners: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetGroupActionSignersRequest__Output, _org_dash_platform_dapi_v0_GetGroupActionSignersResponse>;
  
  getGroupActions: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetGroupActionsRequest__Output, _org_dash_platform_dapi_v0_GetGroupActionsResponse>;
  
  getGroupInfo: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetGroupInfoRequest__Output, _org_dash_platform_dapi_v0_GetGroupInfoResponse>;
  
  getGroupInfos: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetGroupInfosRequest__Output, _org_dash_platform_dapi_v0_GetGroupInfosResponse>;
  
  getIdentitiesBalances: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetIdentitiesBalancesRequest__Output, _org_dash_platform_dapi_v0_GetIdentitiesBalancesResponse>;
  
  getIdentitiesContractKeys: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetIdentitiesContractKeysRequest__Output, _org_dash_platform_dapi_v0_GetIdentitiesContractKeysResponse>;
  
  getIdentitiesTokenBalances: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetIdentitiesTokenBalancesRequest__Output, _org_dash_platform_dapi_v0_GetIdentitiesTokenBalancesResponse>;
  
  getIdentitiesTokenInfos: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetIdentitiesTokenInfosRequest__Output, _org_dash_platform_dapi_v0_GetIdentitiesTokenInfosResponse>;
  
  getIdentity: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetIdentityRequest__Output, _org_dash_platform_dapi_v0_GetIdentityResponse>;
  
  getIdentityBalance: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetIdentityBalanceRequest__Output, _org_dash_platform_dapi_v0_GetIdentityBalanceResponse>;
  
  getIdentityBalanceAndRevision: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetIdentityBalanceAndRevisionRequest__Output, _org_dash_platform_dapi_v0_GetIdentityBalanceAndRevisionResponse>;
  
  getIdentityByPublicKeyHash: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetIdentityByPublicKeyHashRequest__Output, _org_dash_platform_dapi_v0_GetIdentityByPublicKeyHashResponse>;
  
  getIdentityContractNonce: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetIdentityContractNonceRequest__Output, _org_dash_platform_dapi_v0_GetIdentityContractNonceResponse>;
  
  getIdentityKeys: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetIdentityKeysRequest__Output, _org_dash_platform_dapi_v0_GetIdentityKeysResponse>;
  
  getIdentityNonce: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetIdentityNonceRequest__Output, _org_dash_platform_dapi_v0_GetIdentityNonceResponse>;
  
  getIdentityTokenBalances: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetIdentityTokenBalancesRequest__Output, _org_dash_platform_dapi_v0_GetIdentityTokenBalancesResponse>;
  
  getIdentityTokenInfos: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetIdentityTokenInfosRequest__Output, _org_dash_platform_dapi_v0_GetIdentityTokenInfosResponse>;
  
  getPathElements: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetPathElementsRequest__Output, _org_dash_platform_dapi_v0_GetPathElementsResponse>;
  
  getPrefundedSpecializedBalance: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetPrefundedSpecializedBalanceRequest__Output, _org_dash_platform_dapi_v0_GetPrefundedSpecializedBalanceResponse>;
  
  getProofs: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetProofsRequest__Output, _org_dash_platform_dapi_v0_GetProofsResponse>;
  
  getProtocolVersionUpgradeState: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetProtocolVersionUpgradeStateRequest__Output, _org_dash_platform_dapi_v0_GetProtocolVersionUpgradeStateResponse>;
  
  getProtocolVersionUpgradeVoteStatus: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetProtocolVersionUpgradeVoteStatusRequest__Output, _org_dash_platform_dapi_v0_GetProtocolVersionUpgradeVoteStatusResponse>;
  
  getStatus: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetStatusRequest__Output, _org_dash_platform_dapi_v0_GetStatusResponse>;
  
  getTokenPreProgrammedDistributions: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetTokenPreProgrammedDistributionsRequest__Output, _org_dash_platform_dapi_v0_GetTokenPreProgrammedDistributionsResponse>;
  
  getTokenStatuses: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetTokenStatusesRequest__Output, _org_dash_platform_dapi_v0_GetTokenStatusesResponse>;
  
  getTokenTotalSupply: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetTokenTotalSupplyRequest__Output, _org_dash_platform_dapi_v0_GetTokenTotalSupplyResponse>;
  
  getTotalCreditsInPlatform: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetTotalCreditsInPlatformRequest__Output, _org_dash_platform_dapi_v0_GetTotalCreditsInPlatformResponse>;
  
  getVotePollsByEndDate: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_GetVotePollsByEndDateRequest__Output, _org_dash_platform_dapi_v0_GetVotePollsByEndDateResponse>;
  
  waitForStateTransitionResult: grpc.handleUnaryCall<_org_dash_platform_dapi_v0_WaitForStateTransitionResultRequest__Output, _org_dash_platform_dapi_v0_WaitForStateTransitionResultResponse>;
  
}

export interface PlatformDefinition extends grpc.ServiceDefinition {
  broadcastStateTransition: MethodDefinition<_org_dash_platform_dapi_v0_BroadcastStateTransitionRequest, _org_dash_platform_dapi_v0_BroadcastStateTransitionResponse, _org_dash_platform_dapi_v0_BroadcastStateTransitionRequest__Output, _org_dash_platform_dapi_v0_BroadcastStateTransitionResponse__Output>
  getConsensusParams: MethodDefinition<_org_dash_platform_dapi_v0_GetConsensusParamsRequest, _org_dash_platform_dapi_v0_GetConsensusParamsResponse, _org_dash_platform_dapi_v0_GetConsensusParamsRequest__Output, _org_dash_platform_dapi_v0_GetConsensusParamsResponse__Output>
  getContestedResourceIdentityVotes: MethodDefinition<_org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesRequest, _org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesResponse, _org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesRequest__Output, _org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesResponse__Output>
  getContestedResourceVoteState: MethodDefinition<_org_dash_platform_dapi_v0_GetContestedResourceVoteStateRequest, _org_dash_platform_dapi_v0_GetContestedResourceVoteStateResponse, _org_dash_platform_dapi_v0_GetContestedResourceVoteStateRequest__Output, _org_dash_platform_dapi_v0_GetContestedResourceVoteStateResponse__Output>
  getContestedResourceVotersForIdentity: MethodDefinition<_org_dash_platform_dapi_v0_GetContestedResourceVotersForIdentityRequest, _org_dash_platform_dapi_v0_GetContestedResourceVotersForIdentityResponse, _org_dash_platform_dapi_v0_GetContestedResourceVotersForIdentityRequest__Output, _org_dash_platform_dapi_v0_GetContestedResourceVotersForIdentityResponse__Output>
  getContestedResources: MethodDefinition<_org_dash_platform_dapi_v0_GetContestedResourcesRequest, _org_dash_platform_dapi_v0_GetContestedResourcesResponse, _org_dash_platform_dapi_v0_GetContestedResourcesRequest__Output, _org_dash_platform_dapi_v0_GetContestedResourcesResponse__Output>
  getCurrentQuorumsInfo: MethodDefinition<_org_dash_platform_dapi_v0_GetCurrentQuorumsInfoRequest, _org_dash_platform_dapi_v0_GetCurrentQuorumsInfoResponse, _org_dash_platform_dapi_v0_GetCurrentQuorumsInfoRequest__Output, _org_dash_platform_dapi_v0_GetCurrentQuorumsInfoResponse__Output>
  getDataContract: MethodDefinition<_org_dash_platform_dapi_v0_GetDataContractRequest, _org_dash_platform_dapi_v0_GetDataContractResponse, _org_dash_platform_dapi_v0_GetDataContractRequest__Output, _org_dash_platform_dapi_v0_GetDataContractResponse__Output>
  getDataContractHistory: MethodDefinition<_org_dash_platform_dapi_v0_GetDataContractHistoryRequest, _org_dash_platform_dapi_v0_GetDataContractHistoryResponse, _org_dash_platform_dapi_v0_GetDataContractHistoryRequest__Output, _org_dash_platform_dapi_v0_GetDataContractHistoryResponse__Output>
  getDataContracts: MethodDefinition<_org_dash_platform_dapi_v0_GetDataContractsRequest, _org_dash_platform_dapi_v0_GetDataContractsResponse, _org_dash_platform_dapi_v0_GetDataContractsRequest__Output, _org_dash_platform_dapi_v0_GetDataContractsResponse__Output>
  getDocuments: MethodDefinition<_org_dash_platform_dapi_v0_GetDocumentsRequest, _org_dash_platform_dapi_v0_GetDocumentsResponse, _org_dash_platform_dapi_v0_GetDocumentsRequest__Output, _org_dash_platform_dapi_v0_GetDocumentsResponse__Output>
  getEpochsInfo: MethodDefinition<_org_dash_platform_dapi_v0_GetEpochsInfoRequest, _org_dash_platform_dapi_v0_GetEpochsInfoResponse, _org_dash_platform_dapi_v0_GetEpochsInfoRequest__Output, _org_dash_platform_dapi_v0_GetEpochsInfoResponse__Output>
  getEvonodesProposedEpochBlocksByIds: MethodDefinition<_org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksByIdsRequest, _org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksResponse, _org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksByIdsRequest__Output, _org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksResponse__Output>
  getEvonodesProposedEpochBlocksByRange: MethodDefinition<_org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksByRangeRequest, _org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksResponse, _org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksByRangeRequest__Output, _org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksResponse__Output>
  getGroupActionSigners: MethodDefinition<_org_dash_platform_dapi_v0_GetGroupActionSignersRequest, _org_dash_platform_dapi_v0_GetGroupActionSignersResponse, _org_dash_platform_dapi_v0_GetGroupActionSignersRequest__Output, _org_dash_platform_dapi_v0_GetGroupActionSignersResponse__Output>
  getGroupActions: MethodDefinition<_org_dash_platform_dapi_v0_GetGroupActionsRequest, _org_dash_platform_dapi_v0_GetGroupActionsResponse, _org_dash_platform_dapi_v0_GetGroupActionsRequest__Output, _org_dash_platform_dapi_v0_GetGroupActionsResponse__Output>
  getGroupInfo: MethodDefinition<_org_dash_platform_dapi_v0_GetGroupInfoRequest, _org_dash_platform_dapi_v0_GetGroupInfoResponse, _org_dash_platform_dapi_v0_GetGroupInfoRequest__Output, _org_dash_platform_dapi_v0_GetGroupInfoResponse__Output>
  getGroupInfos: MethodDefinition<_org_dash_platform_dapi_v0_GetGroupInfosRequest, _org_dash_platform_dapi_v0_GetGroupInfosResponse, _org_dash_platform_dapi_v0_GetGroupInfosRequest__Output, _org_dash_platform_dapi_v0_GetGroupInfosResponse__Output>
  getIdentitiesBalances: MethodDefinition<_org_dash_platform_dapi_v0_GetIdentitiesBalancesRequest, _org_dash_platform_dapi_v0_GetIdentitiesBalancesResponse, _org_dash_platform_dapi_v0_GetIdentitiesBalancesRequest__Output, _org_dash_platform_dapi_v0_GetIdentitiesBalancesResponse__Output>
  getIdentitiesContractKeys: MethodDefinition<_org_dash_platform_dapi_v0_GetIdentitiesContractKeysRequest, _org_dash_platform_dapi_v0_GetIdentitiesContractKeysResponse, _org_dash_platform_dapi_v0_GetIdentitiesContractKeysRequest__Output, _org_dash_platform_dapi_v0_GetIdentitiesContractKeysResponse__Output>
  getIdentitiesTokenBalances: MethodDefinition<_org_dash_platform_dapi_v0_GetIdentitiesTokenBalancesRequest, _org_dash_platform_dapi_v0_GetIdentitiesTokenBalancesResponse, _org_dash_platform_dapi_v0_GetIdentitiesTokenBalancesRequest__Output, _org_dash_platform_dapi_v0_GetIdentitiesTokenBalancesResponse__Output>
  getIdentitiesTokenInfos: MethodDefinition<_org_dash_platform_dapi_v0_GetIdentitiesTokenInfosRequest, _org_dash_platform_dapi_v0_GetIdentitiesTokenInfosResponse, _org_dash_platform_dapi_v0_GetIdentitiesTokenInfosRequest__Output, _org_dash_platform_dapi_v0_GetIdentitiesTokenInfosResponse__Output>
  getIdentity: MethodDefinition<_org_dash_platform_dapi_v0_GetIdentityRequest, _org_dash_platform_dapi_v0_GetIdentityResponse, _org_dash_platform_dapi_v0_GetIdentityRequest__Output, _org_dash_platform_dapi_v0_GetIdentityResponse__Output>
  getIdentityBalance: MethodDefinition<_org_dash_platform_dapi_v0_GetIdentityBalanceRequest, _org_dash_platform_dapi_v0_GetIdentityBalanceResponse, _org_dash_platform_dapi_v0_GetIdentityBalanceRequest__Output, _org_dash_platform_dapi_v0_GetIdentityBalanceResponse__Output>
  getIdentityBalanceAndRevision: MethodDefinition<_org_dash_platform_dapi_v0_GetIdentityBalanceAndRevisionRequest, _org_dash_platform_dapi_v0_GetIdentityBalanceAndRevisionResponse, _org_dash_platform_dapi_v0_GetIdentityBalanceAndRevisionRequest__Output, _org_dash_platform_dapi_v0_GetIdentityBalanceAndRevisionResponse__Output>
  getIdentityByPublicKeyHash: MethodDefinition<_org_dash_platform_dapi_v0_GetIdentityByPublicKeyHashRequest, _org_dash_platform_dapi_v0_GetIdentityByPublicKeyHashResponse, _org_dash_platform_dapi_v0_GetIdentityByPublicKeyHashRequest__Output, _org_dash_platform_dapi_v0_GetIdentityByPublicKeyHashResponse__Output>
  getIdentityContractNonce: MethodDefinition<_org_dash_platform_dapi_v0_GetIdentityContractNonceRequest, _org_dash_platform_dapi_v0_GetIdentityContractNonceResponse, _org_dash_platform_dapi_v0_GetIdentityContractNonceRequest__Output, _org_dash_platform_dapi_v0_GetIdentityContractNonceResponse__Output>
  getIdentityKeys: MethodDefinition<_org_dash_platform_dapi_v0_GetIdentityKeysRequest, _org_dash_platform_dapi_v0_GetIdentityKeysResponse, _org_dash_platform_dapi_v0_GetIdentityKeysRequest__Output, _org_dash_platform_dapi_v0_GetIdentityKeysResponse__Output>
  getIdentityNonce: MethodDefinition<_org_dash_platform_dapi_v0_GetIdentityNonceRequest, _org_dash_platform_dapi_v0_GetIdentityNonceResponse, _org_dash_platform_dapi_v0_GetIdentityNonceRequest__Output, _org_dash_platform_dapi_v0_GetIdentityNonceResponse__Output>
  getIdentityTokenBalances: MethodDefinition<_org_dash_platform_dapi_v0_GetIdentityTokenBalancesRequest, _org_dash_platform_dapi_v0_GetIdentityTokenBalancesResponse, _org_dash_platform_dapi_v0_GetIdentityTokenBalancesRequest__Output, _org_dash_platform_dapi_v0_GetIdentityTokenBalancesResponse__Output>
  getIdentityTokenInfos: MethodDefinition<_org_dash_platform_dapi_v0_GetIdentityTokenInfosRequest, _org_dash_platform_dapi_v0_GetIdentityTokenInfosResponse, _org_dash_platform_dapi_v0_GetIdentityTokenInfosRequest__Output, _org_dash_platform_dapi_v0_GetIdentityTokenInfosResponse__Output>
  getPathElements: MethodDefinition<_org_dash_platform_dapi_v0_GetPathElementsRequest, _org_dash_platform_dapi_v0_GetPathElementsResponse, _org_dash_platform_dapi_v0_GetPathElementsRequest__Output, _org_dash_platform_dapi_v0_GetPathElementsResponse__Output>
  getPrefundedSpecializedBalance: MethodDefinition<_org_dash_platform_dapi_v0_GetPrefundedSpecializedBalanceRequest, _org_dash_platform_dapi_v0_GetPrefundedSpecializedBalanceResponse, _org_dash_platform_dapi_v0_GetPrefundedSpecializedBalanceRequest__Output, _org_dash_platform_dapi_v0_GetPrefundedSpecializedBalanceResponse__Output>
  getProofs: MethodDefinition<_org_dash_platform_dapi_v0_GetProofsRequest, _org_dash_platform_dapi_v0_GetProofsResponse, _org_dash_platform_dapi_v0_GetProofsRequest__Output, _org_dash_platform_dapi_v0_GetProofsResponse__Output>
  getProtocolVersionUpgradeState: MethodDefinition<_org_dash_platform_dapi_v0_GetProtocolVersionUpgradeStateRequest, _org_dash_platform_dapi_v0_GetProtocolVersionUpgradeStateResponse, _org_dash_platform_dapi_v0_GetProtocolVersionUpgradeStateRequest__Output, _org_dash_platform_dapi_v0_GetProtocolVersionUpgradeStateResponse__Output>
  getProtocolVersionUpgradeVoteStatus: MethodDefinition<_org_dash_platform_dapi_v0_GetProtocolVersionUpgradeVoteStatusRequest, _org_dash_platform_dapi_v0_GetProtocolVersionUpgradeVoteStatusResponse, _org_dash_platform_dapi_v0_GetProtocolVersionUpgradeVoteStatusRequest__Output, _org_dash_platform_dapi_v0_GetProtocolVersionUpgradeVoteStatusResponse__Output>
  getStatus: MethodDefinition<_org_dash_platform_dapi_v0_GetStatusRequest, _org_dash_platform_dapi_v0_GetStatusResponse, _org_dash_platform_dapi_v0_GetStatusRequest__Output, _org_dash_platform_dapi_v0_GetStatusResponse__Output>
  getTokenPreProgrammedDistributions: MethodDefinition<_org_dash_platform_dapi_v0_GetTokenPreProgrammedDistributionsRequest, _org_dash_platform_dapi_v0_GetTokenPreProgrammedDistributionsResponse, _org_dash_platform_dapi_v0_GetTokenPreProgrammedDistributionsRequest__Output, _org_dash_platform_dapi_v0_GetTokenPreProgrammedDistributionsResponse__Output>
  getTokenStatuses: MethodDefinition<_org_dash_platform_dapi_v0_GetTokenStatusesRequest, _org_dash_platform_dapi_v0_GetTokenStatusesResponse, _org_dash_platform_dapi_v0_GetTokenStatusesRequest__Output, _org_dash_platform_dapi_v0_GetTokenStatusesResponse__Output>
  getTokenTotalSupply: MethodDefinition<_org_dash_platform_dapi_v0_GetTokenTotalSupplyRequest, _org_dash_platform_dapi_v0_GetTokenTotalSupplyResponse, _org_dash_platform_dapi_v0_GetTokenTotalSupplyRequest__Output, _org_dash_platform_dapi_v0_GetTokenTotalSupplyResponse__Output>
  getTotalCreditsInPlatform: MethodDefinition<_org_dash_platform_dapi_v0_GetTotalCreditsInPlatformRequest, _org_dash_platform_dapi_v0_GetTotalCreditsInPlatformResponse, _org_dash_platform_dapi_v0_GetTotalCreditsInPlatformRequest__Output, _org_dash_platform_dapi_v0_GetTotalCreditsInPlatformResponse__Output>
  getVotePollsByEndDate: MethodDefinition<_org_dash_platform_dapi_v0_GetVotePollsByEndDateRequest, _org_dash_platform_dapi_v0_GetVotePollsByEndDateResponse, _org_dash_platform_dapi_v0_GetVotePollsByEndDateRequest__Output, _org_dash_platform_dapi_v0_GetVotePollsByEndDateResponse__Output>
  waitForStateTransitionResult: MethodDefinition<_org_dash_platform_dapi_v0_WaitForStateTransitionResultRequest, _org_dash_platform_dapi_v0_WaitForStateTransitionResultResponse, _org_dash_platform_dapi_v0_WaitForStateTransitionResultRequest__Output, _org_dash_platform_dapi_v0_WaitForStateTransitionResultResponse__Output>
}
