// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

import type { Proof as _org_dash_platform_dapi_v0_Proof, Proof__Output as _org_dash_platform_dapi_v0_Proof__Output } from '../../../../../org/dash/platform/dapi/v0/Proof';
import type { ResponseMetadata as _org_dash_platform_dapi_v0_ResponseMetadata, ResponseMetadata__Output as _org_dash_platform_dapi_v0_ResponseMetadata__Output } from '../../../../../org/dash/platform/dapi/v0/ResponseMetadata';
import type { Long } from '@grpc/proto-loader';

export interface _org_dash_platform_dapi_v0_GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0_Contender {
  'identifier'?: (Buffer | Uint8Array | string);
  'voteCount'?: (number);
  'document'?: (Buffer | Uint8Array | string);
  '_voteCount'?: "voteCount";
  '_document'?: "document";
}

export interface _org_dash_platform_dapi_v0_GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0_Contender__Output {
  'identifier': (Buffer);
  'voteCount'?: (number);
  'document'?: (Buffer);
  '_voteCount': "voteCount";
  '_document': "document";
}

export interface _org_dash_platform_dapi_v0_GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0_ContestedResourceContenders {
  'contenders'?: (_org_dash_platform_dapi_v0_GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0_Contender)[];
  'abstainVoteTally'?: (number);
  'lockVoteTally'?: (number);
  'finishedVoteInfo'?: (_org_dash_platform_dapi_v0_GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0_FinishedVoteInfo | null);
  '_abstainVoteTally'?: "abstainVoteTally";
  '_lockVoteTally'?: "lockVoteTally";
  '_finishedVoteInfo'?: "finishedVoteInfo";
}

export interface _org_dash_platform_dapi_v0_GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0_ContestedResourceContenders__Output {
  'contenders': (_org_dash_platform_dapi_v0_GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0_Contender__Output)[];
  'abstainVoteTally'?: (number);
  'lockVoteTally'?: (number);
  'finishedVoteInfo'?: (_org_dash_platform_dapi_v0_GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0_FinishedVoteInfo__Output | null);
  '_abstainVoteTally': "abstainVoteTally";
  '_lockVoteTally': "lockVoteTally";
  '_finishedVoteInfo': "finishedVoteInfo";
}

export interface _org_dash_platform_dapi_v0_GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0_FinishedVoteInfo {
  'finishedVoteOutcome'?: (_org_dash_platform_dapi_v0_GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0_FinishedVoteInfo_FinishedVoteOutcome);
  'wonByIdentityId'?: (Buffer | Uint8Array | string);
  'finishedAtBlockHeight'?: (number | string | Long);
  'finishedAtCoreBlockHeight'?: (number);
  'finishedAtBlockTimeMs'?: (number | string | Long);
  'finishedAtEpoch'?: (number);
  '_wonByIdentityId'?: "wonByIdentityId";
}

export interface _org_dash_platform_dapi_v0_GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0_FinishedVoteInfo__Output {
  'finishedVoteOutcome': (_org_dash_platform_dapi_v0_GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0_FinishedVoteInfo_FinishedVoteOutcome__Output);
  'wonByIdentityId'?: (Buffer);
  'finishedAtBlockHeight': (string);
  'finishedAtCoreBlockHeight': (number);
  'finishedAtBlockTimeMs': (string);
  'finishedAtEpoch': (number);
  '_wonByIdentityId': "wonByIdentityId";
}

// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

export const _org_dash_platform_dapi_v0_GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0_FinishedVoteInfo_FinishedVoteOutcome = {
  TOWARDS_IDENTITY: 'TOWARDS_IDENTITY',
  LOCKED: 'LOCKED',
  NO_PREVIOUS_WINNER: 'NO_PREVIOUS_WINNER',
} as const;

export type _org_dash_platform_dapi_v0_GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0_FinishedVoteInfo_FinishedVoteOutcome =
  | 'TOWARDS_IDENTITY'
  | 0
  | 'LOCKED'
  | 1
  | 'NO_PREVIOUS_WINNER'
  | 2

export type _org_dash_platform_dapi_v0_GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0_FinishedVoteInfo_FinishedVoteOutcome__Output = typeof _org_dash_platform_dapi_v0_GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0_FinishedVoteInfo_FinishedVoteOutcome[keyof typeof _org_dash_platform_dapi_v0_GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0_FinishedVoteInfo_FinishedVoteOutcome]

export interface _org_dash_platform_dapi_v0_GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0 {
  'contestedResourceContenders'?: (_org_dash_platform_dapi_v0_GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0_ContestedResourceContenders | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof | null);
  'metadata'?: (_org_dash_platform_dapi_v0_ResponseMetadata | null);
  'result'?: "contestedResourceContenders"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0__Output {
  'contestedResourceContenders'?: (_org_dash_platform_dapi_v0_GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0_ContestedResourceContenders__Output | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof__Output | null);
  'metadata': (_org_dash_platform_dapi_v0_ResponseMetadata__Output | null);
  'result': "contestedResourceContenders"|"proof";
}

export interface GetContestedResourceVoteStateResponse {
  'v0'?: (_org_dash_platform_dapi_v0_GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0 | null);
  'version'?: "v0";
}

export interface GetContestedResourceVoteStateResponse__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetContestedResourceVoteStateResponse_GetContestedResourceVoteStateResponseV0__Output | null);
  'version': "v0";
}
