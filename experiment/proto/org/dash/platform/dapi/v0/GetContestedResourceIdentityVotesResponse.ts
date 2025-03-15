// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

import type { Proof as _org_dash_platform_dapi_v0_Proof, Proof__Output as _org_dash_platform_dapi_v0_Proof__Output } from '../../../../../org/dash/platform/dapi/v0/Proof';
import type { ResponseMetadata as _org_dash_platform_dapi_v0_ResponseMetadata, ResponseMetadata__Output as _org_dash_platform_dapi_v0_ResponseMetadata__Output } from '../../../../../org/dash/platform/dapi/v0/ResponseMetadata';

export interface _org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0_ContestedResourceIdentityVote {
  'contractId'?: (Buffer | Uint8Array | string);
  'documentTypeName'?: (string);
  'serializedIndexStorageValues'?: (Buffer | Uint8Array | string)[];
  'voteChoice'?: (_org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0_ResourceVoteChoice | null);
}

export interface _org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0_ContestedResourceIdentityVote__Output {
  'contractId': (Buffer);
  'documentTypeName': (string);
  'serializedIndexStorageValues': (Buffer)[];
  'voteChoice': (_org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0_ResourceVoteChoice__Output | null);
}

export interface _org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0_ContestedResourceIdentityVotes {
  'contestedResourceIdentityVotes'?: (_org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0_ContestedResourceIdentityVote)[];
  'finishedResults'?: (boolean);
}

export interface _org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0_ContestedResourceIdentityVotes__Output {
  'contestedResourceIdentityVotes': (_org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0_ContestedResourceIdentityVote__Output)[];
  'finishedResults': (boolean);
}

export interface _org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0 {
  'votes'?: (_org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0_ContestedResourceIdentityVotes | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof | null);
  'metadata'?: (_org_dash_platform_dapi_v0_ResponseMetadata | null);
  'result'?: "votes"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0__Output {
  'votes'?: (_org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0_ContestedResourceIdentityVotes__Output | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof__Output | null);
  'metadata': (_org_dash_platform_dapi_v0_ResponseMetadata__Output | null);
  'result': "votes"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0_ResourceVoteChoice {
  'voteChoiceType'?: (_org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0_ResourceVoteChoice_VoteChoiceType);
  'identityId'?: (Buffer | Uint8Array | string);
  '_identityId'?: "identityId";
}

export interface _org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0_ResourceVoteChoice__Output {
  'voteChoiceType': (_org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0_ResourceVoteChoice_VoteChoiceType__Output);
  'identityId'?: (Buffer);
  '_identityId': "identityId";
}

// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

export const _org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0_ResourceVoteChoice_VoteChoiceType = {
  TOWARDS_IDENTITY: 'TOWARDS_IDENTITY',
  ABSTAIN: 'ABSTAIN',
  LOCK: 'LOCK',
} as const;

export type _org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0_ResourceVoteChoice_VoteChoiceType =
  | 'TOWARDS_IDENTITY'
  | 0
  | 'ABSTAIN'
  | 1
  | 'LOCK'
  | 2

export type _org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0_ResourceVoteChoice_VoteChoiceType__Output = typeof _org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0_ResourceVoteChoice_VoteChoiceType[keyof typeof _org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0_ResourceVoteChoice_VoteChoiceType]

export interface GetContestedResourceIdentityVotesResponse {
  'v0'?: (_org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0 | null);
  'version'?: "v0";
}

export interface GetContestedResourceIdentityVotesResponse__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesResponse_GetContestedResourceIdentityVotesResponseV0__Output | null);
  'version': "v0";
}
