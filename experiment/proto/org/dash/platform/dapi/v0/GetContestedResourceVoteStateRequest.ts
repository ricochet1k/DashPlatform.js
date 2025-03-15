// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto


export interface _org_dash_platform_dapi_v0_GetContestedResourceVoteStateRequest_GetContestedResourceVoteStateRequestV0 {
  'contractId'?: (Buffer | Uint8Array | string);
  'documentTypeName'?: (string);
  'indexName'?: (string);
  'indexValues'?: (Buffer | Uint8Array | string)[];
  'resultType'?: (_org_dash_platform_dapi_v0_GetContestedResourceVoteStateRequest_GetContestedResourceVoteStateRequestV0_ResultType);
  'allowIncludeLockedAndAbstainingVoteTally'?: (boolean);
  'startAtIdentifierInfo'?: (_org_dash_platform_dapi_v0_GetContestedResourceVoteStateRequest_GetContestedResourceVoteStateRequestV0_StartAtIdentifierInfo | null);
  'count'?: (number);
  'prove'?: (boolean);
  '_startAtIdentifierInfo'?: "startAtIdentifierInfo";
  '_count'?: "count";
}

export interface _org_dash_platform_dapi_v0_GetContestedResourceVoteStateRequest_GetContestedResourceVoteStateRequestV0__Output {
  'contractId': (Buffer);
  'documentTypeName': (string);
  'indexName': (string);
  'indexValues': (Buffer)[];
  'resultType': (_org_dash_platform_dapi_v0_GetContestedResourceVoteStateRequest_GetContestedResourceVoteStateRequestV0_ResultType__Output);
  'allowIncludeLockedAndAbstainingVoteTally': (boolean);
  'startAtIdentifierInfo'?: (_org_dash_platform_dapi_v0_GetContestedResourceVoteStateRequest_GetContestedResourceVoteStateRequestV0_StartAtIdentifierInfo__Output | null);
  'count'?: (number);
  'prove': (boolean);
  '_startAtIdentifierInfo': "startAtIdentifierInfo";
  '_count': "count";
}

// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

export const _org_dash_platform_dapi_v0_GetContestedResourceVoteStateRequest_GetContestedResourceVoteStateRequestV0_ResultType = {
  DOCUMENTS: 'DOCUMENTS',
  VOTE_TALLY: 'VOTE_TALLY',
  DOCUMENTS_AND_VOTE_TALLY: 'DOCUMENTS_AND_VOTE_TALLY',
} as const;

export type _org_dash_platform_dapi_v0_GetContestedResourceVoteStateRequest_GetContestedResourceVoteStateRequestV0_ResultType =
  | 'DOCUMENTS'
  | 0
  | 'VOTE_TALLY'
  | 1
  | 'DOCUMENTS_AND_VOTE_TALLY'
  | 2

export type _org_dash_platform_dapi_v0_GetContestedResourceVoteStateRequest_GetContestedResourceVoteStateRequestV0_ResultType__Output = typeof _org_dash_platform_dapi_v0_GetContestedResourceVoteStateRequest_GetContestedResourceVoteStateRequestV0_ResultType[keyof typeof _org_dash_platform_dapi_v0_GetContestedResourceVoteStateRequest_GetContestedResourceVoteStateRequestV0_ResultType]

export interface _org_dash_platform_dapi_v0_GetContestedResourceVoteStateRequest_GetContestedResourceVoteStateRequestV0_StartAtIdentifierInfo {
  'startIdentifier'?: (Buffer | Uint8Array | string);
  'startIdentifierIncluded'?: (boolean);
}

export interface _org_dash_platform_dapi_v0_GetContestedResourceVoteStateRequest_GetContestedResourceVoteStateRequestV0_StartAtIdentifierInfo__Output {
  'startIdentifier': (Buffer);
  'startIdentifierIncluded': (boolean);
}

export interface GetContestedResourceVoteStateRequest {
  'v0'?: (_org_dash_platform_dapi_v0_GetContestedResourceVoteStateRequest_GetContestedResourceVoteStateRequestV0 | null);
  'version'?: "v0";
}

export interface GetContestedResourceVoteStateRequest__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetContestedResourceVoteStateRequest_GetContestedResourceVoteStateRequestV0__Output | null);
  'version': "v0";
}
