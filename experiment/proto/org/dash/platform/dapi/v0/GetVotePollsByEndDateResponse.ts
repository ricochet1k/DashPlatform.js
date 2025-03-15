// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

import type { Proof as _org_dash_platform_dapi_v0_Proof, Proof__Output as _org_dash_platform_dapi_v0_Proof__Output } from '../../../../../org/dash/platform/dapi/v0/Proof';
import type { ResponseMetadata as _org_dash_platform_dapi_v0_ResponseMetadata, ResponseMetadata__Output as _org_dash_platform_dapi_v0_ResponseMetadata__Output } from '../../../../../org/dash/platform/dapi/v0/ResponseMetadata';
import type { Long } from '@grpc/proto-loader';

export interface _org_dash_platform_dapi_v0_GetVotePollsByEndDateResponse_GetVotePollsByEndDateResponseV0 {
  'votePollsByTimestamps'?: (_org_dash_platform_dapi_v0_GetVotePollsByEndDateResponse_GetVotePollsByEndDateResponseV0_SerializedVotePollsByTimestamps | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof | null);
  'metadata'?: (_org_dash_platform_dapi_v0_ResponseMetadata | null);
  'result'?: "votePollsByTimestamps"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetVotePollsByEndDateResponse_GetVotePollsByEndDateResponseV0__Output {
  'votePollsByTimestamps'?: (_org_dash_platform_dapi_v0_GetVotePollsByEndDateResponse_GetVotePollsByEndDateResponseV0_SerializedVotePollsByTimestamps__Output | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof__Output | null);
  'metadata': (_org_dash_platform_dapi_v0_ResponseMetadata__Output | null);
  'result': "votePollsByTimestamps"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetVotePollsByEndDateResponse_GetVotePollsByEndDateResponseV0_SerializedVotePollsByTimestamp {
  'timestamp'?: (number | string | Long);
  'serializedVotePolls'?: (Buffer | Uint8Array | string)[];
}

export interface _org_dash_platform_dapi_v0_GetVotePollsByEndDateResponse_GetVotePollsByEndDateResponseV0_SerializedVotePollsByTimestamp__Output {
  'timestamp': (string);
  'serializedVotePolls': (Buffer)[];
}

export interface _org_dash_platform_dapi_v0_GetVotePollsByEndDateResponse_GetVotePollsByEndDateResponseV0_SerializedVotePollsByTimestamps {
  'votePollsByTimestamps'?: (_org_dash_platform_dapi_v0_GetVotePollsByEndDateResponse_GetVotePollsByEndDateResponseV0_SerializedVotePollsByTimestamp)[];
  'finishedResults'?: (boolean);
}

export interface _org_dash_platform_dapi_v0_GetVotePollsByEndDateResponse_GetVotePollsByEndDateResponseV0_SerializedVotePollsByTimestamps__Output {
  'votePollsByTimestamps': (_org_dash_platform_dapi_v0_GetVotePollsByEndDateResponse_GetVotePollsByEndDateResponseV0_SerializedVotePollsByTimestamp__Output)[];
  'finishedResults': (boolean);
}

export interface GetVotePollsByEndDateResponse {
  'v0'?: (_org_dash_platform_dapi_v0_GetVotePollsByEndDateResponse_GetVotePollsByEndDateResponseV0 | null);
  'version'?: "v0";
}

export interface GetVotePollsByEndDateResponse__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetVotePollsByEndDateResponse_GetVotePollsByEndDateResponseV0__Output | null);
  'version': "v0";
}
