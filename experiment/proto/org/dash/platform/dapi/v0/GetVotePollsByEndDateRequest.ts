// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

import type { Long } from '@grpc/proto-loader';

export interface _org_dash_platform_dapi_v0_GetVotePollsByEndDateRequest_GetVotePollsByEndDateRequestV0_EndAtTimeInfo {
  'endTimeMs'?: (number | string | Long);
  'endTimeIncluded'?: (boolean);
}

export interface _org_dash_platform_dapi_v0_GetVotePollsByEndDateRequest_GetVotePollsByEndDateRequestV0_EndAtTimeInfo__Output {
  'endTimeMs': (string);
  'endTimeIncluded': (boolean);
}

export interface _org_dash_platform_dapi_v0_GetVotePollsByEndDateRequest_GetVotePollsByEndDateRequestV0 {
  'startTimeInfo'?: (_org_dash_platform_dapi_v0_GetVotePollsByEndDateRequest_GetVotePollsByEndDateRequestV0_StartAtTimeInfo | null);
  'endTimeInfo'?: (_org_dash_platform_dapi_v0_GetVotePollsByEndDateRequest_GetVotePollsByEndDateRequestV0_EndAtTimeInfo | null);
  'limit'?: (number);
  'offset'?: (number);
  'ascending'?: (boolean);
  'prove'?: (boolean);
  '_startTimeInfo'?: "startTimeInfo";
  '_endTimeInfo'?: "endTimeInfo";
  '_limit'?: "limit";
  '_offset'?: "offset";
}

export interface _org_dash_platform_dapi_v0_GetVotePollsByEndDateRequest_GetVotePollsByEndDateRequestV0__Output {
  'startTimeInfo'?: (_org_dash_platform_dapi_v0_GetVotePollsByEndDateRequest_GetVotePollsByEndDateRequestV0_StartAtTimeInfo__Output | null);
  'endTimeInfo'?: (_org_dash_platform_dapi_v0_GetVotePollsByEndDateRequest_GetVotePollsByEndDateRequestV0_EndAtTimeInfo__Output | null);
  'limit'?: (number);
  'offset'?: (number);
  'ascending': (boolean);
  'prove': (boolean);
  '_startTimeInfo': "startTimeInfo";
  '_endTimeInfo': "endTimeInfo";
  '_limit': "limit";
  '_offset': "offset";
}

export interface _org_dash_platform_dapi_v0_GetVotePollsByEndDateRequest_GetVotePollsByEndDateRequestV0_StartAtTimeInfo {
  'startTimeMs'?: (number | string | Long);
  'startTimeIncluded'?: (boolean);
}

export interface _org_dash_platform_dapi_v0_GetVotePollsByEndDateRequest_GetVotePollsByEndDateRequestV0_StartAtTimeInfo__Output {
  'startTimeMs': (string);
  'startTimeIncluded': (boolean);
}

export interface GetVotePollsByEndDateRequest {
  'v0'?: (_org_dash_platform_dapi_v0_GetVotePollsByEndDateRequest_GetVotePollsByEndDateRequestV0 | null);
  'version'?: "v0";
}

export interface GetVotePollsByEndDateRequest__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetVotePollsByEndDateRequest_GetVotePollsByEndDateRequestV0__Output | null);
  'version': "v0";
}
