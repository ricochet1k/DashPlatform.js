// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

import type { Long } from '@grpc/proto-loader';

export interface _org_dash_platform_dapi_v0_GetTokenPreProgrammedDistributionsRequest_GetTokenPreProgrammedDistributionsRequestV0 {
  'tokenId'?: (Buffer | Uint8Array | string);
  'startAtInfo'?: (_org_dash_platform_dapi_v0_GetTokenPreProgrammedDistributionsRequest_GetTokenPreProgrammedDistributionsRequestV0_StartAtInfo | null);
  'limit'?: (number);
  'prove'?: (boolean);
  '_startAtInfo'?: "startAtInfo";
  '_limit'?: "limit";
}

export interface _org_dash_platform_dapi_v0_GetTokenPreProgrammedDistributionsRequest_GetTokenPreProgrammedDistributionsRequestV0__Output {
  'tokenId': (Buffer);
  'startAtInfo'?: (_org_dash_platform_dapi_v0_GetTokenPreProgrammedDistributionsRequest_GetTokenPreProgrammedDistributionsRequestV0_StartAtInfo__Output | null);
  'limit'?: (number);
  'prove': (boolean);
  '_startAtInfo': "startAtInfo";
  '_limit': "limit";
}

export interface _org_dash_platform_dapi_v0_GetTokenPreProgrammedDistributionsRequest_GetTokenPreProgrammedDistributionsRequestV0_StartAtInfo {
  'startTimeMs'?: (number | string | Long);
  'startRecipient'?: (Buffer | Uint8Array | string);
  'startRecipientIncluded'?: (boolean);
  '_startRecipient'?: "startRecipient";
  '_startRecipientIncluded'?: "startRecipientIncluded";
}

export interface _org_dash_platform_dapi_v0_GetTokenPreProgrammedDistributionsRequest_GetTokenPreProgrammedDistributionsRequestV0_StartAtInfo__Output {
  'startTimeMs': (string);
  'startRecipient'?: (Buffer);
  'startRecipientIncluded'?: (boolean);
  '_startRecipient': "startRecipient";
  '_startRecipientIncluded': "startRecipientIncluded";
}

export interface GetTokenPreProgrammedDistributionsRequest {
  'v0'?: (_org_dash_platform_dapi_v0_GetTokenPreProgrammedDistributionsRequest_GetTokenPreProgrammedDistributionsRequestV0 | null);
  'version'?: "v0";
}

export interface GetTokenPreProgrammedDistributionsRequest__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetTokenPreProgrammedDistributionsRequest_GetTokenPreProgrammedDistributionsRequestV0__Output | null);
  'version': "v0";
}
