// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

import type { Proof as _org_dash_platform_dapi_v0_Proof, Proof__Output as _org_dash_platform_dapi_v0_Proof__Output } from '../../../../../org/dash/platform/dapi/v0/Proof';
import type { ResponseMetadata as _org_dash_platform_dapi_v0_ResponseMetadata, ResponseMetadata__Output as _org_dash_platform_dapi_v0_ResponseMetadata__Output } from '../../../../../org/dash/platform/dapi/v0/ResponseMetadata';
import type { Long } from '@grpc/proto-loader';

export interface _org_dash_platform_dapi_v0_GetTotalCreditsInPlatformResponse_GetTotalCreditsInPlatformResponseV0 {
  'credits'?: (number | string | Long);
  'proof'?: (_org_dash_platform_dapi_v0_Proof | null);
  'metadata'?: (_org_dash_platform_dapi_v0_ResponseMetadata | null);
  'result'?: "credits"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetTotalCreditsInPlatformResponse_GetTotalCreditsInPlatformResponseV0__Output {
  'credits'?: (string);
  'proof'?: (_org_dash_platform_dapi_v0_Proof__Output | null);
  'metadata': (_org_dash_platform_dapi_v0_ResponseMetadata__Output | null);
  'result': "credits"|"proof";
}

export interface GetTotalCreditsInPlatformResponse {
  'v0'?: (_org_dash_platform_dapi_v0_GetTotalCreditsInPlatformResponse_GetTotalCreditsInPlatformResponseV0 | null);
  'version'?: "v0";
}

export interface GetTotalCreditsInPlatformResponse__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetTotalCreditsInPlatformResponse_GetTotalCreditsInPlatformResponseV0__Output | null);
  'version': "v0";
}
