// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

import type { Proof as _org_dash_platform_dapi_v0_Proof, Proof__Output as _org_dash_platform_dapi_v0_Proof__Output } from '../../../../../org/dash/platform/dapi/v0/Proof';
import type { ResponseMetadata as _org_dash_platform_dapi_v0_ResponseMetadata, ResponseMetadata__Output as _org_dash_platform_dapi_v0_ResponseMetadata__Output } from '../../../../../org/dash/platform/dapi/v0/ResponseMetadata';
import type { Long } from '@grpc/proto-loader';

export interface _org_dash_platform_dapi_v0_GetPrefundedSpecializedBalanceResponse_GetPrefundedSpecializedBalanceResponseV0 {
  'balance'?: (number | string | Long);
  'proof'?: (_org_dash_platform_dapi_v0_Proof | null);
  'metadata'?: (_org_dash_platform_dapi_v0_ResponseMetadata | null);
  'result'?: "balance"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetPrefundedSpecializedBalanceResponse_GetPrefundedSpecializedBalanceResponseV0__Output {
  'balance'?: (string);
  'proof'?: (_org_dash_platform_dapi_v0_Proof__Output | null);
  'metadata': (_org_dash_platform_dapi_v0_ResponseMetadata__Output | null);
  'result': "balance"|"proof";
}

export interface GetPrefundedSpecializedBalanceResponse {
  'v0'?: (_org_dash_platform_dapi_v0_GetPrefundedSpecializedBalanceResponse_GetPrefundedSpecializedBalanceResponseV0 | null);
  'version'?: "v0";
}

export interface GetPrefundedSpecializedBalanceResponse__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetPrefundedSpecializedBalanceResponse_GetPrefundedSpecializedBalanceResponseV0__Output | null);
  'version': "v0";
}
