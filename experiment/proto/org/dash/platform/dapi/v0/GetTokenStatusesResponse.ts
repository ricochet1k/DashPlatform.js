// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

import type { Proof as _org_dash_platform_dapi_v0_Proof, Proof__Output as _org_dash_platform_dapi_v0_Proof__Output } from '../../../../../org/dash/platform/dapi/v0/Proof';
import type { ResponseMetadata as _org_dash_platform_dapi_v0_ResponseMetadata, ResponseMetadata__Output as _org_dash_platform_dapi_v0_ResponseMetadata__Output } from '../../../../../org/dash/platform/dapi/v0/ResponseMetadata';

export interface _org_dash_platform_dapi_v0_GetTokenStatusesResponse_GetTokenStatusesResponseV0 {
  'tokenStatuses'?: (_org_dash_platform_dapi_v0_GetTokenStatusesResponse_GetTokenStatusesResponseV0_TokenStatuses | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof | null);
  'metadata'?: (_org_dash_platform_dapi_v0_ResponseMetadata | null);
  'result'?: "tokenStatuses"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetTokenStatusesResponse_GetTokenStatusesResponseV0__Output {
  'tokenStatuses'?: (_org_dash_platform_dapi_v0_GetTokenStatusesResponse_GetTokenStatusesResponseV0_TokenStatuses__Output | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof__Output | null);
  'metadata': (_org_dash_platform_dapi_v0_ResponseMetadata__Output | null);
  'result': "tokenStatuses"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetTokenStatusesResponse_GetTokenStatusesResponseV0_TokenStatusEntry {
  'tokenId'?: (Buffer | Uint8Array | string);
  'paused'?: (boolean);
  '_paused'?: "paused";
}

export interface _org_dash_platform_dapi_v0_GetTokenStatusesResponse_GetTokenStatusesResponseV0_TokenStatusEntry__Output {
  'tokenId': (Buffer);
  'paused'?: (boolean);
  '_paused': "paused";
}

export interface _org_dash_platform_dapi_v0_GetTokenStatusesResponse_GetTokenStatusesResponseV0_TokenStatuses {
  'tokenStatuses'?: (_org_dash_platform_dapi_v0_GetTokenStatusesResponse_GetTokenStatusesResponseV0_TokenStatusEntry)[];
}

export interface _org_dash_platform_dapi_v0_GetTokenStatusesResponse_GetTokenStatusesResponseV0_TokenStatuses__Output {
  'tokenStatuses': (_org_dash_platform_dapi_v0_GetTokenStatusesResponse_GetTokenStatusesResponseV0_TokenStatusEntry__Output)[];
}

export interface GetTokenStatusesResponse {
  'v0'?: (_org_dash_platform_dapi_v0_GetTokenStatusesResponse_GetTokenStatusesResponseV0 | null);
  'version'?: "v0";
}

export interface GetTokenStatusesResponse__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetTokenStatusesResponse_GetTokenStatusesResponseV0__Output | null);
  'version': "v0";
}
