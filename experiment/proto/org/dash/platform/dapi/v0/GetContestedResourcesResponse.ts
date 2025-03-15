// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

import type { Proof as _org_dash_platform_dapi_v0_Proof, Proof__Output as _org_dash_platform_dapi_v0_Proof__Output } from '../../../../../org/dash/platform/dapi/v0/Proof';
import type { ResponseMetadata as _org_dash_platform_dapi_v0_ResponseMetadata, ResponseMetadata__Output as _org_dash_platform_dapi_v0_ResponseMetadata__Output } from '../../../../../org/dash/platform/dapi/v0/ResponseMetadata';

export interface _org_dash_platform_dapi_v0_GetContestedResourcesResponse_GetContestedResourcesResponseV0_ContestedResourceValues {
  'contestedResourceValues'?: (Buffer | Uint8Array | string)[];
}

export interface _org_dash_platform_dapi_v0_GetContestedResourcesResponse_GetContestedResourcesResponseV0_ContestedResourceValues__Output {
  'contestedResourceValues': (Buffer)[];
}

export interface _org_dash_platform_dapi_v0_GetContestedResourcesResponse_GetContestedResourcesResponseV0 {
  'contestedResourceValues'?: (_org_dash_platform_dapi_v0_GetContestedResourcesResponse_GetContestedResourcesResponseV0_ContestedResourceValues | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof | null);
  'metadata'?: (_org_dash_platform_dapi_v0_ResponseMetadata | null);
  'result'?: "contestedResourceValues"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetContestedResourcesResponse_GetContestedResourcesResponseV0__Output {
  'contestedResourceValues'?: (_org_dash_platform_dapi_v0_GetContestedResourcesResponse_GetContestedResourcesResponseV0_ContestedResourceValues__Output | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof__Output | null);
  'metadata': (_org_dash_platform_dapi_v0_ResponseMetadata__Output | null);
  'result': "contestedResourceValues"|"proof";
}

export interface GetContestedResourcesResponse {
  'v0'?: (_org_dash_platform_dapi_v0_GetContestedResourcesResponse_GetContestedResourcesResponseV0 | null);
  'version'?: "v0";
}

export interface GetContestedResourcesResponse__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetContestedResourcesResponse_GetContestedResourcesResponseV0__Output | null);
  'version': "v0";
}
