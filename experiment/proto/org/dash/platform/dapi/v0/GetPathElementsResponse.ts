// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

import type { Proof as _org_dash_platform_dapi_v0_Proof, Proof__Output as _org_dash_platform_dapi_v0_Proof__Output } from '../../../../../org/dash/platform/dapi/v0/Proof';
import type { ResponseMetadata as _org_dash_platform_dapi_v0_ResponseMetadata, ResponseMetadata__Output as _org_dash_platform_dapi_v0_ResponseMetadata__Output } from '../../../../../org/dash/platform/dapi/v0/ResponseMetadata';

export interface _org_dash_platform_dapi_v0_GetPathElementsResponse_GetPathElementsResponseV0_Elements {
  'elements'?: (Buffer | Uint8Array | string)[];
}

export interface _org_dash_platform_dapi_v0_GetPathElementsResponse_GetPathElementsResponseV0_Elements__Output {
  'elements': (Buffer)[];
}

export interface _org_dash_platform_dapi_v0_GetPathElementsResponse_GetPathElementsResponseV0 {
  'elements'?: (_org_dash_platform_dapi_v0_GetPathElementsResponse_GetPathElementsResponseV0_Elements | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof | null);
  'metadata'?: (_org_dash_platform_dapi_v0_ResponseMetadata | null);
  'result'?: "elements"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetPathElementsResponse_GetPathElementsResponseV0__Output {
  'elements'?: (_org_dash_platform_dapi_v0_GetPathElementsResponse_GetPathElementsResponseV0_Elements__Output | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof__Output | null);
  'metadata': (_org_dash_platform_dapi_v0_ResponseMetadata__Output | null);
  'result': "elements"|"proof";
}

export interface GetPathElementsResponse {
  'v0'?: (_org_dash_platform_dapi_v0_GetPathElementsResponse_GetPathElementsResponseV0 | null);
  'version'?: "v0";
}

export interface GetPathElementsResponse__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetPathElementsResponse_GetPathElementsResponseV0__Output | null);
  'version': "v0";
}
