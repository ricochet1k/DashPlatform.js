// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

import type { Proof as _org_dash_platform_dapi_v0_Proof, Proof__Output as _org_dash_platform_dapi_v0_Proof__Output } from '../../../../../org/dash/platform/dapi/v0/Proof';
import type { ResponseMetadata as _org_dash_platform_dapi_v0_ResponseMetadata, ResponseMetadata__Output as _org_dash_platform_dapi_v0_ResponseMetadata__Output } from '../../../../../org/dash/platform/dapi/v0/ResponseMetadata';

export interface _org_dash_platform_dapi_v0_GetIdentityByPublicKeyHashResponse_GetIdentityByPublicKeyHashResponseV0 {
  'identity'?: (Buffer | Uint8Array | string);
  'proof'?: (_org_dash_platform_dapi_v0_Proof | null);
  'metadata'?: (_org_dash_platform_dapi_v0_ResponseMetadata | null);
  'result'?: "identity"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetIdentityByPublicKeyHashResponse_GetIdentityByPublicKeyHashResponseV0__Output {
  'identity'?: (Buffer);
  'proof'?: (_org_dash_platform_dapi_v0_Proof__Output | null);
  'metadata': (_org_dash_platform_dapi_v0_ResponseMetadata__Output | null);
  'result': "identity"|"proof";
}

export interface GetIdentityByPublicKeyHashResponse {
  'v0'?: (_org_dash_platform_dapi_v0_GetIdentityByPublicKeyHashResponse_GetIdentityByPublicKeyHashResponseV0 | null);
  'version'?: "v0";
}

export interface GetIdentityByPublicKeyHashResponse__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetIdentityByPublicKeyHashResponse_GetIdentityByPublicKeyHashResponseV0__Output | null);
  'version': "v0";
}
