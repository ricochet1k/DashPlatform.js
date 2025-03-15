// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

import type { Proof as _org_dash_platform_dapi_v0_Proof, Proof__Output as _org_dash_platform_dapi_v0_Proof__Output } from '../../../../../org/dash/platform/dapi/v0/Proof';
import type { ResponseMetadata as _org_dash_platform_dapi_v0_ResponseMetadata, ResponseMetadata__Output as _org_dash_platform_dapi_v0_ResponseMetadata__Output } from '../../../../../org/dash/platform/dapi/v0/ResponseMetadata';

export interface _org_dash_platform_dapi_v0_GetIdentityKeysResponse_GetIdentityKeysResponseV0 {
  'keys'?: (_org_dash_platform_dapi_v0_GetIdentityKeysResponse_GetIdentityKeysResponseV0_Keys | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof | null);
  'metadata'?: (_org_dash_platform_dapi_v0_ResponseMetadata | null);
  'result'?: "keys"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetIdentityKeysResponse_GetIdentityKeysResponseV0__Output {
  'keys'?: (_org_dash_platform_dapi_v0_GetIdentityKeysResponse_GetIdentityKeysResponseV0_Keys__Output | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof__Output | null);
  'metadata': (_org_dash_platform_dapi_v0_ResponseMetadata__Output | null);
  'result': "keys"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetIdentityKeysResponse_GetIdentityKeysResponseV0_Keys {
  'keysBytes'?: (Buffer | Uint8Array | string)[];
}

export interface _org_dash_platform_dapi_v0_GetIdentityKeysResponse_GetIdentityKeysResponseV0_Keys__Output {
  'keysBytes': (Buffer)[];
}

export interface GetIdentityKeysResponse {
  'v0'?: (_org_dash_platform_dapi_v0_GetIdentityKeysResponse_GetIdentityKeysResponseV0 | null);
  'version'?: "v0";
}

export interface GetIdentityKeysResponse__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetIdentityKeysResponse_GetIdentityKeysResponseV0__Output | null);
  'version': "v0";
}
