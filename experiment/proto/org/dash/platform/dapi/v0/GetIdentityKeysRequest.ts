// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

import type { KeyRequestType as _org_dash_platform_dapi_v0_KeyRequestType, KeyRequestType__Output as _org_dash_platform_dapi_v0_KeyRequestType__Output } from '../../../../../org/dash/platform/dapi/v0/KeyRequestType';
import type { UInt32Value as _google_protobuf_UInt32Value, UInt32Value__Output as _google_protobuf_UInt32Value__Output } from '../../../../../google/protobuf/UInt32Value';

export interface _org_dash_platform_dapi_v0_GetIdentityKeysRequest_GetIdentityKeysRequestV0 {
  'identityId'?: (Buffer | Uint8Array | string);
  'requestType'?: (_org_dash_platform_dapi_v0_KeyRequestType | null);
  'limit'?: (_google_protobuf_UInt32Value | null);
  'offset'?: (_google_protobuf_UInt32Value | null);
  'prove'?: (boolean);
}

export interface _org_dash_platform_dapi_v0_GetIdentityKeysRequest_GetIdentityKeysRequestV0__Output {
  'identityId': (Buffer);
  'requestType': (_org_dash_platform_dapi_v0_KeyRequestType__Output | null);
  'limit': (_google_protobuf_UInt32Value__Output | null);
  'offset': (_google_protobuf_UInt32Value__Output | null);
  'prove': (boolean);
}

export interface GetIdentityKeysRequest {
  'v0'?: (_org_dash_platform_dapi_v0_GetIdentityKeysRequest_GetIdentityKeysRequestV0 | null);
  'version'?: "v0";
}

export interface GetIdentityKeysRequest__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetIdentityKeysRequest_GetIdentityKeysRequestV0__Output | null);
  'version': "v0";
}
