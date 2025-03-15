// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto


export interface _org_dash_platform_dapi_v0_GetIdentityNonceRequest_GetIdentityNonceRequestV0 {
  'identityId'?: (Buffer | Uint8Array | string);
  'prove'?: (boolean);
}

export interface _org_dash_platform_dapi_v0_GetIdentityNonceRequest_GetIdentityNonceRequestV0__Output {
  'identityId': (Buffer);
  'prove': (boolean);
}

export interface GetIdentityNonceRequest {
  'v0'?: (_org_dash_platform_dapi_v0_GetIdentityNonceRequest_GetIdentityNonceRequestV0 | null);
  'version'?: "v0";
}

export interface GetIdentityNonceRequest__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetIdentityNonceRequest_GetIdentityNonceRequestV0__Output | null);
  'version': "v0";
}
