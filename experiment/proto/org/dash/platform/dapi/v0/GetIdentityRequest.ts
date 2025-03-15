// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto


export interface _org_dash_platform_dapi_v0_GetIdentityRequest_GetIdentityRequestV0 {
  'id'?: (Buffer | Uint8Array | string);
  'prove'?: (boolean);
}

export interface _org_dash_platform_dapi_v0_GetIdentityRequest_GetIdentityRequestV0__Output {
  'id': (Buffer);
  'prove': (boolean);
}

export interface GetIdentityRequest {
  'v0'?: (_org_dash_platform_dapi_v0_GetIdentityRequest_GetIdentityRequestV0 | null);
  'version'?: "v0";
}

export interface GetIdentityRequest__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetIdentityRequest_GetIdentityRequestV0__Output | null);
  'version': "v0";
}
