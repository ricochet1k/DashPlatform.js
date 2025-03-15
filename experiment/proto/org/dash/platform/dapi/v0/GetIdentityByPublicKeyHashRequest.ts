// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto


export interface _org_dash_platform_dapi_v0_GetIdentityByPublicKeyHashRequest_GetIdentityByPublicKeyHashRequestV0 {
  'publicKeyHash'?: (Buffer | Uint8Array | string);
  'prove'?: (boolean);
}

export interface _org_dash_platform_dapi_v0_GetIdentityByPublicKeyHashRequest_GetIdentityByPublicKeyHashRequestV0__Output {
  'publicKeyHash': (Buffer);
  'prove': (boolean);
}

export interface GetIdentityByPublicKeyHashRequest {
  'v0'?: (_org_dash_platform_dapi_v0_GetIdentityByPublicKeyHashRequest_GetIdentityByPublicKeyHashRequestV0 | null);
  'version'?: "v0";
}

export interface GetIdentityByPublicKeyHashRequest__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetIdentityByPublicKeyHashRequest_GetIdentityByPublicKeyHashRequestV0__Output | null);
  'version': "v0";
}
