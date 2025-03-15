// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto


export interface _org_dash_platform_dapi_v0_GetIdentityBalanceAndRevisionRequest_GetIdentityBalanceAndRevisionRequestV0 {
  'id'?: (Buffer | Uint8Array | string);
  'prove'?: (boolean);
}

export interface _org_dash_platform_dapi_v0_GetIdentityBalanceAndRevisionRequest_GetIdentityBalanceAndRevisionRequestV0__Output {
  'id': (Buffer);
  'prove': (boolean);
}

export interface GetIdentityBalanceAndRevisionRequest {
  'v0'?: (_org_dash_platform_dapi_v0_GetIdentityBalanceAndRevisionRequest_GetIdentityBalanceAndRevisionRequestV0 | null);
  'version'?: "v0";
}

export interface GetIdentityBalanceAndRevisionRequest__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetIdentityBalanceAndRevisionRequest_GetIdentityBalanceAndRevisionRequestV0__Output | null);
  'version': "v0";
}
