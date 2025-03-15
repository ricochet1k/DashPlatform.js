// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto


export interface _org_dash_platform_dapi_v0_GetPrefundedSpecializedBalanceRequest_GetPrefundedSpecializedBalanceRequestV0 {
  'id'?: (Buffer | Uint8Array | string);
  'prove'?: (boolean);
}

export interface _org_dash_platform_dapi_v0_GetPrefundedSpecializedBalanceRequest_GetPrefundedSpecializedBalanceRequestV0__Output {
  'id': (Buffer);
  'prove': (boolean);
}

export interface GetPrefundedSpecializedBalanceRequest {
  'v0'?: (_org_dash_platform_dapi_v0_GetPrefundedSpecializedBalanceRequest_GetPrefundedSpecializedBalanceRequestV0 | null);
  'version'?: "v0";
}

export interface GetPrefundedSpecializedBalanceRequest__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetPrefundedSpecializedBalanceRequest_GetPrefundedSpecializedBalanceRequestV0__Output | null);
  'version': "v0";
}
