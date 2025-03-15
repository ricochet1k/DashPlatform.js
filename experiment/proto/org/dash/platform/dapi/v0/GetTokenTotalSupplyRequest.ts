// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto


export interface _org_dash_platform_dapi_v0_GetTokenTotalSupplyRequest_GetTokenTotalSupplyRequestV0 {
  'tokenId'?: (Buffer | Uint8Array | string);
  'prove'?: (boolean);
}

export interface _org_dash_platform_dapi_v0_GetTokenTotalSupplyRequest_GetTokenTotalSupplyRequestV0__Output {
  'tokenId': (Buffer);
  'prove': (boolean);
}

export interface GetTokenTotalSupplyRequest {
  'v0'?: (_org_dash_platform_dapi_v0_GetTokenTotalSupplyRequest_GetTokenTotalSupplyRequestV0 | null);
  'version'?: "v0";
}

export interface GetTokenTotalSupplyRequest__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetTokenTotalSupplyRequest_GetTokenTotalSupplyRequestV0__Output | null);
  'version': "v0";
}
