// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto


export interface _org_dash_platform_dapi_v0_GetIdentityTokenBalancesRequest_GetIdentityTokenBalancesRequestV0 {
  'identityId'?: (Buffer | Uint8Array | string);
  'tokenIds'?: (Buffer | Uint8Array | string)[];
  'prove'?: (boolean);
}

export interface _org_dash_platform_dapi_v0_GetIdentityTokenBalancesRequest_GetIdentityTokenBalancesRequestV0__Output {
  'identityId': (Buffer);
  'tokenIds': (Buffer)[];
  'prove': (boolean);
}

export interface GetIdentityTokenBalancesRequest {
  'v0'?: (_org_dash_platform_dapi_v0_GetIdentityTokenBalancesRequest_GetIdentityTokenBalancesRequestV0 | null);
  'version'?: "v0";
}

export interface GetIdentityTokenBalancesRequest__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetIdentityTokenBalancesRequest_GetIdentityTokenBalancesRequestV0__Output | null);
  'version': "v0";
}
