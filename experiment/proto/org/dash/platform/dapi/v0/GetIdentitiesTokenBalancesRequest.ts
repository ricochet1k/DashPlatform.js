// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto


export interface _org_dash_platform_dapi_v0_GetIdentitiesTokenBalancesRequest_GetIdentitiesTokenBalancesRequestV0 {
  'tokenId'?: (Buffer | Uint8Array | string);
  'identityIds'?: (Buffer | Uint8Array | string)[];
  'prove'?: (boolean);
}

export interface _org_dash_platform_dapi_v0_GetIdentitiesTokenBalancesRequest_GetIdentitiesTokenBalancesRequestV0__Output {
  'tokenId': (Buffer);
  'identityIds': (Buffer)[];
  'prove': (boolean);
}

export interface GetIdentitiesTokenBalancesRequest {
  'v0'?: (_org_dash_platform_dapi_v0_GetIdentitiesTokenBalancesRequest_GetIdentitiesTokenBalancesRequestV0 | null);
  'version'?: "v0";
}

export interface GetIdentitiesTokenBalancesRequest__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetIdentitiesTokenBalancesRequest_GetIdentitiesTokenBalancesRequestV0__Output | null);
  'version': "v0";
}
