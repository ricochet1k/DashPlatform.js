// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto


export interface _org_dash_platform_dapi_v0_GetIdentitiesBalancesRequest_GetIdentitiesBalancesRequestV0 {
  'ids'?: (Buffer | Uint8Array | string)[];
  'prove'?: (boolean);
}

export interface _org_dash_platform_dapi_v0_GetIdentitiesBalancesRequest_GetIdentitiesBalancesRequestV0__Output {
  'ids': (Buffer)[];
  'prove': (boolean);
}

export interface GetIdentitiesBalancesRequest {
  'v0'?: (_org_dash_platform_dapi_v0_GetIdentitiesBalancesRequest_GetIdentitiesBalancesRequestV0 | null);
  'version'?: "v0";
}

export interface GetIdentitiesBalancesRequest__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetIdentitiesBalancesRequest_GetIdentitiesBalancesRequestV0__Output | null);
  'version': "v0";
}
