// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto


export interface _org_dash_platform_dapi_v0_GetTokenStatusesRequest_GetTokenStatusesRequestV0 {
  'tokenIds'?: (Buffer | Uint8Array | string)[];
  'prove'?: (boolean);
}

export interface _org_dash_platform_dapi_v0_GetTokenStatusesRequest_GetTokenStatusesRequestV0__Output {
  'tokenIds': (Buffer)[];
  'prove': (boolean);
}

export interface GetTokenStatusesRequest {
  'v0'?: (_org_dash_platform_dapi_v0_GetTokenStatusesRequest_GetTokenStatusesRequestV0 | null);
  'version'?: "v0";
}

export interface GetTokenStatusesRequest__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetTokenStatusesRequest_GetTokenStatusesRequestV0__Output | null);
  'version': "v0";
}
