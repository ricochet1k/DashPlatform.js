// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto


export interface _org_dash_platform_dapi_v0_GetIdentitiesTokenInfosRequest_GetIdentitiesTokenInfosRequestV0 {
  'tokenId'?: (Buffer | Uint8Array | string);
  'identityIds'?: (Buffer | Uint8Array | string)[];
  'prove'?: (boolean);
}

export interface _org_dash_platform_dapi_v0_GetIdentitiesTokenInfosRequest_GetIdentitiesTokenInfosRequestV0__Output {
  'tokenId': (Buffer);
  'identityIds': (Buffer)[];
  'prove': (boolean);
}

export interface GetIdentitiesTokenInfosRequest {
  'v0'?: (_org_dash_platform_dapi_v0_GetIdentitiesTokenInfosRequest_GetIdentitiesTokenInfosRequestV0 | null);
  'version'?: "v0";
}

export interface GetIdentitiesTokenInfosRequest__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetIdentitiesTokenInfosRequest_GetIdentitiesTokenInfosRequestV0__Output | null);
  'version': "v0";
}
