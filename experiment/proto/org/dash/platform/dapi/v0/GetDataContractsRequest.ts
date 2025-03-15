// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto


export interface _org_dash_platform_dapi_v0_GetDataContractsRequest_GetDataContractsRequestV0 {
  'ids'?: (Buffer | Uint8Array | string)[];
  'prove'?: (boolean);
}

export interface _org_dash_platform_dapi_v0_GetDataContractsRequest_GetDataContractsRequestV0__Output {
  'ids': (Buffer)[];
  'prove': (boolean);
}

export interface GetDataContractsRequest {
  'v0'?: (_org_dash_platform_dapi_v0_GetDataContractsRequest_GetDataContractsRequestV0 | null);
  'version'?: "v0";
}

export interface GetDataContractsRequest__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetDataContractsRequest_GetDataContractsRequestV0__Output | null);
  'version': "v0";
}
