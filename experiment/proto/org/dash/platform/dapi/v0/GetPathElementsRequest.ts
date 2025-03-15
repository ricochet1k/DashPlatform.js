// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto


export interface _org_dash_platform_dapi_v0_GetPathElementsRequest_GetPathElementsRequestV0 {
  'path'?: (Buffer | Uint8Array | string)[];
  'keys'?: (Buffer | Uint8Array | string)[];
  'prove'?: (boolean);
}

export interface _org_dash_platform_dapi_v0_GetPathElementsRequest_GetPathElementsRequestV0__Output {
  'path': (Buffer)[];
  'keys': (Buffer)[];
  'prove': (boolean);
}

export interface GetPathElementsRequest {
  'v0'?: (_org_dash_platform_dapi_v0_GetPathElementsRequest_GetPathElementsRequestV0 | null);
  'version'?: "v0";
}

export interface GetPathElementsRequest__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetPathElementsRequest_GetPathElementsRequestV0__Output | null);
  'version': "v0";
}
