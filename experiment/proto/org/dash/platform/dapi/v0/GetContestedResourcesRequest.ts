// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto


export interface _org_dash_platform_dapi_v0_GetContestedResourcesRequest_GetContestedResourcesRequestV0 {
  'contractId'?: (Buffer | Uint8Array | string);
  'documentTypeName'?: (string);
  'indexName'?: (string);
  'startIndexValues'?: (Buffer | Uint8Array | string)[];
  'endIndexValues'?: (Buffer | Uint8Array | string)[];
  'startAtValueInfo'?: (_org_dash_platform_dapi_v0_GetContestedResourcesRequest_GetContestedResourcesRequestV0_StartAtValueInfo | null);
  'count'?: (number);
  'orderAscending'?: (boolean);
  'prove'?: (boolean);
  '_startAtValueInfo'?: "startAtValueInfo";
  '_count'?: "count";
}

export interface _org_dash_platform_dapi_v0_GetContestedResourcesRequest_GetContestedResourcesRequestV0__Output {
  'contractId': (Buffer);
  'documentTypeName': (string);
  'indexName': (string);
  'startIndexValues': (Buffer)[];
  'endIndexValues': (Buffer)[];
  'startAtValueInfo'?: (_org_dash_platform_dapi_v0_GetContestedResourcesRequest_GetContestedResourcesRequestV0_StartAtValueInfo__Output | null);
  'count'?: (number);
  'orderAscending': (boolean);
  'prove': (boolean);
  '_startAtValueInfo': "startAtValueInfo";
  '_count': "count";
}

export interface _org_dash_platform_dapi_v0_GetContestedResourcesRequest_GetContestedResourcesRequestV0_StartAtValueInfo {
  'startValue'?: (Buffer | Uint8Array | string);
  'startValueIncluded'?: (boolean);
}

export interface _org_dash_platform_dapi_v0_GetContestedResourcesRequest_GetContestedResourcesRequestV0_StartAtValueInfo__Output {
  'startValue': (Buffer);
  'startValueIncluded': (boolean);
}

export interface GetContestedResourcesRequest {
  'v0'?: (_org_dash_platform_dapi_v0_GetContestedResourcesRequest_GetContestedResourcesRequestV0 | null);
  'version'?: "v0";
}

export interface GetContestedResourcesRequest__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetContestedResourcesRequest_GetContestedResourcesRequestV0__Output | null);
  'version': "v0";
}
