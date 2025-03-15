// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto


export interface _org_dash_platform_dapi_v0_GetGroupInfosRequest_GetGroupInfosRequestV0 {
  'contractId'?: (Buffer | Uint8Array | string);
  'startAtGroupContractPosition'?: (_org_dash_platform_dapi_v0_GetGroupInfosRequest_StartAtGroupContractPosition | null);
  'count'?: (number);
  'prove'?: (boolean);
  '_startAtGroupContractPosition'?: "startAtGroupContractPosition";
  '_count'?: "count";
}

export interface _org_dash_platform_dapi_v0_GetGroupInfosRequest_GetGroupInfosRequestV0__Output {
  'contractId': (Buffer);
  'startAtGroupContractPosition'?: (_org_dash_platform_dapi_v0_GetGroupInfosRequest_StartAtGroupContractPosition__Output | null);
  'count'?: (number);
  'prove': (boolean);
  '_startAtGroupContractPosition': "startAtGroupContractPosition";
  '_count': "count";
}

export interface _org_dash_platform_dapi_v0_GetGroupInfosRequest_StartAtGroupContractPosition {
  'startGroupContractPosition'?: (number);
  'startGroupContractPositionIncluded'?: (boolean);
}

export interface _org_dash_platform_dapi_v0_GetGroupInfosRequest_StartAtGroupContractPosition__Output {
  'startGroupContractPosition': (number);
  'startGroupContractPositionIncluded': (boolean);
}

export interface GetGroupInfosRequest {
  'v0'?: (_org_dash_platform_dapi_v0_GetGroupInfosRequest_GetGroupInfosRequestV0 | null);
  'version'?: "v0";
}

export interface GetGroupInfosRequest__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetGroupInfosRequest_GetGroupInfosRequestV0__Output | null);
  'version': "v0";
}
