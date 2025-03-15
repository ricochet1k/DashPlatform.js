// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto


export interface _org_dash_platform_dapi_v0_GetGroupInfoRequest_GetGroupInfoRequestV0 {
  'contractId'?: (Buffer | Uint8Array | string);
  'groupContractPosition'?: (number);
  'prove'?: (boolean);
}

export interface _org_dash_platform_dapi_v0_GetGroupInfoRequest_GetGroupInfoRequestV0__Output {
  'contractId': (Buffer);
  'groupContractPosition': (number);
  'prove': (boolean);
}

export interface GetGroupInfoRequest {
  'v0'?: (_org_dash_platform_dapi_v0_GetGroupInfoRequest_GetGroupInfoRequestV0 | null);
  'version'?: "v0";
}

export interface GetGroupInfoRequest__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetGroupInfoRequest_GetGroupInfoRequestV0__Output | null);
  'version': "v0";
}
