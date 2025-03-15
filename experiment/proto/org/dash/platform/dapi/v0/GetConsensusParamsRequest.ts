// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto


export interface _org_dash_platform_dapi_v0_GetConsensusParamsRequest_GetConsensusParamsRequestV0 {
  'height'?: (number);
  'prove'?: (boolean);
}

export interface _org_dash_platform_dapi_v0_GetConsensusParamsRequest_GetConsensusParamsRequestV0__Output {
  'height': (number);
  'prove': (boolean);
}

export interface GetConsensusParamsRequest {
  'v0'?: (_org_dash_platform_dapi_v0_GetConsensusParamsRequest_GetConsensusParamsRequestV0 | null);
  'version'?: "v0";
}

export interface GetConsensusParamsRequest__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetConsensusParamsRequest_GetConsensusParamsRequestV0__Output | null);
  'version': "v0";
}
