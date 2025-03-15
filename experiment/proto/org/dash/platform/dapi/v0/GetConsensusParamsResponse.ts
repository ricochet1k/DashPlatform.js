// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto


export interface _org_dash_platform_dapi_v0_GetConsensusParamsResponse_ConsensusParamsBlock {
  'maxBytes'?: (string);
  'maxGas'?: (string);
  'timeIotaMs'?: (string);
}

export interface _org_dash_platform_dapi_v0_GetConsensusParamsResponse_ConsensusParamsBlock__Output {
  'maxBytes': (string);
  'maxGas': (string);
  'timeIotaMs': (string);
}

export interface _org_dash_platform_dapi_v0_GetConsensusParamsResponse_ConsensusParamsEvidence {
  'maxAgeNumBlocks'?: (string);
  'maxAgeDuration'?: (string);
  'maxBytes'?: (string);
}

export interface _org_dash_platform_dapi_v0_GetConsensusParamsResponse_ConsensusParamsEvidence__Output {
  'maxAgeNumBlocks': (string);
  'maxAgeDuration': (string);
  'maxBytes': (string);
}

export interface _org_dash_platform_dapi_v0_GetConsensusParamsResponse_GetConsensusParamsResponseV0 {
  'block'?: (_org_dash_platform_dapi_v0_GetConsensusParamsResponse_ConsensusParamsBlock | null);
  'evidence'?: (_org_dash_platform_dapi_v0_GetConsensusParamsResponse_ConsensusParamsEvidence | null);
}

export interface _org_dash_platform_dapi_v0_GetConsensusParamsResponse_GetConsensusParamsResponseV0__Output {
  'block': (_org_dash_platform_dapi_v0_GetConsensusParamsResponse_ConsensusParamsBlock__Output | null);
  'evidence': (_org_dash_platform_dapi_v0_GetConsensusParamsResponse_ConsensusParamsEvidence__Output | null);
}

export interface GetConsensusParamsResponse {
  'v0'?: (_org_dash_platform_dapi_v0_GetConsensusParamsResponse_GetConsensusParamsResponseV0 | null);
  'version'?: "v0";
}

export interface GetConsensusParamsResponse__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetConsensusParamsResponse_GetConsensusParamsResponseV0__Output | null);
  'version': "v0";
}
