// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto


export interface _org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksByIdsRequest_GetEvonodesProposedEpochBlocksByIdsRequestV0 {
  'epoch'?: (number);
  'ids'?: (Buffer | Uint8Array | string)[];
  'prove'?: (boolean);
  '_epoch'?: "epoch";
}

export interface _org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksByIdsRequest_GetEvonodesProposedEpochBlocksByIdsRequestV0__Output {
  'epoch'?: (number);
  'ids': (Buffer)[];
  'prove': (boolean);
  '_epoch': "epoch";
}

export interface GetEvonodesProposedEpochBlocksByIdsRequest {
  'v0'?: (_org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksByIdsRequest_GetEvonodesProposedEpochBlocksByIdsRequestV0 | null);
  'version'?: "v0";
}

export interface GetEvonodesProposedEpochBlocksByIdsRequest__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksByIdsRequest_GetEvonodesProposedEpochBlocksByIdsRequestV0__Output | null);
  'version': "v0";
}
