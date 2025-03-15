// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto


export interface _org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksByRangeRequest_GetEvonodesProposedEpochBlocksByRangeRequestV0 {
  'epoch'?: (number);
  'limit'?: (number);
  'startAfter'?: (Buffer | Uint8Array | string);
  'startAt'?: (Buffer | Uint8Array | string);
  'prove'?: (boolean);
  '_epoch'?: "epoch";
  '_limit'?: "limit";
  'start'?: "startAfter"|"startAt";
}

export interface _org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksByRangeRequest_GetEvonodesProposedEpochBlocksByRangeRequestV0__Output {
  'epoch'?: (number);
  'limit'?: (number);
  'startAfter'?: (Buffer);
  'startAt'?: (Buffer);
  'prove': (boolean);
  '_epoch': "epoch";
  '_limit': "limit";
  'start': "startAfter"|"startAt";
}

export interface GetEvonodesProposedEpochBlocksByRangeRequest {
  'v0'?: (_org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksByRangeRequest_GetEvonodesProposedEpochBlocksByRangeRequestV0 | null);
  'version'?: "v0";
}

export interface GetEvonodesProposedEpochBlocksByRangeRequest__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksByRangeRequest_GetEvonodesProposedEpochBlocksByRangeRequestV0__Output | null);
  'version': "v0";
}
