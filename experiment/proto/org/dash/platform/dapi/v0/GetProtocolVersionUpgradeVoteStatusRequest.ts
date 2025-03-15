// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto


export interface _org_dash_platform_dapi_v0_GetProtocolVersionUpgradeVoteStatusRequest_GetProtocolVersionUpgradeVoteStatusRequestV0 {
  'startProTxHash'?: (Buffer | Uint8Array | string);
  'count'?: (number);
  'prove'?: (boolean);
}

export interface _org_dash_platform_dapi_v0_GetProtocolVersionUpgradeVoteStatusRequest_GetProtocolVersionUpgradeVoteStatusRequestV0__Output {
  'startProTxHash': (Buffer);
  'count': (number);
  'prove': (boolean);
}

export interface GetProtocolVersionUpgradeVoteStatusRequest {
  'v0'?: (_org_dash_platform_dapi_v0_GetProtocolVersionUpgradeVoteStatusRequest_GetProtocolVersionUpgradeVoteStatusRequestV0 | null);
  'version'?: "v0";
}

export interface GetProtocolVersionUpgradeVoteStatusRequest__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetProtocolVersionUpgradeVoteStatusRequest_GetProtocolVersionUpgradeVoteStatusRequestV0__Output | null);
  'version': "v0";
}
