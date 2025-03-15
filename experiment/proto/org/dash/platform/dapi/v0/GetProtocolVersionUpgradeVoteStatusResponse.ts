// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

import type { Proof as _org_dash_platform_dapi_v0_Proof, Proof__Output as _org_dash_platform_dapi_v0_Proof__Output } from '../../../../../org/dash/platform/dapi/v0/Proof';
import type { ResponseMetadata as _org_dash_platform_dapi_v0_ResponseMetadata, ResponseMetadata__Output as _org_dash_platform_dapi_v0_ResponseMetadata__Output } from '../../../../../org/dash/platform/dapi/v0/ResponseMetadata';

export interface _org_dash_platform_dapi_v0_GetProtocolVersionUpgradeVoteStatusResponse_GetProtocolVersionUpgradeVoteStatusResponseV0 {
  'versions'?: (_org_dash_platform_dapi_v0_GetProtocolVersionUpgradeVoteStatusResponse_GetProtocolVersionUpgradeVoteStatusResponseV0_VersionSignals | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof | null);
  'metadata'?: (_org_dash_platform_dapi_v0_ResponseMetadata | null);
  'result'?: "versions"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetProtocolVersionUpgradeVoteStatusResponse_GetProtocolVersionUpgradeVoteStatusResponseV0__Output {
  'versions'?: (_org_dash_platform_dapi_v0_GetProtocolVersionUpgradeVoteStatusResponse_GetProtocolVersionUpgradeVoteStatusResponseV0_VersionSignals__Output | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof__Output | null);
  'metadata': (_org_dash_platform_dapi_v0_ResponseMetadata__Output | null);
  'result': "versions"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetProtocolVersionUpgradeVoteStatusResponse_GetProtocolVersionUpgradeVoteStatusResponseV0_VersionSignal {
  'proTxHash'?: (Buffer | Uint8Array | string);
  'version'?: (number);
}

export interface _org_dash_platform_dapi_v0_GetProtocolVersionUpgradeVoteStatusResponse_GetProtocolVersionUpgradeVoteStatusResponseV0_VersionSignal__Output {
  'proTxHash': (Buffer);
  'version': (number);
}

export interface _org_dash_platform_dapi_v0_GetProtocolVersionUpgradeVoteStatusResponse_GetProtocolVersionUpgradeVoteStatusResponseV0_VersionSignals {
  'versionSignals'?: (_org_dash_platform_dapi_v0_GetProtocolVersionUpgradeVoteStatusResponse_GetProtocolVersionUpgradeVoteStatusResponseV0_VersionSignal)[];
}

export interface _org_dash_platform_dapi_v0_GetProtocolVersionUpgradeVoteStatusResponse_GetProtocolVersionUpgradeVoteStatusResponseV0_VersionSignals__Output {
  'versionSignals': (_org_dash_platform_dapi_v0_GetProtocolVersionUpgradeVoteStatusResponse_GetProtocolVersionUpgradeVoteStatusResponseV0_VersionSignal__Output)[];
}

export interface GetProtocolVersionUpgradeVoteStatusResponse {
  'v0'?: (_org_dash_platform_dapi_v0_GetProtocolVersionUpgradeVoteStatusResponse_GetProtocolVersionUpgradeVoteStatusResponseV0 | null);
  'version'?: "v0";
}

export interface GetProtocolVersionUpgradeVoteStatusResponse__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetProtocolVersionUpgradeVoteStatusResponse_GetProtocolVersionUpgradeVoteStatusResponseV0__Output | null);
  'version': "v0";
}
