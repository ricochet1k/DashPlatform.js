// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

import type { Proof as _org_dash_platform_dapi_v0_Proof, Proof__Output as _org_dash_platform_dapi_v0_Proof__Output } from '../../../../../org/dash/platform/dapi/v0/Proof';
import type { ResponseMetadata as _org_dash_platform_dapi_v0_ResponseMetadata, ResponseMetadata__Output as _org_dash_platform_dapi_v0_ResponseMetadata__Output } from '../../../../../org/dash/platform/dapi/v0/ResponseMetadata';

export interface _org_dash_platform_dapi_v0_GetProtocolVersionUpgradeStateResponse_GetProtocolVersionUpgradeStateResponseV0 {
  'versions'?: (_org_dash_platform_dapi_v0_GetProtocolVersionUpgradeStateResponse_GetProtocolVersionUpgradeStateResponseV0_Versions | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof | null);
  'metadata'?: (_org_dash_platform_dapi_v0_ResponseMetadata | null);
  'result'?: "versions"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetProtocolVersionUpgradeStateResponse_GetProtocolVersionUpgradeStateResponseV0__Output {
  'versions'?: (_org_dash_platform_dapi_v0_GetProtocolVersionUpgradeStateResponse_GetProtocolVersionUpgradeStateResponseV0_Versions__Output | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof__Output | null);
  'metadata': (_org_dash_platform_dapi_v0_ResponseMetadata__Output | null);
  'result': "versions"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetProtocolVersionUpgradeStateResponse_GetProtocolVersionUpgradeStateResponseV0_VersionEntry {
  'versionNumber'?: (number);
  'voteCount'?: (number);
}

export interface _org_dash_platform_dapi_v0_GetProtocolVersionUpgradeStateResponse_GetProtocolVersionUpgradeStateResponseV0_VersionEntry__Output {
  'versionNumber': (number);
  'voteCount': (number);
}

export interface _org_dash_platform_dapi_v0_GetProtocolVersionUpgradeStateResponse_GetProtocolVersionUpgradeStateResponseV0_Versions {
  'versions'?: (_org_dash_platform_dapi_v0_GetProtocolVersionUpgradeStateResponse_GetProtocolVersionUpgradeStateResponseV0_VersionEntry)[];
}

export interface _org_dash_platform_dapi_v0_GetProtocolVersionUpgradeStateResponse_GetProtocolVersionUpgradeStateResponseV0_Versions__Output {
  'versions': (_org_dash_platform_dapi_v0_GetProtocolVersionUpgradeStateResponse_GetProtocolVersionUpgradeStateResponseV0_VersionEntry__Output)[];
}

export interface GetProtocolVersionUpgradeStateResponse {
  'v0'?: (_org_dash_platform_dapi_v0_GetProtocolVersionUpgradeStateResponse_GetProtocolVersionUpgradeStateResponseV0 | null);
  'version'?: "v0";
}

export interface GetProtocolVersionUpgradeStateResponse__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetProtocolVersionUpgradeStateResponse_GetProtocolVersionUpgradeStateResponseV0__Output | null);
  'version': "v0";
}
