// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

import type { Proof as _org_dash_platform_dapi_v0_Proof, Proof__Output as _org_dash_platform_dapi_v0_Proof__Output } from '../../../../../org/dash/platform/dapi/v0/Proof';
import type { ResponseMetadata as _org_dash_platform_dapi_v0_ResponseMetadata, ResponseMetadata__Output as _org_dash_platform_dapi_v0_ResponseMetadata__Output } from '../../../../../org/dash/platform/dapi/v0/ResponseMetadata';

export interface _org_dash_platform_dapi_v0_GetGroupInfosResponse_GetGroupInfosResponseV0 {
  'groupInfos'?: (_org_dash_platform_dapi_v0_GetGroupInfosResponse_GetGroupInfosResponseV0_GroupInfos | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof | null);
  'metadata'?: (_org_dash_platform_dapi_v0_ResponseMetadata | null);
  'result'?: "groupInfos"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetGroupInfosResponse_GetGroupInfosResponseV0__Output {
  'groupInfos'?: (_org_dash_platform_dapi_v0_GetGroupInfosResponse_GetGroupInfosResponseV0_GroupInfos__Output | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof__Output | null);
  'metadata': (_org_dash_platform_dapi_v0_ResponseMetadata__Output | null);
  'result': "groupInfos"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetGroupInfosResponse_GetGroupInfosResponseV0_GroupInfos {
  'groupInfos'?: (_org_dash_platform_dapi_v0_GetGroupInfosResponse_GetGroupInfosResponseV0_GroupPositionInfoEntry)[];
}

export interface _org_dash_platform_dapi_v0_GetGroupInfosResponse_GetGroupInfosResponseV0_GroupInfos__Output {
  'groupInfos': (_org_dash_platform_dapi_v0_GetGroupInfosResponse_GetGroupInfosResponseV0_GroupPositionInfoEntry__Output)[];
}

export interface _org_dash_platform_dapi_v0_GetGroupInfosResponse_GetGroupInfosResponseV0_GroupMemberEntry {
  'memberId'?: (Buffer | Uint8Array | string);
  'power'?: (number);
}

export interface _org_dash_platform_dapi_v0_GetGroupInfosResponse_GetGroupInfosResponseV0_GroupMemberEntry__Output {
  'memberId': (Buffer);
  'power': (number);
}

export interface _org_dash_platform_dapi_v0_GetGroupInfosResponse_GetGroupInfosResponseV0_GroupPositionInfoEntry {
  'groupContractPosition'?: (number);
  'members'?: (_org_dash_platform_dapi_v0_GetGroupInfosResponse_GetGroupInfosResponseV0_GroupMemberEntry)[];
  'groupRequiredPower'?: (number);
}

export interface _org_dash_platform_dapi_v0_GetGroupInfosResponse_GetGroupInfosResponseV0_GroupPositionInfoEntry__Output {
  'groupContractPosition': (number);
  'members': (_org_dash_platform_dapi_v0_GetGroupInfosResponse_GetGroupInfosResponseV0_GroupMemberEntry__Output)[];
  'groupRequiredPower': (number);
}

export interface GetGroupInfosResponse {
  'v0'?: (_org_dash_platform_dapi_v0_GetGroupInfosResponse_GetGroupInfosResponseV0 | null);
  'version'?: "v0";
}

export interface GetGroupInfosResponse__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetGroupInfosResponse_GetGroupInfosResponseV0__Output | null);
  'version': "v0";
}
