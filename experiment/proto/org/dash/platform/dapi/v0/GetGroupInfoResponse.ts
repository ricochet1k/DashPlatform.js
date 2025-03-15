// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

import type { Proof as _org_dash_platform_dapi_v0_Proof, Proof__Output as _org_dash_platform_dapi_v0_Proof__Output } from '../../../../../org/dash/platform/dapi/v0/Proof';
import type { ResponseMetadata as _org_dash_platform_dapi_v0_ResponseMetadata, ResponseMetadata__Output as _org_dash_platform_dapi_v0_ResponseMetadata__Output } from '../../../../../org/dash/platform/dapi/v0/ResponseMetadata';

export interface _org_dash_platform_dapi_v0_GetGroupInfoResponse_GetGroupInfoResponseV0 {
  'groupInfo'?: (_org_dash_platform_dapi_v0_GetGroupInfoResponse_GetGroupInfoResponseV0_GroupInfo | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof | null);
  'metadata'?: (_org_dash_platform_dapi_v0_ResponseMetadata | null);
  'result'?: "groupInfo"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetGroupInfoResponse_GetGroupInfoResponseV0__Output {
  'groupInfo'?: (_org_dash_platform_dapi_v0_GetGroupInfoResponse_GetGroupInfoResponseV0_GroupInfo__Output | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof__Output | null);
  'metadata': (_org_dash_platform_dapi_v0_ResponseMetadata__Output | null);
  'result': "groupInfo"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetGroupInfoResponse_GetGroupInfoResponseV0_GroupInfo {
  'groupInfo'?: (_org_dash_platform_dapi_v0_GetGroupInfoResponse_GetGroupInfoResponseV0_GroupInfoEntry | null);
  '_groupInfo'?: "groupInfo";
}

export interface _org_dash_platform_dapi_v0_GetGroupInfoResponse_GetGroupInfoResponseV0_GroupInfo__Output {
  'groupInfo'?: (_org_dash_platform_dapi_v0_GetGroupInfoResponse_GetGroupInfoResponseV0_GroupInfoEntry__Output | null);
  '_groupInfo': "groupInfo";
}

export interface _org_dash_platform_dapi_v0_GetGroupInfoResponse_GetGroupInfoResponseV0_GroupInfoEntry {
  'members'?: (_org_dash_platform_dapi_v0_GetGroupInfoResponse_GetGroupInfoResponseV0_GroupMemberEntry)[];
  'groupRequiredPower'?: (number);
}

export interface _org_dash_platform_dapi_v0_GetGroupInfoResponse_GetGroupInfoResponseV0_GroupInfoEntry__Output {
  'members': (_org_dash_platform_dapi_v0_GetGroupInfoResponse_GetGroupInfoResponseV0_GroupMemberEntry__Output)[];
  'groupRequiredPower': (number);
}

export interface _org_dash_platform_dapi_v0_GetGroupInfoResponse_GetGroupInfoResponseV0_GroupMemberEntry {
  'memberId'?: (Buffer | Uint8Array | string);
  'power'?: (number);
}

export interface _org_dash_platform_dapi_v0_GetGroupInfoResponse_GetGroupInfoResponseV0_GroupMemberEntry__Output {
  'memberId': (Buffer);
  'power': (number);
}

export interface GetGroupInfoResponse {
  'v0'?: (_org_dash_platform_dapi_v0_GetGroupInfoResponse_GetGroupInfoResponseV0 | null);
  'version'?: "v0";
}

export interface GetGroupInfoResponse__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetGroupInfoResponse_GetGroupInfoResponseV0__Output | null);
  'version': "v0";
}
