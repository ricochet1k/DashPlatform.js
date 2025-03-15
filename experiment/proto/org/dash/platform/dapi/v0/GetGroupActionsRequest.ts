// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto


// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

export const _org_dash_platform_dapi_v0_GetGroupActionsRequest_ActionStatus = {
  ACTIVE: 'ACTIVE',
  CLOSED: 'CLOSED',
} as const;

export type _org_dash_platform_dapi_v0_GetGroupActionsRequest_ActionStatus =
  | 'ACTIVE'
  | 0
  | 'CLOSED'
  | 1

export type _org_dash_platform_dapi_v0_GetGroupActionsRequest_ActionStatus__Output = typeof _org_dash_platform_dapi_v0_GetGroupActionsRequest_ActionStatus[keyof typeof _org_dash_platform_dapi_v0_GetGroupActionsRequest_ActionStatus]

export interface _org_dash_platform_dapi_v0_GetGroupActionsRequest_GetGroupActionsRequestV0 {
  'contractId'?: (Buffer | Uint8Array | string);
  'groupContractPosition'?: (number);
  'status'?: (_org_dash_platform_dapi_v0_GetGroupActionsRequest_ActionStatus);
  'startAtActionId'?: (_org_dash_platform_dapi_v0_GetGroupActionsRequest_StartAtActionId | null);
  'count'?: (number);
  'prove'?: (boolean);
  '_startAtActionId'?: "startAtActionId";
  '_count'?: "count";
}

export interface _org_dash_platform_dapi_v0_GetGroupActionsRequest_GetGroupActionsRequestV0__Output {
  'contractId': (Buffer);
  'groupContractPosition': (number);
  'status': (_org_dash_platform_dapi_v0_GetGroupActionsRequest_ActionStatus__Output);
  'startAtActionId'?: (_org_dash_platform_dapi_v0_GetGroupActionsRequest_StartAtActionId__Output | null);
  'count'?: (number);
  'prove': (boolean);
  '_startAtActionId': "startAtActionId";
  '_count': "count";
}

export interface _org_dash_platform_dapi_v0_GetGroupActionsRequest_StartAtActionId {
  'startActionId'?: (Buffer | Uint8Array | string);
  'startActionIdIncluded'?: (boolean);
}

export interface _org_dash_platform_dapi_v0_GetGroupActionsRequest_StartAtActionId__Output {
  'startActionId': (Buffer);
  'startActionIdIncluded': (boolean);
}

export interface GetGroupActionsRequest {
  'v0'?: (_org_dash_platform_dapi_v0_GetGroupActionsRequest_GetGroupActionsRequestV0 | null);
  'version'?: "v0";
}

export interface GetGroupActionsRequest__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetGroupActionsRequest_GetGroupActionsRequestV0__Output | null);
  'version': "v0";
}
