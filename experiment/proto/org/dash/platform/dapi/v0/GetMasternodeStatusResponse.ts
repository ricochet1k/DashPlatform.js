// Original file: ../../platform/packages/dapi-grpc/protos/core/v0/core.proto


// Original file: ../../platform/packages/dapi-grpc/protos/core/v0/core.proto

export const _org_dash_platform_dapi_v0_GetMasternodeStatusResponse_Status = {
  UNKNOWN: 'UNKNOWN',
  WAITING_FOR_PROTX: 'WAITING_FOR_PROTX',
  POSE_BANNED: 'POSE_BANNED',
  REMOVED: 'REMOVED',
  OPERATOR_KEY_CHANGED: 'OPERATOR_KEY_CHANGED',
  PROTX_IP_CHANGED: 'PROTX_IP_CHANGED',
  READY: 'READY',
  ERROR: 'ERROR',
} as const;

export type _org_dash_platform_dapi_v0_GetMasternodeStatusResponse_Status =
  | 'UNKNOWN'
  | 0
  | 'WAITING_FOR_PROTX'
  | 1
  | 'POSE_BANNED'
  | 2
  | 'REMOVED'
  | 3
  | 'OPERATOR_KEY_CHANGED'
  | 4
  | 'PROTX_IP_CHANGED'
  | 5
  | 'READY'
  | 6
  | 'ERROR'
  | 7

export type _org_dash_platform_dapi_v0_GetMasternodeStatusResponse_Status__Output = typeof _org_dash_platform_dapi_v0_GetMasternodeStatusResponse_Status[keyof typeof _org_dash_platform_dapi_v0_GetMasternodeStatusResponse_Status]

export interface GetMasternodeStatusResponse {
  'status'?: (_org_dash_platform_dapi_v0_GetMasternodeStatusResponse_Status);
  'proTxHash'?: (Buffer | Uint8Array | string);
  'posePenalty'?: (number);
  'isSynced'?: (boolean);
  'syncProgress'?: (number | string);
}

export interface GetMasternodeStatusResponse__Output {
  'status': (_org_dash_platform_dapi_v0_GetMasternodeStatusResponse_Status__Output);
  'proTxHash': (Buffer);
  'posePenalty': (number);
  'isSynced': (boolean);
  'syncProgress': (number);
}
