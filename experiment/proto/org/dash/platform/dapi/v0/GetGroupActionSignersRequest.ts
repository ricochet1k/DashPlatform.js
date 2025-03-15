// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto


// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

export const _org_dash_platform_dapi_v0_GetGroupActionSignersRequest_ActionStatus = {
  ACTIVE: 'ACTIVE',
  CLOSED: 'CLOSED',
} as const;

export type _org_dash_platform_dapi_v0_GetGroupActionSignersRequest_ActionStatus =
  | 'ACTIVE'
  | 0
  | 'CLOSED'
  | 1

export type _org_dash_platform_dapi_v0_GetGroupActionSignersRequest_ActionStatus__Output = typeof _org_dash_platform_dapi_v0_GetGroupActionSignersRequest_ActionStatus[keyof typeof _org_dash_platform_dapi_v0_GetGroupActionSignersRequest_ActionStatus]

export interface _org_dash_platform_dapi_v0_GetGroupActionSignersRequest_GetGroupActionSignersRequestV0 {
  'contractId'?: (Buffer | Uint8Array | string);
  'groupContractPosition'?: (number);
  'status'?: (_org_dash_platform_dapi_v0_GetGroupActionSignersRequest_ActionStatus);
  'actionId'?: (Buffer | Uint8Array | string);
  'prove'?: (boolean);
}

export interface _org_dash_platform_dapi_v0_GetGroupActionSignersRequest_GetGroupActionSignersRequestV0__Output {
  'contractId': (Buffer);
  'groupContractPosition': (number);
  'status': (_org_dash_platform_dapi_v0_GetGroupActionSignersRequest_ActionStatus__Output);
  'actionId': (Buffer);
  'prove': (boolean);
}

export interface GetGroupActionSignersRequest {
  'v0'?: (_org_dash_platform_dapi_v0_GetGroupActionSignersRequest_GetGroupActionSignersRequestV0 | null);
  'version'?: "v0";
}

export interface GetGroupActionSignersRequest__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetGroupActionSignersRequest_GetGroupActionSignersRequestV0__Output | null);
  'version': "v0";
}
