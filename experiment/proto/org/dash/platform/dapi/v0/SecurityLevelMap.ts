// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto


// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

export const _org_dash_platform_dapi_v0_SecurityLevelMap_KeyKindRequestType = {
  CURRENT_KEY_OF_KIND_REQUEST: 'CURRENT_KEY_OF_KIND_REQUEST',
  ALL_KEYS_OF_KIND_REQUEST: 'ALL_KEYS_OF_KIND_REQUEST',
} as const;

export type _org_dash_platform_dapi_v0_SecurityLevelMap_KeyKindRequestType =
  | 'CURRENT_KEY_OF_KIND_REQUEST'
  | 0
  | 'ALL_KEYS_OF_KIND_REQUEST'
  | 1

export type _org_dash_platform_dapi_v0_SecurityLevelMap_KeyKindRequestType__Output = typeof _org_dash_platform_dapi_v0_SecurityLevelMap_KeyKindRequestType[keyof typeof _org_dash_platform_dapi_v0_SecurityLevelMap_KeyKindRequestType]

export interface SecurityLevelMap {
  'securityLevelMap'?: ({[key: number]: _org_dash_platform_dapi_v0_SecurityLevelMap_KeyKindRequestType});
}

export interface SecurityLevelMap__Output {
  'securityLevelMap': ({[key: number]: _org_dash_platform_dapi_v0_SecurityLevelMap_KeyKindRequestType__Output});
}
