// Original file: ../../platform/packages/dapi-grpc/protos/core/v0/core.proto


export interface _org_dash_platform_dapi_v0_GetBlockchainStatusResponse_Chain {
  'name'?: (string);
  'headersCount'?: (number);
  'blocksCount'?: (number);
  'bestBlockHash'?: (Buffer | Uint8Array | string);
  'difficulty'?: (number | string);
  'chainWork'?: (Buffer | Uint8Array | string);
  'isSynced'?: (boolean);
  'syncProgress'?: (number | string);
}

export interface _org_dash_platform_dapi_v0_GetBlockchainStatusResponse_Chain__Output {
  'name': (string);
  'headersCount': (number);
  'blocksCount': (number);
  'bestBlockHash': (Buffer);
  'difficulty': (number);
  'chainWork': (Buffer);
  'isSynced': (boolean);
  'syncProgress': (number);
}

export interface _org_dash_platform_dapi_v0_GetBlockchainStatusResponse_Network {
  'peersCount'?: (number);
  'fee'?: (_org_dash_platform_dapi_v0_GetBlockchainStatusResponse_NetworkFee | null);
}

export interface _org_dash_platform_dapi_v0_GetBlockchainStatusResponse_Network__Output {
  'peersCount': (number);
  'fee': (_org_dash_platform_dapi_v0_GetBlockchainStatusResponse_NetworkFee__Output | null);
}

export interface _org_dash_platform_dapi_v0_GetBlockchainStatusResponse_NetworkFee {
  'relay'?: (number | string);
  'incremental'?: (number | string);
}

export interface _org_dash_platform_dapi_v0_GetBlockchainStatusResponse_NetworkFee__Output {
  'relay': (number);
  'incremental': (number);
}

// Original file: ../../platform/packages/dapi-grpc/protos/core/v0/core.proto

export const _org_dash_platform_dapi_v0_GetBlockchainStatusResponse_Status = {
  NOT_STARTED: 'NOT_STARTED',
  SYNCING: 'SYNCING',
  READY: 'READY',
  ERROR: 'ERROR',
} as const;

export type _org_dash_platform_dapi_v0_GetBlockchainStatusResponse_Status =
  | 'NOT_STARTED'
  | 0
  | 'SYNCING'
  | 1
  | 'READY'
  | 2
  | 'ERROR'
  | 3

export type _org_dash_platform_dapi_v0_GetBlockchainStatusResponse_Status__Output = typeof _org_dash_platform_dapi_v0_GetBlockchainStatusResponse_Status[keyof typeof _org_dash_platform_dapi_v0_GetBlockchainStatusResponse_Status]

export interface _org_dash_platform_dapi_v0_GetBlockchainStatusResponse_Time {
  'now'?: (number);
  'offset'?: (number);
  'median'?: (number);
}

export interface _org_dash_platform_dapi_v0_GetBlockchainStatusResponse_Time__Output {
  'now': (number);
  'offset': (number);
  'median': (number);
}

export interface _org_dash_platform_dapi_v0_GetBlockchainStatusResponse_Version {
  'protocol'?: (number);
  'software'?: (number);
  'agent'?: (string);
}

export interface _org_dash_platform_dapi_v0_GetBlockchainStatusResponse_Version__Output {
  'protocol': (number);
  'software': (number);
  'agent': (string);
}

export interface GetBlockchainStatusResponse {
  'version'?: (_org_dash_platform_dapi_v0_GetBlockchainStatusResponse_Version | null);
  'time'?: (_org_dash_platform_dapi_v0_GetBlockchainStatusResponse_Time | null);
  'status'?: (_org_dash_platform_dapi_v0_GetBlockchainStatusResponse_Status);
  'syncProgress'?: (number | string);
  'chain'?: (_org_dash_platform_dapi_v0_GetBlockchainStatusResponse_Chain | null);
  'network'?: (_org_dash_platform_dapi_v0_GetBlockchainStatusResponse_Network | null);
}

export interface GetBlockchainStatusResponse__Output {
  'version': (_org_dash_platform_dapi_v0_GetBlockchainStatusResponse_Version__Output | null);
  'time': (_org_dash_platform_dapi_v0_GetBlockchainStatusResponse_Time__Output | null);
  'status': (_org_dash_platform_dapi_v0_GetBlockchainStatusResponse_Status__Output);
  'syncProgress': (number);
  'chain': (_org_dash_platform_dapi_v0_GetBlockchainStatusResponse_Chain__Output | null);
  'network': (_org_dash_platform_dapi_v0_GetBlockchainStatusResponse_Network__Output | null);
}
