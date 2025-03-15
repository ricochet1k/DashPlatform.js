// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

import type { Long } from '@grpc/proto-loader';

export interface _org_dash_platform_dapi_v0_GetStatusResponse_GetStatusResponseV0_Chain {
  'catchingUp'?: (boolean);
  'latestBlockHash'?: (Buffer | Uint8Array | string);
  'latestAppHash'?: (Buffer | Uint8Array | string);
  'latestBlockHeight'?: (number | string | Long);
  'earliestBlockHash'?: (Buffer | Uint8Array | string);
  'earliestAppHash'?: (Buffer | Uint8Array | string);
  'earliestBlockHeight'?: (number | string | Long);
  'maxPeerBlockHeight'?: (number | string | Long);
  'coreChainLockedHeight'?: (number);
  '_coreChainLockedHeight'?: "coreChainLockedHeight";
}

export interface _org_dash_platform_dapi_v0_GetStatusResponse_GetStatusResponseV0_Chain__Output {
  'catchingUp': (boolean);
  'latestBlockHash': (Buffer);
  'latestAppHash': (Buffer);
  'latestBlockHeight': (string);
  'earliestBlockHash': (Buffer);
  'earliestAppHash': (Buffer);
  'earliestBlockHeight': (string);
  'maxPeerBlockHeight': (string);
  'coreChainLockedHeight'?: (number);
  '_coreChainLockedHeight': "coreChainLockedHeight";
}

export interface _org_dash_platform_dapi_v0_GetStatusResponse_GetStatusResponseV0_Version_Protocol_Drive {
  'latest'?: (number);
  'current'?: (number);
}

export interface _org_dash_platform_dapi_v0_GetStatusResponse_GetStatusResponseV0_Version_Protocol_Drive__Output {
  'latest': (number);
  'current': (number);
}

export interface _org_dash_platform_dapi_v0_GetStatusResponse_GetStatusResponseV0 {
  'version'?: (_org_dash_platform_dapi_v0_GetStatusResponse_GetStatusResponseV0_Version | null);
  'node'?: (_org_dash_platform_dapi_v0_GetStatusResponse_GetStatusResponseV0_Node | null);
  'chain'?: (_org_dash_platform_dapi_v0_GetStatusResponse_GetStatusResponseV0_Chain | null);
  'network'?: (_org_dash_platform_dapi_v0_GetStatusResponse_GetStatusResponseV0_Network | null);
  'stateSync'?: (_org_dash_platform_dapi_v0_GetStatusResponse_GetStatusResponseV0_StateSync | null);
  'time'?: (_org_dash_platform_dapi_v0_GetStatusResponse_GetStatusResponseV0_Time | null);
}

export interface _org_dash_platform_dapi_v0_GetStatusResponse_GetStatusResponseV0__Output {
  'version': (_org_dash_platform_dapi_v0_GetStatusResponse_GetStatusResponseV0_Version__Output | null);
  'node': (_org_dash_platform_dapi_v0_GetStatusResponse_GetStatusResponseV0_Node__Output | null);
  'chain': (_org_dash_platform_dapi_v0_GetStatusResponse_GetStatusResponseV0_Chain__Output | null);
  'network': (_org_dash_platform_dapi_v0_GetStatusResponse_GetStatusResponseV0_Network__Output | null);
  'stateSync': (_org_dash_platform_dapi_v0_GetStatusResponse_GetStatusResponseV0_StateSync__Output | null);
  'time': (_org_dash_platform_dapi_v0_GetStatusResponse_GetStatusResponseV0_Time__Output | null);
}

export interface _org_dash_platform_dapi_v0_GetStatusResponse_GetStatusResponseV0_Network {
  'chainId'?: (string);
  'peersCount'?: (number);
  'listening'?: (boolean);
}

export interface _org_dash_platform_dapi_v0_GetStatusResponse_GetStatusResponseV0_Network__Output {
  'chainId': (string);
  'peersCount': (number);
  'listening': (boolean);
}

export interface _org_dash_platform_dapi_v0_GetStatusResponse_GetStatusResponseV0_Node {
  'id'?: (Buffer | Uint8Array | string);
  'proTxHash'?: (Buffer | Uint8Array | string);
  '_proTxHash'?: "proTxHash";
}

export interface _org_dash_platform_dapi_v0_GetStatusResponse_GetStatusResponseV0_Node__Output {
  'id': (Buffer);
  'proTxHash'?: (Buffer);
  '_proTxHash': "proTxHash";
}

export interface _org_dash_platform_dapi_v0_GetStatusResponse_GetStatusResponseV0_Version_Protocol {
  'tenderdash'?: (_org_dash_platform_dapi_v0_GetStatusResponse_GetStatusResponseV0_Version_Protocol_Tenderdash | null);
  'drive'?: (_org_dash_platform_dapi_v0_GetStatusResponse_GetStatusResponseV0_Version_Protocol_Drive | null);
}

export interface _org_dash_platform_dapi_v0_GetStatusResponse_GetStatusResponseV0_Version_Protocol__Output {
  'tenderdash': (_org_dash_platform_dapi_v0_GetStatusResponse_GetStatusResponseV0_Version_Protocol_Tenderdash__Output | null);
  'drive': (_org_dash_platform_dapi_v0_GetStatusResponse_GetStatusResponseV0_Version_Protocol_Drive__Output | null);
}

export interface _org_dash_platform_dapi_v0_GetStatusResponse_GetStatusResponseV0_Version_Software {
  'dapi'?: (string);
  'drive'?: (string);
  'tenderdash'?: (string);
  '_drive'?: "drive";
  '_tenderdash'?: "tenderdash";
}

export interface _org_dash_platform_dapi_v0_GetStatusResponse_GetStatusResponseV0_Version_Software__Output {
  'dapi': (string);
  'drive'?: (string);
  'tenderdash'?: (string);
  '_drive': "drive";
  '_tenderdash': "tenderdash";
}

export interface _org_dash_platform_dapi_v0_GetStatusResponse_GetStatusResponseV0_StateSync {
  'totalSyncedTime'?: (number | string | Long);
  'remainingTime'?: (number | string | Long);
  'totalSnapshots'?: (number);
  'chunkProcessAvgTime'?: (number | string | Long);
  'snapshotHeight'?: (number | string | Long);
  'snapshotChunksCount'?: (number | string | Long);
  'backfilledBlocks'?: (number | string | Long);
  'backfillBlocksTotal'?: (number | string | Long);
}

export interface _org_dash_platform_dapi_v0_GetStatusResponse_GetStatusResponseV0_StateSync__Output {
  'totalSyncedTime': (string);
  'remainingTime': (string);
  'totalSnapshots': (number);
  'chunkProcessAvgTime': (string);
  'snapshotHeight': (string);
  'snapshotChunksCount': (string);
  'backfilledBlocks': (string);
  'backfillBlocksTotal': (string);
}

export interface _org_dash_platform_dapi_v0_GetStatusResponse_GetStatusResponseV0_Version_Protocol_Tenderdash {
  'p2p'?: (number);
  'block'?: (number);
}

export interface _org_dash_platform_dapi_v0_GetStatusResponse_GetStatusResponseV0_Version_Protocol_Tenderdash__Output {
  'p2p': (number);
  'block': (number);
}

export interface _org_dash_platform_dapi_v0_GetStatusResponse_GetStatusResponseV0_Time {
  'local'?: (number | string | Long);
  'block'?: (number | string | Long);
  'genesis'?: (number | string | Long);
  'epoch'?: (number);
  '_block'?: "block";
  '_genesis'?: "genesis";
  '_epoch'?: "epoch";
}

export interface _org_dash_platform_dapi_v0_GetStatusResponse_GetStatusResponseV0_Time__Output {
  'local': (string);
  'block'?: (string);
  'genesis'?: (string);
  'epoch'?: (number);
  '_block': "block";
  '_genesis': "genesis";
  '_epoch': "epoch";
}

export interface _org_dash_platform_dapi_v0_GetStatusResponse_GetStatusResponseV0_Version {
  'software'?: (_org_dash_platform_dapi_v0_GetStatusResponse_GetStatusResponseV0_Version_Software | null);
  'protocol'?: (_org_dash_platform_dapi_v0_GetStatusResponse_GetStatusResponseV0_Version_Protocol | null);
}

export interface _org_dash_platform_dapi_v0_GetStatusResponse_GetStatusResponseV0_Version__Output {
  'software': (_org_dash_platform_dapi_v0_GetStatusResponse_GetStatusResponseV0_Version_Software__Output | null);
  'protocol': (_org_dash_platform_dapi_v0_GetStatusResponse_GetStatusResponseV0_Version_Protocol__Output | null);
}

export interface GetStatusResponse {
  'v0'?: (_org_dash_platform_dapi_v0_GetStatusResponse_GetStatusResponseV0 | null);
  'version'?: "v0";
}

export interface GetStatusResponse__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetStatusResponse_GetStatusResponseV0__Output | null);
  'version': "v0";
}
