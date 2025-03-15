// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

import type { Proof as _org_dash_platform_dapi_v0_Proof, Proof__Output as _org_dash_platform_dapi_v0_Proof__Output } from '../../../../../org/dash/platform/dapi/v0/Proof';
import type { ResponseMetadata as _org_dash_platform_dapi_v0_ResponseMetadata, ResponseMetadata__Output as _org_dash_platform_dapi_v0_ResponseMetadata__Output } from '../../../../../org/dash/platform/dapi/v0/ResponseMetadata';
import type { Long } from '@grpc/proto-loader';

export interface _org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksResponse_GetEvonodesProposedEpochBlocksResponseV0_EvonodeProposedBlocks {
  'proTxHash'?: (Buffer | Uint8Array | string);
  'count'?: (number | string | Long);
}

export interface _org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksResponse_GetEvonodesProposedEpochBlocksResponseV0_EvonodeProposedBlocks__Output {
  'proTxHash': (Buffer);
  'count': (string);
}

export interface _org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksResponse_GetEvonodesProposedEpochBlocksResponseV0_EvonodesProposedBlocks {
  'evonodesProposedBlockCounts'?: (_org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksResponse_GetEvonodesProposedEpochBlocksResponseV0_EvonodeProposedBlocks)[];
}

export interface _org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksResponse_GetEvonodesProposedEpochBlocksResponseV0_EvonodesProposedBlocks__Output {
  'evonodesProposedBlockCounts': (_org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksResponse_GetEvonodesProposedEpochBlocksResponseV0_EvonodeProposedBlocks__Output)[];
}

export interface _org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksResponse_GetEvonodesProposedEpochBlocksResponseV0 {
  'evonodesProposedBlockCountsInfo'?: (_org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksResponse_GetEvonodesProposedEpochBlocksResponseV0_EvonodesProposedBlocks | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof | null);
  'metadata'?: (_org_dash_platform_dapi_v0_ResponseMetadata | null);
  'result'?: "evonodesProposedBlockCountsInfo"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksResponse_GetEvonodesProposedEpochBlocksResponseV0__Output {
  'evonodesProposedBlockCountsInfo'?: (_org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksResponse_GetEvonodesProposedEpochBlocksResponseV0_EvonodesProposedBlocks__Output | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof__Output | null);
  'metadata': (_org_dash_platform_dapi_v0_ResponseMetadata__Output | null);
  'result': "evonodesProposedBlockCountsInfo"|"proof";
}

export interface GetEvonodesProposedEpochBlocksResponse {
  'v0'?: (_org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksResponse_GetEvonodesProposedEpochBlocksResponseV0 | null);
  'version'?: "v0";
}

export interface GetEvonodesProposedEpochBlocksResponse__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetEvonodesProposedEpochBlocksResponse_GetEvonodesProposedEpochBlocksResponseV0__Output | null);
  'version': "v0";
}
