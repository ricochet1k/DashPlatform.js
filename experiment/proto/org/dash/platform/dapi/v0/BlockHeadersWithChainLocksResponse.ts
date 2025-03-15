// Original file: ../../platform/packages/dapi-grpc/protos/core/v0/core.proto

import type { BlockHeaders as _org_dash_platform_dapi_v0_BlockHeaders, BlockHeaders__Output as _org_dash_platform_dapi_v0_BlockHeaders__Output } from '../../../../../org/dash/platform/dapi/v0/BlockHeaders';

export interface BlockHeadersWithChainLocksResponse {
  'blockHeaders'?: (_org_dash_platform_dapi_v0_BlockHeaders | null);
  'chainLock'?: (Buffer | Uint8Array | string);
  'responses'?: "blockHeaders"|"chainLock";
}

export interface BlockHeadersWithChainLocksResponse__Output {
  'blockHeaders'?: (_org_dash_platform_dapi_v0_BlockHeaders__Output | null);
  'chainLock'?: (Buffer);
  'responses': "blockHeaders"|"chainLock";
}
