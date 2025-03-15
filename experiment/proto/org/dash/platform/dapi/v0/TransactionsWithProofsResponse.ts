// Original file: ../../platform/packages/dapi-grpc/protos/core/v0/core.proto

import type { RawTransactions as _org_dash_platform_dapi_v0_RawTransactions, RawTransactions__Output as _org_dash_platform_dapi_v0_RawTransactions__Output } from '../../../../../org/dash/platform/dapi/v0/RawTransactions';
import type { InstantSendLockMessages as _org_dash_platform_dapi_v0_InstantSendLockMessages, InstantSendLockMessages__Output as _org_dash_platform_dapi_v0_InstantSendLockMessages__Output } from '../../../../../org/dash/platform/dapi/v0/InstantSendLockMessages';

export interface TransactionsWithProofsResponse {
  'rawTransactions'?: (_org_dash_platform_dapi_v0_RawTransactions | null);
  'instantSendLockMessages'?: (_org_dash_platform_dapi_v0_InstantSendLockMessages | null);
  'rawMerkleBlock'?: (Buffer | Uint8Array | string);
  'responses'?: "rawTransactions"|"instantSendLockMessages"|"rawMerkleBlock";
}

export interface TransactionsWithProofsResponse__Output {
  'rawTransactions'?: (_org_dash_platform_dapi_v0_RawTransactions__Output | null);
  'instantSendLockMessages'?: (_org_dash_platform_dapi_v0_InstantSendLockMessages__Output | null);
  'rawMerkleBlock'?: (Buffer);
  'responses': "rawTransactions"|"instantSendLockMessages"|"rawMerkleBlock";
}
