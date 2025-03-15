// Original file: ../../platform/packages/dapi-grpc/protos/core/v0/core.proto

import type { BloomFilter as _org_dash_platform_dapi_v0_BloomFilter, BloomFilter__Output as _org_dash_platform_dapi_v0_BloomFilter__Output } from '../../../../../org/dash/platform/dapi/v0/BloomFilter';

export interface TransactionsWithProofsRequest {
  'bloomFilter'?: (_org_dash_platform_dapi_v0_BloomFilter | null);
  'fromBlockHash'?: (Buffer | Uint8Array | string);
  'fromBlockHeight'?: (number);
  'count'?: (number);
  'sendTransactionHashes'?: (boolean);
  'fromBlock'?: "fromBlockHash"|"fromBlockHeight";
}

export interface TransactionsWithProofsRequest__Output {
  'bloomFilter': (_org_dash_platform_dapi_v0_BloomFilter__Output | null);
  'fromBlockHash'?: (Buffer);
  'fromBlockHeight'?: (number);
  'count': (number);
  'sendTransactionHashes': (boolean);
  'fromBlock': "fromBlockHash"|"fromBlockHeight";
}
