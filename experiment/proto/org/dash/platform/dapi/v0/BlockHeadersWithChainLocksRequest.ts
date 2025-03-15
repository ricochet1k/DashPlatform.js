// Original file: ../../platform/packages/dapi-grpc/protos/core/v0/core.proto


export interface BlockHeadersWithChainLocksRequest {
  'fromBlockHash'?: (Buffer | Uint8Array | string);
  'fromBlockHeight'?: (number);
  'count'?: (number);
  'fromBlock'?: "fromBlockHash"|"fromBlockHeight";
}

export interface BlockHeadersWithChainLocksRequest__Output {
  'fromBlockHash'?: (Buffer);
  'fromBlockHeight'?: (number);
  'count': (number);
  'fromBlock': "fromBlockHash"|"fromBlockHeight";
}
