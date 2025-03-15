// Original file: ../../platform/packages/dapi-grpc/protos/core/v0/core.proto


export interface GetTransactionResponse {
  'transaction'?: (Buffer | Uint8Array | string);
  'blockHash'?: (Buffer | Uint8Array | string);
  'height'?: (number);
  'confirmations'?: (number);
  'isInstantLocked'?: (boolean);
  'isChainLocked'?: (boolean);
}

export interface GetTransactionResponse__Output {
  'transaction': (Buffer);
  'blockHash': (Buffer);
  'height': (number);
  'confirmations': (number);
  'isInstantLocked': (boolean);
  'isChainLocked': (boolean);
}
