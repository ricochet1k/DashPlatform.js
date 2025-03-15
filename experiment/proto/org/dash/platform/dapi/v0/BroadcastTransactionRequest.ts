// Original file: ../../platform/packages/dapi-grpc/protos/core/v0/core.proto


export interface BroadcastTransactionRequest {
  'transaction'?: (Buffer | Uint8Array | string);
  'allowHighFees'?: (boolean);
  'bypassLimits'?: (boolean);
}

export interface BroadcastTransactionRequest__Output {
  'transaction': (Buffer);
  'allowHighFees': (boolean);
  'bypassLimits': (boolean);
}
