// Original file: ../../platform/packages/dapi-grpc/protos/core/v0/core.proto


export interface BloomFilter {
  'vData'?: (Buffer | Uint8Array | string);
  'nHashFuncs'?: (number);
  'nTweak'?: (number);
  'nFlags'?: (number);
}

export interface BloomFilter__Output {
  'vData': (Buffer);
  'nHashFuncs': (number);
  'nTweak': (number);
  'nFlags': (number);
}
