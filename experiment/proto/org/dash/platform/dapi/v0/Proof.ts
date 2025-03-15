// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto


export interface Proof {
  'grovedbProof'?: (Buffer | Uint8Array | string);
  'quorumHash'?: (Buffer | Uint8Array | string);
  'signature'?: (Buffer | Uint8Array | string);
  'round'?: (number);
  'blockIdHash'?: (Buffer | Uint8Array | string);
  'quorumType'?: (number);
}

export interface Proof__Output {
  'grovedbProof': (Buffer);
  'quorumHash': (Buffer);
  'signature': (Buffer);
  'round': (number);
  'blockIdHash': (Buffer);
  'quorumType': (number);
}
