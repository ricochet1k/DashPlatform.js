// Original file: ../../platform/packages/dapi-grpc/protos/core/v0/core.proto


export interface GetBlockRequest {
  'height'?: (number);
  'hash'?: (string);
  'block'?: "height"|"hash";
}

export interface GetBlockRequest__Output {
  'height'?: (number);
  'hash'?: (string);
  'block': "height"|"hash";
}
