// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto


export interface StateTransitionBroadcastError {
  'code'?: (number);
  'message'?: (string);
  'data'?: (Buffer | Uint8Array | string);
}

export interface StateTransitionBroadcastError__Output {
  'code': (number);
  'message': (string);
  'data': (Buffer);
}
