// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

import type { Long } from '@grpc/proto-loader';

export interface ResponseMetadata {
  'height'?: (number | string | Long);
  'coreChainLockedHeight'?: (number);
  'epoch'?: (number);
  'timeMs'?: (number | string | Long);
  'protocolVersion'?: (number);
  'chainId'?: (string);
}

export interface ResponseMetadata__Output {
  'height': (string);
  'coreChainLockedHeight': (number);
  'epoch': (number);
  'timeMs': (string);
  'protocolVersion': (number);
  'chainId': (string);
}
