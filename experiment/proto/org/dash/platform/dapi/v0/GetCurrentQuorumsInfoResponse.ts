// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

import type { ResponseMetadata as _org_dash_platform_dapi_v0_ResponseMetadata, ResponseMetadata__Output as _org_dash_platform_dapi_v0_ResponseMetadata__Output } from '../../../../../org/dash/platform/dapi/v0/ResponseMetadata';

export interface _org_dash_platform_dapi_v0_GetCurrentQuorumsInfoResponse_GetCurrentQuorumsInfoResponseV0 {
  'quorumHashes'?: (Buffer | Uint8Array | string)[];
  'currentQuorumHash'?: (Buffer | Uint8Array | string);
  'validatorSets'?: (_org_dash_platform_dapi_v0_GetCurrentQuorumsInfoResponse_ValidatorSetV0)[];
  'lastBlockProposer'?: (Buffer | Uint8Array | string);
  'metadata'?: (_org_dash_platform_dapi_v0_ResponseMetadata | null);
}

export interface _org_dash_platform_dapi_v0_GetCurrentQuorumsInfoResponse_GetCurrentQuorumsInfoResponseV0__Output {
  'quorumHashes': (Buffer)[];
  'currentQuorumHash': (Buffer);
  'validatorSets': (_org_dash_platform_dapi_v0_GetCurrentQuorumsInfoResponse_ValidatorSetV0__Output)[];
  'lastBlockProposer': (Buffer);
  'metadata': (_org_dash_platform_dapi_v0_ResponseMetadata__Output | null);
}

export interface _org_dash_platform_dapi_v0_GetCurrentQuorumsInfoResponse_ValidatorSetV0 {
  'quorumHash'?: (Buffer | Uint8Array | string);
  'coreHeight'?: (number);
  'members'?: (_org_dash_platform_dapi_v0_GetCurrentQuorumsInfoResponse_ValidatorV0)[];
  'thresholdPublicKey'?: (Buffer | Uint8Array | string);
}

export interface _org_dash_platform_dapi_v0_GetCurrentQuorumsInfoResponse_ValidatorSetV0__Output {
  'quorumHash': (Buffer);
  'coreHeight': (number);
  'members': (_org_dash_platform_dapi_v0_GetCurrentQuorumsInfoResponse_ValidatorV0__Output)[];
  'thresholdPublicKey': (Buffer);
}

export interface _org_dash_platform_dapi_v0_GetCurrentQuorumsInfoResponse_ValidatorV0 {
  'proTxHash'?: (Buffer | Uint8Array | string);
  'nodeIp'?: (string);
  'isBanned'?: (boolean);
}

export interface _org_dash_platform_dapi_v0_GetCurrentQuorumsInfoResponse_ValidatorV0__Output {
  'proTxHash': (Buffer);
  'nodeIp': (string);
  'isBanned': (boolean);
}

export interface GetCurrentQuorumsInfoResponse {
  'v0'?: (_org_dash_platform_dapi_v0_GetCurrentQuorumsInfoResponse_GetCurrentQuorumsInfoResponseV0 | null);
  'version'?: "v0";
}

export interface GetCurrentQuorumsInfoResponse__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetCurrentQuorumsInfoResponse_GetCurrentQuorumsInfoResponseV0__Output | null);
  'version': "v0";
}
