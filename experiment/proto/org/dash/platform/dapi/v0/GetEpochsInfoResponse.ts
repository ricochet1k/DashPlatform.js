// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

import type { Proof as _org_dash_platform_dapi_v0_Proof, Proof__Output as _org_dash_platform_dapi_v0_Proof__Output } from '../../../../../org/dash/platform/dapi/v0/Proof';
import type { ResponseMetadata as _org_dash_platform_dapi_v0_ResponseMetadata, ResponseMetadata__Output as _org_dash_platform_dapi_v0_ResponseMetadata__Output } from '../../../../../org/dash/platform/dapi/v0/ResponseMetadata';
import type { Long } from '@grpc/proto-loader';

export interface _org_dash_platform_dapi_v0_GetEpochsInfoResponse_GetEpochsInfoResponseV0_EpochInfo {
  'number'?: (number);
  'firstBlockHeight'?: (number | string | Long);
  'firstCoreBlockHeight'?: (number);
  'startTime'?: (number | string | Long);
  'feeMultiplier'?: (number | string);
  'protocolVersion'?: (number);
}

export interface _org_dash_platform_dapi_v0_GetEpochsInfoResponse_GetEpochsInfoResponseV0_EpochInfo__Output {
  'number': (number);
  'firstBlockHeight': (string);
  'firstCoreBlockHeight': (number);
  'startTime': (string);
  'feeMultiplier': (number);
  'protocolVersion': (number);
}

export interface _org_dash_platform_dapi_v0_GetEpochsInfoResponse_GetEpochsInfoResponseV0_EpochInfos {
  'epochInfos'?: (_org_dash_platform_dapi_v0_GetEpochsInfoResponse_GetEpochsInfoResponseV0_EpochInfo)[];
}

export interface _org_dash_platform_dapi_v0_GetEpochsInfoResponse_GetEpochsInfoResponseV0_EpochInfos__Output {
  'epochInfos': (_org_dash_platform_dapi_v0_GetEpochsInfoResponse_GetEpochsInfoResponseV0_EpochInfo__Output)[];
}

export interface _org_dash_platform_dapi_v0_GetEpochsInfoResponse_GetEpochsInfoResponseV0 {
  'epochs'?: (_org_dash_platform_dapi_v0_GetEpochsInfoResponse_GetEpochsInfoResponseV0_EpochInfos | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof | null);
  'metadata'?: (_org_dash_platform_dapi_v0_ResponseMetadata | null);
  'result'?: "epochs"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetEpochsInfoResponse_GetEpochsInfoResponseV0__Output {
  'epochs'?: (_org_dash_platform_dapi_v0_GetEpochsInfoResponse_GetEpochsInfoResponseV0_EpochInfos__Output | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof__Output | null);
  'metadata': (_org_dash_platform_dapi_v0_ResponseMetadata__Output | null);
  'result': "epochs"|"proof";
}

export interface GetEpochsInfoResponse {
  'v0'?: (_org_dash_platform_dapi_v0_GetEpochsInfoResponse_GetEpochsInfoResponseV0 | null);
  'version'?: "v0";
}

export interface GetEpochsInfoResponse__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetEpochsInfoResponse_GetEpochsInfoResponseV0__Output | null);
  'version': "v0";
}
