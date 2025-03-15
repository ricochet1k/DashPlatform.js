// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

import type { StateTransitionBroadcastError as _org_dash_platform_dapi_v0_StateTransitionBroadcastError, StateTransitionBroadcastError__Output as _org_dash_platform_dapi_v0_StateTransitionBroadcastError__Output } from '../../../../../org/dash/platform/dapi/v0/StateTransitionBroadcastError';
import type { Proof as _org_dash_platform_dapi_v0_Proof, Proof__Output as _org_dash_platform_dapi_v0_Proof__Output } from '../../../../../org/dash/platform/dapi/v0/Proof';
import type { ResponseMetadata as _org_dash_platform_dapi_v0_ResponseMetadata, ResponseMetadata__Output as _org_dash_platform_dapi_v0_ResponseMetadata__Output } from '../../../../../org/dash/platform/dapi/v0/ResponseMetadata';

export interface _org_dash_platform_dapi_v0_WaitForStateTransitionResultResponse_WaitForStateTransitionResultResponseV0 {
  'error'?: (_org_dash_platform_dapi_v0_StateTransitionBroadcastError | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof | null);
  'metadata'?: (_org_dash_platform_dapi_v0_ResponseMetadata | null);
  'result'?: "error"|"proof";
}

export interface _org_dash_platform_dapi_v0_WaitForStateTransitionResultResponse_WaitForStateTransitionResultResponseV0__Output {
  'error'?: (_org_dash_platform_dapi_v0_StateTransitionBroadcastError__Output | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof__Output | null);
  'metadata': (_org_dash_platform_dapi_v0_ResponseMetadata__Output | null);
  'result': "error"|"proof";
}

export interface WaitForStateTransitionResultResponse {
  'v0'?: (_org_dash_platform_dapi_v0_WaitForStateTransitionResultResponse_WaitForStateTransitionResultResponseV0 | null);
  'version'?: "v0";
}

export interface WaitForStateTransitionResultResponse__Output {
  'v0'?: (_org_dash_platform_dapi_v0_WaitForStateTransitionResultResponse_WaitForStateTransitionResultResponseV0__Output | null);
  'version': "v0";
}
