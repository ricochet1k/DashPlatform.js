// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto


export interface _org_dash_platform_dapi_v0_WaitForStateTransitionResultRequest_WaitForStateTransitionResultRequestV0 {
  'stateTransitionHash'?: (Buffer | Uint8Array | string);
  'prove'?: (boolean);
}

export interface _org_dash_platform_dapi_v0_WaitForStateTransitionResultRequest_WaitForStateTransitionResultRequestV0__Output {
  'stateTransitionHash': (Buffer);
  'prove': (boolean);
}

export interface WaitForStateTransitionResultRequest {
  'v0'?: (_org_dash_platform_dapi_v0_WaitForStateTransitionResultRequest_WaitForStateTransitionResultRequestV0 | null);
  'version'?: "v0";
}

export interface WaitForStateTransitionResultRequest__Output {
  'v0'?: (_org_dash_platform_dapi_v0_WaitForStateTransitionResultRequest_WaitForStateTransitionResultRequestV0__Output | null);
  'version': "v0";
}
