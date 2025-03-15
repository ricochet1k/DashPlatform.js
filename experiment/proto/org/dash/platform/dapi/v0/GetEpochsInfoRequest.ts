// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

import type { UInt32Value as _google_protobuf_UInt32Value, UInt32Value__Output as _google_protobuf_UInt32Value__Output } from '../../../../../google/protobuf/UInt32Value';

export interface _org_dash_platform_dapi_v0_GetEpochsInfoRequest_GetEpochsInfoRequestV0 {
  'startEpoch'?: (_google_protobuf_UInt32Value | null);
  'count'?: (number);
  'ascending'?: (boolean);
  'prove'?: (boolean);
}

export interface _org_dash_platform_dapi_v0_GetEpochsInfoRequest_GetEpochsInfoRequestV0__Output {
  'startEpoch': (_google_protobuf_UInt32Value__Output | null);
  'count': (number);
  'ascending': (boolean);
  'prove': (boolean);
}

export interface GetEpochsInfoRequest {
  'v0'?: (_org_dash_platform_dapi_v0_GetEpochsInfoRequest_GetEpochsInfoRequestV0 | null);
  'version'?: "v0";
}

export interface GetEpochsInfoRequest__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetEpochsInfoRequest_GetEpochsInfoRequestV0__Output | null);
  'version': "v0";
}
