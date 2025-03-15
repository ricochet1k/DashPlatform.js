// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

import type { UInt32Value as _google_protobuf_UInt32Value, UInt32Value__Output as _google_protobuf_UInt32Value__Output } from '../../../../../google/protobuf/UInt32Value';
import type { Long } from '@grpc/proto-loader';

export interface _org_dash_platform_dapi_v0_GetDataContractHistoryRequest_GetDataContractHistoryRequestV0 {
  'id'?: (Buffer | Uint8Array | string);
  'limit'?: (_google_protobuf_UInt32Value | null);
  'offset'?: (_google_protobuf_UInt32Value | null);
  'startAtMs'?: (number | string | Long);
  'prove'?: (boolean);
}

export interface _org_dash_platform_dapi_v0_GetDataContractHistoryRequest_GetDataContractHistoryRequestV0__Output {
  'id': (Buffer);
  'limit': (_google_protobuf_UInt32Value__Output | null);
  'offset': (_google_protobuf_UInt32Value__Output | null);
  'startAtMs': (string);
  'prove': (boolean);
}

export interface GetDataContractHistoryRequest {
  'v0'?: (_org_dash_platform_dapi_v0_GetDataContractHistoryRequest_GetDataContractHistoryRequestV0 | null);
  'version'?: "v0";
}

export interface GetDataContractHistoryRequest__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetDataContractHistoryRequest_GetDataContractHistoryRequestV0__Output | null);
  'version': "v0";
}
