// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

import type { BytesValue as _google_protobuf_BytesValue, BytesValue__Output as _google_protobuf_BytesValue__Output } from '../../../../../google/protobuf/BytesValue';
import type { Proof as _org_dash_platform_dapi_v0_Proof, Proof__Output as _org_dash_platform_dapi_v0_Proof__Output } from '../../../../../org/dash/platform/dapi/v0/Proof';
import type { ResponseMetadata as _org_dash_platform_dapi_v0_ResponseMetadata, ResponseMetadata__Output as _org_dash_platform_dapi_v0_ResponseMetadata__Output } from '../../../../../org/dash/platform/dapi/v0/ResponseMetadata';

export interface _org_dash_platform_dapi_v0_GetDataContractsResponse_DataContractEntry {
  'identifier'?: (Buffer | Uint8Array | string);
  'dataContract'?: (_google_protobuf_BytesValue | null);
}

export interface _org_dash_platform_dapi_v0_GetDataContractsResponse_DataContractEntry__Output {
  'identifier': (Buffer);
  'dataContract': (_google_protobuf_BytesValue__Output | null);
}

export interface _org_dash_platform_dapi_v0_GetDataContractsResponse_DataContracts {
  'dataContractEntries'?: (_org_dash_platform_dapi_v0_GetDataContractsResponse_DataContractEntry)[];
}

export interface _org_dash_platform_dapi_v0_GetDataContractsResponse_DataContracts__Output {
  'dataContractEntries': (_org_dash_platform_dapi_v0_GetDataContractsResponse_DataContractEntry__Output)[];
}

export interface _org_dash_platform_dapi_v0_GetDataContractsResponse_GetDataContractsResponseV0 {
  'dataContracts'?: (_org_dash_platform_dapi_v0_GetDataContractsResponse_DataContracts | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof | null);
  'metadata'?: (_org_dash_platform_dapi_v0_ResponseMetadata | null);
  'result'?: "dataContracts"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetDataContractsResponse_GetDataContractsResponseV0__Output {
  'dataContracts'?: (_org_dash_platform_dapi_v0_GetDataContractsResponse_DataContracts__Output | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof__Output | null);
  'metadata': (_org_dash_platform_dapi_v0_ResponseMetadata__Output | null);
  'result': "dataContracts"|"proof";
}

export interface GetDataContractsResponse {
  'v0'?: (_org_dash_platform_dapi_v0_GetDataContractsResponse_GetDataContractsResponseV0 | null);
  'version'?: "v0";
}

export interface GetDataContractsResponse__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetDataContractsResponse_GetDataContractsResponseV0__Output | null);
  'version': "v0";
}
