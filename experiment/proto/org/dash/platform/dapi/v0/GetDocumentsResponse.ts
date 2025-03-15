// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

import type { Proof as _org_dash_platform_dapi_v0_Proof, Proof__Output as _org_dash_platform_dapi_v0_Proof__Output } from '../../../../../org/dash/platform/dapi/v0/Proof';
import type { ResponseMetadata as _org_dash_platform_dapi_v0_ResponseMetadata, ResponseMetadata__Output as _org_dash_platform_dapi_v0_ResponseMetadata__Output } from '../../../../../org/dash/platform/dapi/v0/ResponseMetadata';

export interface _org_dash_platform_dapi_v0_GetDocumentsResponse_GetDocumentsResponseV0_Documents {
  'documents'?: (Buffer | Uint8Array | string)[];
}

export interface _org_dash_platform_dapi_v0_GetDocumentsResponse_GetDocumentsResponseV0_Documents__Output {
  'documents': (Buffer)[];
}

export interface _org_dash_platform_dapi_v0_GetDocumentsResponse_GetDocumentsResponseV0 {
  'documents'?: (_org_dash_platform_dapi_v0_GetDocumentsResponse_GetDocumentsResponseV0_Documents | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof | null);
  'metadata'?: (_org_dash_platform_dapi_v0_ResponseMetadata | null);
  'result'?: "documents"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetDocumentsResponse_GetDocumentsResponseV0__Output {
  'documents'?: (_org_dash_platform_dapi_v0_GetDocumentsResponse_GetDocumentsResponseV0_Documents__Output | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof__Output | null);
  'metadata': (_org_dash_platform_dapi_v0_ResponseMetadata__Output | null);
  'result': "documents"|"proof";
}

export interface GetDocumentsResponse {
  'v0'?: (_org_dash_platform_dapi_v0_GetDocumentsResponse_GetDocumentsResponseV0 | null);
  'version'?: "v0";
}

export interface GetDocumentsResponse__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetDocumentsResponse_GetDocumentsResponseV0__Output | null);
  'version': "v0";
}
