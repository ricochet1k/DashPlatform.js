// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto


export interface _org_dash_platform_dapi_v0_GetDocumentsRequest_GetDocumentsRequestV0 {
  'dataContractId'?: (Buffer | Uint8Array | string);
  'documentType'?: (string);
  'where'?: (Buffer | Uint8Array | string);
  'orderBy'?: (Buffer | Uint8Array | string);
  'limit'?: (number);
  'startAfter'?: (Buffer | Uint8Array | string);
  'startAt'?: (Buffer | Uint8Array | string);
  'prove'?: (boolean);
  'start'?: "startAfter"|"startAt";
}

export interface _org_dash_platform_dapi_v0_GetDocumentsRequest_GetDocumentsRequestV0__Output {
  'dataContractId': (Buffer);
  'documentType': (string);
  'where': (Buffer);
  'orderBy': (Buffer);
  'limit': (number);
  'startAfter'?: (Buffer);
  'startAt'?: (Buffer);
  'prove': (boolean);
  'start': "startAfter"|"startAt";
}

export interface GetDocumentsRequest {
  'v0'?: (_org_dash_platform_dapi_v0_GetDocumentsRequest_GetDocumentsRequestV0 | null);
  'version'?: "v0";
}

export interface GetDocumentsRequest__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetDocumentsRequest_GetDocumentsRequestV0__Output | null);
  'version': "v0";
}
