// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto


export interface _org_dash_platform_dapi_v0_GetDataContractRequest_GetDataContractRequestV0 {
  'id'?: (Buffer | Uint8Array | string);
  'prove'?: (boolean);
}

export interface _org_dash_platform_dapi_v0_GetDataContractRequest_GetDataContractRequestV0__Output {
  'id': (Buffer);
  'prove': (boolean);
}

export interface GetDataContractRequest {
  'v0'?: (_org_dash_platform_dapi_v0_GetDataContractRequest_GetDataContractRequestV0 | null);
  'version'?: "v0";
}

export interface GetDataContractRequest__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetDataContractRequest_GetDataContractRequestV0__Output | null);
  'version': "v0";
}
