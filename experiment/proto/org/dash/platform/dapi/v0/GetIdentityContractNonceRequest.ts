// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto


export interface _org_dash_platform_dapi_v0_GetIdentityContractNonceRequest_GetIdentityContractNonceRequestV0 {
  'identityId'?: (Buffer | Uint8Array | string);
  'contractId'?: (Buffer | Uint8Array | string);
  'prove'?: (boolean);
}

export interface _org_dash_platform_dapi_v0_GetIdentityContractNonceRequest_GetIdentityContractNonceRequestV0__Output {
  'identityId': (Buffer);
  'contractId': (Buffer);
  'prove': (boolean);
}

export interface GetIdentityContractNonceRequest {
  'v0'?: (_org_dash_platform_dapi_v0_GetIdentityContractNonceRequest_GetIdentityContractNonceRequestV0 | null);
  'version'?: "v0";
}

export interface GetIdentityContractNonceRequest__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetIdentityContractNonceRequest_GetIdentityContractNonceRequestV0__Output | null);
  'version': "v0";
}
