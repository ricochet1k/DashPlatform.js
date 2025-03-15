// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

import type { Proof as _org_dash_platform_dapi_v0_Proof, Proof__Output as _org_dash_platform_dapi_v0_Proof__Output } from '../../../../../org/dash/platform/dapi/v0/Proof';
import type { ResponseMetadata as _org_dash_platform_dapi_v0_ResponseMetadata, ResponseMetadata__Output as _org_dash_platform_dapi_v0_ResponseMetadata__Output } from '../../../../../org/dash/platform/dapi/v0/ResponseMetadata';
import type { Long } from '@grpc/proto-loader';

export interface _org_dash_platform_dapi_v0_GetIdentityContractNonceResponse_GetIdentityContractNonceResponseV0 {
  'identityContractNonce'?: (number | string | Long);
  'proof'?: (_org_dash_platform_dapi_v0_Proof | null);
  'metadata'?: (_org_dash_platform_dapi_v0_ResponseMetadata | null);
  'result'?: "identityContractNonce"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetIdentityContractNonceResponse_GetIdentityContractNonceResponseV0__Output {
  'identityContractNonce'?: (string);
  'proof'?: (_org_dash_platform_dapi_v0_Proof__Output | null);
  'metadata': (_org_dash_platform_dapi_v0_ResponseMetadata__Output | null);
  'result': "identityContractNonce"|"proof";
}

export interface GetIdentityContractNonceResponse {
  'v0'?: (_org_dash_platform_dapi_v0_GetIdentityContractNonceResponse_GetIdentityContractNonceResponseV0 | null);
  'version'?: "v0";
}

export interface GetIdentityContractNonceResponse__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetIdentityContractNonceResponse_GetIdentityContractNonceResponseV0__Output | null);
  'version': "v0";
}
