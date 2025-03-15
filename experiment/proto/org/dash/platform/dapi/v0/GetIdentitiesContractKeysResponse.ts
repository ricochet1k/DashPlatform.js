// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

import type { Proof as _org_dash_platform_dapi_v0_Proof, Proof__Output as _org_dash_platform_dapi_v0_Proof__Output } from '../../../../../org/dash/platform/dapi/v0/Proof';
import type { ResponseMetadata as _org_dash_platform_dapi_v0_ResponseMetadata, ResponseMetadata__Output as _org_dash_platform_dapi_v0_ResponseMetadata__Output } from '../../../../../org/dash/platform/dapi/v0/ResponseMetadata';
import type { KeyPurpose as _org_dash_platform_dapi_v0_KeyPurpose, KeyPurpose__Output as _org_dash_platform_dapi_v0_KeyPurpose__Output } from '../../../../../org/dash/platform/dapi/v0/KeyPurpose';

export interface _org_dash_platform_dapi_v0_GetIdentitiesContractKeysResponse_GetIdentitiesContractKeysResponseV0 {
  'identitiesKeys'?: (_org_dash_platform_dapi_v0_GetIdentitiesContractKeysResponse_GetIdentitiesContractKeysResponseV0_IdentitiesKeys | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof | null);
  'metadata'?: (_org_dash_platform_dapi_v0_ResponseMetadata | null);
  'result'?: "identitiesKeys"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetIdentitiesContractKeysResponse_GetIdentitiesContractKeysResponseV0__Output {
  'identitiesKeys'?: (_org_dash_platform_dapi_v0_GetIdentitiesContractKeysResponse_GetIdentitiesContractKeysResponseV0_IdentitiesKeys__Output | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof__Output | null);
  'metadata': (_org_dash_platform_dapi_v0_ResponseMetadata__Output | null);
  'result': "identitiesKeys"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetIdentitiesContractKeysResponse_GetIdentitiesContractKeysResponseV0_IdentitiesKeys {
  'entries'?: (_org_dash_platform_dapi_v0_GetIdentitiesContractKeysResponse_GetIdentitiesContractKeysResponseV0_IdentityKeys)[];
}

export interface _org_dash_platform_dapi_v0_GetIdentitiesContractKeysResponse_GetIdentitiesContractKeysResponseV0_IdentitiesKeys__Output {
  'entries': (_org_dash_platform_dapi_v0_GetIdentitiesContractKeysResponse_GetIdentitiesContractKeysResponseV0_IdentityKeys__Output)[];
}

export interface _org_dash_platform_dapi_v0_GetIdentitiesContractKeysResponse_GetIdentitiesContractKeysResponseV0_IdentityKeys {
  'identityId'?: (Buffer | Uint8Array | string);
  'keys'?: (_org_dash_platform_dapi_v0_GetIdentitiesContractKeysResponse_GetIdentitiesContractKeysResponseV0_PurposeKeys)[];
}

export interface _org_dash_platform_dapi_v0_GetIdentitiesContractKeysResponse_GetIdentitiesContractKeysResponseV0_IdentityKeys__Output {
  'identityId': (Buffer);
  'keys': (_org_dash_platform_dapi_v0_GetIdentitiesContractKeysResponse_GetIdentitiesContractKeysResponseV0_PurposeKeys__Output)[];
}

export interface _org_dash_platform_dapi_v0_GetIdentitiesContractKeysResponse_GetIdentitiesContractKeysResponseV0_PurposeKeys {
  'purpose'?: (_org_dash_platform_dapi_v0_KeyPurpose);
  'keysBytes'?: (Buffer | Uint8Array | string)[];
}

export interface _org_dash_platform_dapi_v0_GetIdentitiesContractKeysResponse_GetIdentitiesContractKeysResponseV0_PurposeKeys__Output {
  'purpose': (_org_dash_platform_dapi_v0_KeyPurpose__Output);
  'keysBytes': (Buffer)[];
}

export interface GetIdentitiesContractKeysResponse {
  'v0'?: (_org_dash_platform_dapi_v0_GetIdentitiesContractKeysResponse_GetIdentitiesContractKeysResponseV0 | null);
  'version'?: "v0";
}

export interface GetIdentitiesContractKeysResponse__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetIdentitiesContractKeysResponse_GetIdentitiesContractKeysResponseV0__Output | null);
  'version': "v0";
}
