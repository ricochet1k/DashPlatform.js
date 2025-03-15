// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

import type { KeyPurpose as _org_dash_platform_dapi_v0_KeyPurpose, KeyPurpose__Output as _org_dash_platform_dapi_v0_KeyPurpose__Output } from '../../../../../org/dash/platform/dapi/v0/KeyPurpose';

export interface _org_dash_platform_dapi_v0_GetIdentitiesContractKeysRequest_GetIdentitiesContractKeysRequestV0 {
  'identitiesIds'?: (Buffer | Uint8Array | string)[];
  'contractId'?: (Buffer | Uint8Array | string);
  'documentTypeName'?: (string);
  'purposes'?: (_org_dash_platform_dapi_v0_KeyPurpose)[];
  'prove'?: (boolean);
  '_documentTypeName'?: "documentTypeName";
}

export interface _org_dash_platform_dapi_v0_GetIdentitiesContractKeysRequest_GetIdentitiesContractKeysRequestV0__Output {
  'identitiesIds': (Buffer)[];
  'contractId': (Buffer);
  'documentTypeName'?: (string);
  'purposes': (_org_dash_platform_dapi_v0_KeyPurpose__Output)[];
  'prove': (boolean);
  '_documentTypeName': "documentTypeName";
}

export interface GetIdentitiesContractKeysRequest {
  'v0'?: (_org_dash_platform_dapi_v0_GetIdentitiesContractKeysRequest_GetIdentitiesContractKeysRequestV0 | null);
  'version'?: "v0";
}

export interface GetIdentitiesContractKeysRequest__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetIdentitiesContractKeysRequest_GetIdentitiesContractKeysRequestV0__Output | null);
  'version': "v0";
}
