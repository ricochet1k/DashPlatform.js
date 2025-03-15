// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

import type { Proof as _org_dash_platform_dapi_v0_Proof, Proof__Output as _org_dash_platform_dapi_v0_Proof__Output } from '../../../../../org/dash/platform/dapi/v0/Proof';
import type { ResponseMetadata as _org_dash_platform_dapi_v0_ResponseMetadata, ResponseMetadata__Output as _org_dash_platform_dapi_v0_ResponseMetadata__Output } from '../../../../../org/dash/platform/dapi/v0/ResponseMetadata';

export interface _org_dash_platform_dapi_v0_GetGroupActionSignersResponse_GetGroupActionSignersResponseV0 {
  'groupActionSigners'?: (_org_dash_platform_dapi_v0_GetGroupActionSignersResponse_GetGroupActionSignersResponseV0_GroupActionSigners | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof | null);
  'metadata'?: (_org_dash_platform_dapi_v0_ResponseMetadata | null);
  'result'?: "groupActionSigners"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetGroupActionSignersResponse_GetGroupActionSignersResponseV0__Output {
  'groupActionSigners'?: (_org_dash_platform_dapi_v0_GetGroupActionSignersResponse_GetGroupActionSignersResponseV0_GroupActionSigners__Output | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof__Output | null);
  'metadata': (_org_dash_platform_dapi_v0_ResponseMetadata__Output | null);
  'result': "groupActionSigners"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetGroupActionSignersResponse_GetGroupActionSignersResponseV0_GroupActionSigner {
  'signerId'?: (Buffer | Uint8Array | string);
  'power'?: (number);
}

export interface _org_dash_platform_dapi_v0_GetGroupActionSignersResponse_GetGroupActionSignersResponseV0_GroupActionSigner__Output {
  'signerId': (Buffer);
  'power': (number);
}

export interface _org_dash_platform_dapi_v0_GetGroupActionSignersResponse_GetGroupActionSignersResponseV0_GroupActionSigners {
  'signers'?: (_org_dash_platform_dapi_v0_GetGroupActionSignersResponse_GetGroupActionSignersResponseV0_GroupActionSigner)[];
}

export interface _org_dash_platform_dapi_v0_GetGroupActionSignersResponse_GetGroupActionSignersResponseV0_GroupActionSigners__Output {
  'signers': (_org_dash_platform_dapi_v0_GetGroupActionSignersResponse_GetGroupActionSignersResponseV0_GroupActionSigner__Output)[];
}

export interface GetGroupActionSignersResponse {
  'v0'?: (_org_dash_platform_dapi_v0_GetGroupActionSignersResponse_GetGroupActionSignersResponseV0 | null);
  'version'?: "v0";
}

export interface GetGroupActionSignersResponse__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetGroupActionSignersResponse_GetGroupActionSignersResponseV0__Output | null);
  'version': "v0";
}
