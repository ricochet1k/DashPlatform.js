// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

import type { Proof as _org_dash_platform_dapi_v0_Proof, Proof__Output as _org_dash_platform_dapi_v0_Proof__Output } from '../../../../../org/dash/platform/dapi/v0/Proof';
import type { ResponseMetadata as _org_dash_platform_dapi_v0_ResponseMetadata, ResponseMetadata__Output as _org_dash_platform_dapi_v0_ResponseMetadata__Output } from '../../../../../org/dash/platform/dapi/v0/ResponseMetadata';
import type { Long } from '@grpc/proto-loader';

export interface _org_dash_platform_dapi_v0_GetIdentitiesBalancesResponse_GetIdentitiesBalancesResponseV0 {
  'identitiesBalances'?: (_org_dash_platform_dapi_v0_GetIdentitiesBalancesResponse_GetIdentitiesBalancesResponseV0_IdentitiesBalances | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof | null);
  'metadata'?: (_org_dash_platform_dapi_v0_ResponseMetadata | null);
  'result'?: "identitiesBalances"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetIdentitiesBalancesResponse_GetIdentitiesBalancesResponseV0__Output {
  'identitiesBalances'?: (_org_dash_platform_dapi_v0_GetIdentitiesBalancesResponse_GetIdentitiesBalancesResponseV0_IdentitiesBalances__Output | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof__Output | null);
  'metadata': (_org_dash_platform_dapi_v0_ResponseMetadata__Output | null);
  'result': "identitiesBalances"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetIdentitiesBalancesResponse_GetIdentitiesBalancesResponseV0_IdentitiesBalances {
  'entries'?: (_org_dash_platform_dapi_v0_GetIdentitiesBalancesResponse_GetIdentitiesBalancesResponseV0_IdentityBalance)[];
}

export interface _org_dash_platform_dapi_v0_GetIdentitiesBalancesResponse_GetIdentitiesBalancesResponseV0_IdentitiesBalances__Output {
  'entries': (_org_dash_platform_dapi_v0_GetIdentitiesBalancesResponse_GetIdentitiesBalancesResponseV0_IdentityBalance__Output)[];
}

export interface _org_dash_platform_dapi_v0_GetIdentitiesBalancesResponse_GetIdentitiesBalancesResponseV0_IdentityBalance {
  'identityId'?: (Buffer | Uint8Array | string);
  'balance'?: (number | string | Long);
  '_balance'?: "balance";
}

export interface _org_dash_platform_dapi_v0_GetIdentitiesBalancesResponse_GetIdentitiesBalancesResponseV0_IdentityBalance__Output {
  'identityId': (Buffer);
  'balance'?: (string);
  '_balance': "balance";
}

export interface GetIdentitiesBalancesResponse {
  'v0'?: (_org_dash_platform_dapi_v0_GetIdentitiesBalancesResponse_GetIdentitiesBalancesResponseV0 | null);
  'version'?: "v0";
}

export interface GetIdentitiesBalancesResponse__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetIdentitiesBalancesResponse_GetIdentitiesBalancesResponseV0__Output | null);
  'version': "v0";
}
