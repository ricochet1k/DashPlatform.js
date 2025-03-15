// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

import type { Proof as _org_dash_platform_dapi_v0_Proof, Proof__Output as _org_dash_platform_dapi_v0_Proof__Output } from '../../../../../org/dash/platform/dapi/v0/Proof';
import type { ResponseMetadata as _org_dash_platform_dapi_v0_ResponseMetadata, ResponseMetadata__Output as _org_dash_platform_dapi_v0_ResponseMetadata__Output } from '../../../../../org/dash/platform/dapi/v0/ResponseMetadata';
import type { Long } from '@grpc/proto-loader';

export interface _org_dash_platform_dapi_v0_GetIdentitiesTokenBalancesResponse_GetIdentitiesTokenBalancesResponseV0 {
  'identityTokenBalances'?: (_org_dash_platform_dapi_v0_GetIdentitiesTokenBalancesResponse_GetIdentitiesTokenBalancesResponseV0_IdentityTokenBalances | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof | null);
  'metadata'?: (_org_dash_platform_dapi_v0_ResponseMetadata | null);
  'result'?: "identityTokenBalances"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetIdentitiesTokenBalancesResponse_GetIdentitiesTokenBalancesResponseV0__Output {
  'identityTokenBalances'?: (_org_dash_platform_dapi_v0_GetIdentitiesTokenBalancesResponse_GetIdentitiesTokenBalancesResponseV0_IdentityTokenBalances__Output | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof__Output | null);
  'metadata': (_org_dash_platform_dapi_v0_ResponseMetadata__Output | null);
  'result': "identityTokenBalances"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetIdentitiesTokenBalancesResponse_GetIdentitiesTokenBalancesResponseV0_IdentityTokenBalanceEntry {
  'identityId'?: (Buffer | Uint8Array | string);
  'balance'?: (number | string | Long);
  '_balance'?: "balance";
}

export interface _org_dash_platform_dapi_v0_GetIdentitiesTokenBalancesResponse_GetIdentitiesTokenBalancesResponseV0_IdentityTokenBalanceEntry__Output {
  'identityId': (Buffer);
  'balance'?: (string);
  '_balance': "balance";
}

export interface _org_dash_platform_dapi_v0_GetIdentitiesTokenBalancesResponse_GetIdentitiesTokenBalancesResponseV0_IdentityTokenBalances {
  'identityTokenBalances'?: (_org_dash_platform_dapi_v0_GetIdentitiesTokenBalancesResponse_GetIdentitiesTokenBalancesResponseV0_IdentityTokenBalanceEntry)[];
}

export interface _org_dash_platform_dapi_v0_GetIdentitiesTokenBalancesResponse_GetIdentitiesTokenBalancesResponseV0_IdentityTokenBalances__Output {
  'identityTokenBalances': (_org_dash_platform_dapi_v0_GetIdentitiesTokenBalancesResponse_GetIdentitiesTokenBalancesResponseV0_IdentityTokenBalanceEntry__Output)[];
}

export interface GetIdentitiesTokenBalancesResponse {
  'v0'?: (_org_dash_platform_dapi_v0_GetIdentitiesTokenBalancesResponse_GetIdentitiesTokenBalancesResponseV0 | null);
  'version'?: "v0";
}

export interface GetIdentitiesTokenBalancesResponse__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetIdentitiesTokenBalancesResponse_GetIdentitiesTokenBalancesResponseV0__Output | null);
  'version': "v0";
}
