// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

import type { Proof as _org_dash_platform_dapi_v0_Proof, Proof__Output as _org_dash_platform_dapi_v0_Proof__Output } from '../../../../../org/dash/platform/dapi/v0/Proof';
import type { ResponseMetadata as _org_dash_platform_dapi_v0_ResponseMetadata, ResponseMetadata__Output as _org_dash_platform_dapi_v0_ResponseMetadata__Output } from '../../../../../org/dash/platform/dapi/v0/ResponseMetadata';
import type { Long } from '@grpc/proto-loader';

export interface _org_dash_platform_dapi_v0_GetIdentityTokenBalancesResponse_GetIdentityTokenBalancesResponseV0 {
  'tokenBalances'?: (_org_dash_platform_dapi_v0_GetIdentityTokenBalancesResponse_GetIdentityTokenBalancesResponseV0_TokenBalances | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof | null);
  'metadata'?: (_org_dash_platform_dapi_v0_ResponseMetadata | null);
  'result'?: "tokenBalances"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetIdentityTokenBalancesResponse_GetIdentityTokenBalancesResponseV0__Output {
  'tokenBalances'?: (_org_dash_platform_dapi_v0_GetIdentityTokenBalancesResponse_GetIdentityTokenBalancesResponseV0_TokenBalances__Output | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof__Output | null);
  'metadata': (_org_dash_platform_dapi_v0_ResponseMetadata__Output | null);
  'result': "tokenBalances"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetIdentityTokenBalancesResponse_GetIdentityTokenBalancesResponseV0_TokenBalanceEntry {
  'tokenId'?: (Buffer | Uint8Array | string);
  'balance'?: (number | string | Long);
  '_balance'?: "balance";
}

export interface _org_dash_platform_dapi_v0_GetIdentityTokenBalancesResponse_GetIdentityTokenBalancesResponseV0_TokenBalanceEntry__Output {
  'tokenId': (Buffer);
  'balance'?: (string);
  '_balance': "balance";
}

export interface _org_dash_platform_dapi_v0_GetIdentityTokenBalancesResponse_GetIdentityTokenBalancesResponseV0_TokenBalances {
  'tokenBalances'?: (_org_dash_platform_dapi_v0_GetIdentityTokenBalancesResponse_GetIdentityTokenBalancesResponseV0_TokenBalanceEntry)[];
}

export interface _org_dash_platform_dapi_v0_GetIdentityTokenBalancesResponse_GetIdentityTokenBalancesResponseV0_TokenBalances__Output {
  'tokenBalances': (_org_dash_platform_dapi_v0_GetIdentityTokenBalancesResponse_GetIdentityTokenBalancesResponseV0_TokenBalanceEntry__Output)[];
}

export interface GetIdentityTokenBalancesResponse {
  'v0'?: (_org_dash_platform_dapi_v0_GetIdentityTokenBalancesResponse_GetIdentityTokenBalancesResponseV0 | null);
  'version'?: "v0";
}

export interface GetIdentityTokenBalancesResponse__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetIdentityTokenBalancesResponse_GetIdentityTokenBalancesResponseV0__Output | null);
  'version': "v0";
}
