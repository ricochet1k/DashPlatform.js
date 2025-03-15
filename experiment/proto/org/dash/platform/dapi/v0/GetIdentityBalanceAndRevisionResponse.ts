// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

import type { Proof as _org_dash_platform_dapi_v0_Proof, Proof__Output as _org_dash_platform_dapi_v0_Proof__Output } from '../../../../../org/dash/platform/dapi/v0/Proof';
import type { ResponseMetadata as _org_dash_platform_dapi_v0_ResponseMetadata, ResponseMetadata__Output as _org_dash_platform_dapi_v0_ResponseMetadata__Output } from '../../../../../org/dash/platform/dapi/v0/ResponseMetadata';
import type { Long } from '@grpc/proto-loader';

export interface _org_dash_platform_dapi_v0_GetIdentityBalanceAndRevisionResponse_GetIdentityBalanceAndRevisionResponseV0_BalanceAndRevision {
  'balance'?: (number | string | Long);
  'revision'?: (number | string | Long);
}

export interface _org_dash_platform_dapi_v0_GetIdentityBalanceAndRevisionResponse_GetIdentityBalanceAndRevisionResponseV0_BalanceAndRevision__Output {
  'balance': (string);
  'revision': (string);
}

export interface _org_dash_platform_dapi_v0_GetIdentityBalanceAndRevisionResponse_GetIdentityBalanceAndRevisionResponseV0 {
  'balanceAndRevision'?: (_org_dash_platform_dapi_v0_GetIdentityBalanceAndRevisionResponse_GetIdentityBalanceAndRevisionResponseV0_BalanceAndRevision | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof | null);
  'metadata'?: (_org_dash_platform_dapi_v0_ResponseMetadata | null);
  'result'?: "balanceAndRevision"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetIdentityBalanceAndRevisionResponse_GetIdentityBalanceAndRevisionResponseV0__Output {
  'balanceAndRevision'?: (_org_dash_platform_dapi_v0_GetIdentityBalanceAndRevisionResponse_GetIdentityBalanceAndRevisionResponseV0_BalanceAndRevision__Output | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof__Output | null);
  'metadata': (_org_dash_platform_dapi_v0_ResponseMetadata__Output | null);
  'result': "balanceAndRevision"|"proof";
}

export interface GetIdentityBalanceAndRevisionResponse {
  'v0'?: (_org_dash_platform_dapi_v0_GetIdentityBalanceAndRevisionResponse_GetIdentityBalanceAndRevisionResponseV0 | null);
  'version'?: "v0";
}

export interface GetIdentityBalanceAndRevisionResponse__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetIdentityBalanceAndRevisionResponse_GetIdentityBalanceAndRevisionResponseV0__Output | null);
  'version': "v0";
}
