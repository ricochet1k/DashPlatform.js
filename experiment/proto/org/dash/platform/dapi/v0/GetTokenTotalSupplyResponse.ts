// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

import type { Proof as _org_dash_platform_dapi_v0_Proof, Proof__Output as _org_dash_platform_dapi_v0_Proof__Output } from '../../../../../org/dash/platform/dapi/v0/Proof';
import type { ResponseMetadata as _org_dash_platform_dapi_v0_ResponseMetadata, ResponseMetadata__Output as _org_dash_platform_dapi_v0_ResponseMetadata__Output } from '../../../../../org/dash/platform/dapi/v0/ResponseMetadata';
import type { Long } from '@grpc/proto-loader';

export interface _org_dash_platform_dapi_v0_GetTokenTotalSupplyResponse_GetTokenTotalSupplyResponseV0 {
  'tokenTotalSupply'?: (_org_dash_platform_dapi_v0_GetTokenTotalSupplyResponse_GetTokenTotalSupplyResponseV0_TokenTotalSupplyEntry | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof | null);
  'metadata'?: (_org_dash_platform_dapi_v0_ResponseMetadata | null);
  'result'?: "tokenTotalSupply"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetTokenTotalSupplyResponse_GetTokenTotalSupplyResponseV0__Output {
  'tokenTotalSupply'?: (_org_dash_platform_dapi_v0_GetTokenTotalSupplyResponse_GetTokenTotalSupplyResponseV0_TokenTotalSupplyEntry__Output | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof__Output | null);
  'metadata': (_org_dash_platform_dapi_v0_ResponseMetadata__Output | null);
  'result': "tokenTotalSupply"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetTokenTotalSupplyResponse_GetTokenTotalSupplyResponseV0_TokenTotalSupplyEntry {
  'tokenId'?: (Buffer | Uint8Array | string);
  'totalAggregatedAmountInUserAccounts'?: (number | string | Long);
  'totalSystemAmount'?: (number | string | Long);
}

export interface _org_dash_platform_dapi_v0_GetTokenTotalSupplyResponse_GetTokenTotalSupplyResponseV0_TokenTotalSupplyEntry__Output {
  'tokenId': (Buffer);
  'totalAggregatedAmountInUserAccounts': (string);
  'totalSystemAmount': (string);
}

export interface GetTokenTotalSupplyResponse {
  'v0'?: (_org_dash_platform_dapi_v0_GetTokenTotalSupplyResponse_GetTokenTotalSupplyResponseV0 | null);
  'version'?: "v0";
}

export interface GetTokenTotalSupplyResponse__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetTokenTotalSupplyResponse_GetTokenTotalSupplyResponseV0__Output | null);
  'version': "v0";
}
