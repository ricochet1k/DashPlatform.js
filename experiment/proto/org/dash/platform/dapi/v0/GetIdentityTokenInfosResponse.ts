// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

import type { Proof as _org_dash_platform_dapi_v0_Proof, Proof__Output as _org_dash_platform_dapi_v0_Proof__Output } from '../../../../../org/dash/platform/dapi/v0/Proof';
import type { ResponseMetadata as _org_dash_platform_dapi_v0_ResponseMetadata, ResponseMetadata__Output as _org_dash_platform_dapi_v0_ResponseMetadata__Output } from '../../../../../org/dash/platform/dapi/v0/ResponseMetadata';

export interface _org_dash_platform_dapi_v0_GetIdentityTokenInfosResponse_GetIdentityTokenInfosResponseV0 {
  'tokenInfos'?: (_org_dash_platform_dapi_v0_GetIdentityTokenInfosResponse_GetIdentityTokenInfosResponseV0_TokenInfos | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof | null);
  'metadata'?: (_org_dash_platform_dapi_v0_ResponseMetadata | null);
  'result'?: "tokenInfos"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetIdentityTokenInfosResponse_GetIdentityTokenInfosResponseV0__Output {
  'tokenInfos'?: (_org_dash_platform_dapi_v0_GetIdentityTokenInfosResponse_GetIdentityTokenInfosResponseV0_TokenInfos__Output | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof__Output | null);
  'metadata': (_org_dash_platform_dapi_v0_ResponseMetadata__Output | null);
  'result': "tokenInfos"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetIdentityTokenInfosResponse_GetIdentityTokenInfosResponseV0_TokenIdentityInfoEntry {
  'frozen'?: (boolean);
}

export interface _org_dash_platform_dapi_v0_GetIdentityTokenInfosResponse_GetIdentityTokenInfosResponseV0_TokenIdentityInfoEntry__Output {
  'frozen': (boolean);
}

export interface _org_dash_platform_dapi_v0_GetIdentityTokenInfosResponse_GetIdentityTokenInfosResponseV0_TokenInfoEntry {
  'tokenId'?: (Buffer | Uint8Array | string);
  'info'?: (_org_dash_platform_dapi_v0_GetIdentityTokenInfosResponse_GetIdentityTokenInfosResponseV0_TokenIdentityInfoEntry | null);
  '_info'?: "info";
}

export interface _org_dash_platform_dapi_v0_GetIdentityTokenInfosResponse_GetIdentityTokenInfosResponseV0_TokenInfoEntry__Output {
  'tokenId': (Buffer);
  'info'?: (_org_dash_platform_dapi_v0_GetIdentityTokenInfosResponse_GetIdentityTokenInfosResponseV0_TokenIdentityInfoEntry__Output | null);
  '_info': "info";
}

export interface _org_dash_platform_dapi_v0_GetIdentityTokenInfosResponse_GetIdentityTokenInfosResponseV0_TokenInfos {
  'tokenInfos'?: (_org_dash_platform_dapi_v0_GetIdentityTokenInfosResponse_GetIdentityTokenInfosResponseV0_TokenInfoEntry)[];
}

export interface _org_dash_platform_dapi_v0_GetIdentityTokenInfosResponse_GetIdentityTokenInfosResponseV0_TokenInfos__Output {
  'tokenInfos': (_org_dash_platform_dapi_v0_GetIdentityTokenInfosResponse_GetIdentityTokenInfosResponseV0_TokenInfoEntry__Output)[];
}

export interface GetIdentityTokenInfosResponse {
  'v0'?: (_org_dash_platform_dapi_v0_GetIdentityTokenInfosResponse_GetIdentityTokenInfosResponseV0 | null);
  'version'?: "v0";
}

export interface GetIdentityTokenInfosResponse__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetIdentityTokenInfosResponse_GetIdentityTokenInfosResponseV0__Output | null);
  'version': "v0";
}
