// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

import type { Proof as _org_dash_platform_dapi_v0_Proof, Proof__Output as _org_dash_platform_dapi_v0_Proof__Output } from '../../../../../org/dash/platform/dapi/v0/Proof';
import type { ResponseMetadata as _org_dash_platform_dapi_v0_ResponseMetadata, ResponseMetadata__Output as _org_dash_platform_dapi_v0_ResponseMetadata__Output } from '../../../../../org/dash/platform/dapi/v0/ResponseMetadata';

export interface _org_dash_platform_dapi_v0_GetIdentitiesTokenInfosResponse_GetIdentitiesTokenInfosResponseV0 {
  'identityTokenInfos'?: (_org_dash_platform_dapi_v0_GetIdentitiesTokenInfosResponse_GetIdentitiesTokenInfosResponseV0_IdentityTokenInfos | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof | null);
  'metadata'?: (_org_dash_platform_dapi_v0_ResponseMetadata | null);
  'result'?: "identityTokenInfos"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetIdentitiesTokenInfosResponse_GetIdentitiesTokenInfosResponseV0__Output {
  'identityTokenInfos'?: (_org_dash_platform_dapi_v0_GetIdentitiesTokenInfosResponse_GetIdentitiesTokenInfosResponseV0_IdentityTokenInfos__Output | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof__Output | null);
  'metadata': (_org_dash_platform_dapi_v0_ResponseMetadata__Output | null);
  'result': "identityTokenInfos"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetIdentitiesTokenInfosResponse_GetIdentitiesTokenInfosResponseV0_IdentityTokenInfos {
  'tokenInfos'?: (_org_dash_platform_dapi_v0_GetIdentitiesTokenInfosResponse_GetIdentitiesTokenInfosResponseV0_TokenInfoEntry)[];
}

export interface _org_dash_platform_dapi_v0_GetIdentitiesTokenInfosResponse_GetIdentitiesTokenInfosResponseV0_IdentityTokenInfos__Output {
  'tokenInfos': (_org_dash_platform_dapi_v0_GetIdentitiesTokenInfosResponse_GetIdentitiesTokenInfosResponseV0_TokenInfoEntry__Output)[];
}

export interface _org_dash_platform_dapi_v0_GetIdentitiesTokenInfosResponse_GetIdentitiesTokenInfosResponseV0_TokenIdentityInfoEntry {
  'frozen'?: (boolean);
}

export interface _org_dash_platform_dapi_v0_GetIdentitiesTokenInfosResponse_GetIdentitiesTokenInfosResponseV0_TokenIdentityInfoEntry__Output {
  'frozen': (boolean);
}

export interface _org_dash_platform_dapi_v0_GetIdentitiesTokenInfosResponse_GetIdentitiesTokenInfosResponseV0_TokenInfoEntry {
  'identityId'?: (Buffer | Uint8Array | string);
  'info'?: (_org_dash_platform_dapi_v0_GetIdentitiesTokenInfosResponse_GetIdentitiesTokenInfosResponseV0_TokenIdentityInfoEntry | null);
  '_info'?: "info";
}

export interface _org_dash_platform_dapi_v0_GetIdentitiesTokenInfosResponse_GetIdentitiesTokenInfosResponseV0_TokenInfoEntry__Output {
  'identityId': (Buffer);
  'info'?: (_org_dash_platform_dapi_v0_GetIdentitiesTokenInfosResponse_GetIdentitiesTokenInfosResponseV0_TokenIdentityInfoEntry__Output | null);
  '_info': "info";
}

export interface GetIdentitiesTokenInfosResponse {
  'v0'?: (_org_dash_platform_dapi_v0_GetIdentitiesTokenInfosResponse_GetIdentitiesTokenInfosResponseV0 | null);
  'version'?: "v0";
}

export interface GetIdentitiesTokenInfosResponse__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetIdentitiesTokenInfosResponse_GetIdentitiesTokenInfosResponseV0__Output | null);
  'version': "v0";
}
