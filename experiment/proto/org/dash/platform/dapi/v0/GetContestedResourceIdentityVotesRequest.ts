// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

import type { UInt32Value as _google_protobuf_UInt32Value, UInt32Value__Output as _google_protobuf_UInt32Value__Output } from '../../../../../google/protobuf/UInt32Value';

export interface _org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesRequest_GetContestedResourceIdentityVotesRequestV0 {
  'identityId'?: (Buffer | Uint8Array | string);
  'limit'?: (_google_protobuf_UInt32Value | null);
  'offset'?: (_google_protobuf_UInt32Value | null);
  'orderAscending'?: (boolean);
  'startAtVotePollIdInfo'?: (_org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesRequest_GetContestedResourceIdentityVotesRequestV0_StartAtVotePollIdInfo | null);
  'prove'?: (boolean);
  '_startAtVotePollIdInfo'?: "startAtVotePollIdInfo";
}

export interface _org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesRequest_GetContestedResourceIdentityVotesRequestV0__Output {
  'identityId': (Buffer);
  'limit': (_google_protobuf_UInt32Value__Output | null);
  'offset': (_google_protobuf_UInt32Value__Output | null);
  'orderAscending': (boolean);
  'startAtVotePollIdInfo'?: (_org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesRequest_GetContestedResourceIdentityVotesRequestV0_StartAtVotePollIdInfo__Output | null);
  'prove': (boolean);
  '_startAtVotePollIdInfo': "startAtVotePollIdInfo";
}

export interface _org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesRequest_GetContestedResourceIdentityVotesRequestV0_StartAtVotePollIdInfo {
  'startAtPollIdentifier'?: (Buffer | Uint8Array | string);
  'startPollIdentifierIncluded'?: (boolean);
}

export interface _org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesRequest_GetContestedResourceIdentityVotesRequestV0_StartAtVotePollIdInfo__Output {
  'startAtPollIdentifier': (Buffer);
  'startPollIdentifierIncluded': (boolean);
}

export interface GetContestedResourceIdentityVotesRequest {
  'v0'?: (_org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesRequest_GetContestedResourceIdentityVotesRequestV0 | null);
  'version'?: "v0";
}

export interface GetContestedResourceIdentityVotesRequest__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetContestedResourceIdentityVotesRequest_GetContestedResourceIdentityVotesRequestV0__Output | null);
  'version': "v0";
}
