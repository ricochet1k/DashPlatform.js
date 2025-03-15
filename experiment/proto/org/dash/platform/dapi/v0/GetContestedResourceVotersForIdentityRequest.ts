// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto


export interface _org_dash_platform_dapi_v0_GetContestedResourceVotersForIdentityRequest_GetContestedResourceVotersForIdentityRequestV0 {
  'contractId'?: (Buffer | Uint8Array | string);
  'documentTypeName'?: (string);
  'indexName'?: (string);
  'indexValues'?: (Buffer | Uint8Array | string)[];
  'contestantId'?: (Buffer | Uint8Array | string);
  'startAtIdentifierInfo'?: (_org_dash_platform_dapi_v0_GetContestedResourceVotersForIdentityRequest_GetContestedResourceVotersForIdentityRequestV0_StartAtIdentifierInfo | null);
  'count'?: (number);
  'orderAscending'?: (boolean);
  'prove'?: (boolean);
  '_startAtIdentifierInfo'?: "startAtIdentifierInfo";
  '_count'?: "count";
}

export interface _org_dash_platform_dapi_v0_GetContestedResourceVotersForIdentityRequest_GetContestedResourceVotersForIdentityRequestV0__Output {
  'contractId': (Buffer);
  'documentTypeName': (string);
  'indexName': (string);
  'indexValues': (Buffer)[];
  'contestantId': (Buffer);
  'startAtIdentifierInfo'?: (_org_dash_platform_dapi_v0_GetContestedResourceVotersForIdentityRequest_GetContestedResourceVotersForIdentityRequestV0_StartAtIdentifierInfo__Output | null);
  'count'?: (number);
  'orderAscending': (boolean);
  'prove': (boolean);
  '_startAtIdentifierInfo': "startAtIdentifierInfo";
  '_count': "count";
}

export interface _org_dash_platform_dapi_v0_GetContestedResourceVotersForIdentityRequest_GetContestedResourceVotersForIdentityRequestV0_StartAtIdentifierInfo {
  'startIdentifier'?: (Buffer | Uint8Array | string);
  'startIdentifierIncluded'?: (boolean);
}

export interface _org_dash_platform_dapi_v0_GetContestedResourceVotersForIdentityRequest_GetContestedResourceVotersForIdentityRequestV0_StartAtIdentifierInfo__Output {
  'startIdentifier': (Buffer);
  'startIdentifierIncluded': (boolean);
}

export interface GetContestedResourceVotersForIdentityRequest {
  'v0'?: (_org_dash_platform_dapi_v0_GetContestedResourceVotersForIdentityRequest_GetContestedResourceVotersForIdentityRequestV0 | null);
  'version'?: "v0";
}

export interface GetContestedResourceVotersForIdentityRequest__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetContestedResourceVotersForIdentityRequest_GetContestedResourceVotersForIdentityRequestV0__Output | null);
  'version': "v0";
}
