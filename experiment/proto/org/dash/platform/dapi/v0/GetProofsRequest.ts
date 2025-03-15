// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto


export interface _org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_VoteStatusRequest_ContestedResourceVoteStatusRequest {
  'contractId'?: (Buffer | Uint8Array | string);
  'documentTypeName'?: (string);
  'indexName'?: (string);
  'indexValues'?: (Buffer | Uint8Array | string)[];
  'voterIdentifier'?: (Buffer | Uint8Array | string);
}

export interface _org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_VoteStatusRequest_ContestedResourceVoteStatusRequest__Output {
  'contractId': (Buffer);
  'documentTypeName': (string);
  'indexName': (string);
  'indexValues': (Buffer)[];
  'voterIdentifier': (Buffer);
}

export interface _org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_ContractRequest {
  'contractId'?: (Buffer | Uint8Array | string);
}

export interface _org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_ContractRequest__Output {
  'contractId': (Buffer);
}

// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

export const _org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_DocumentRequest_DocumentContestedStatus = {
  NOT_CONTESTED: 'NOT_CONTESTED',
  MAYBE_CONTESTED: 'MAYBE_CONTESTED',
  CONTESTED: 'CONTESTED',
} as const;

export type _org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_DocumentRequest_DocumentContestedStatus =
  | 'NOT_CONTESTED'
  | 0
  | 'MAYBE_CONTESTED'
  | 1
  | 'CONTESTED'
  | 2

export type _org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_DocumentRequest_DocumentContestedStatus__Output = typeof _org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_DocumentRequest_DocumentContestedStatus[keyof typeof _org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_DocumentRequest_DocumentContestedStatus]

export interface _org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_DocumentRequest {
  'contractId'?: (Buffer | Uint8Array | string);
  'documentType'?: (string);
  'documentTypeKeepsHistory'?: (boolean);
  'documentId'?: (Buffer | Uint8Array | string);
  'documentContestedStatus'?: (_org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_DocumentRequest_DocumentContestedStatus);
}

export interface _org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_DocumentRequest__Output {
  'contractId': (Buffer);
  'documentType': (string);
  'documentTypeKeepsHistory': (boolean);
  'documentId': (Buffer);
  'documentContestedStatus': (_org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_DocumentRequest_DocumentContestedStatus__Output);
}

export interface _org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0 {
  'identities'?: (_org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_IdentityRequest)[];
  'contracts'?: (_org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_ContractRequest)[];
  'documents'?: (_org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_DocumentRequest)[];
  'votes'?: (_org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_VoteStatusRequest)[];
  'identityTokenBalances'?: (_org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_IdentityTokenBalanceRequest)[];
  'identityTokenInfos'?: (_org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_IdentityTokenInfoRequest)[];
  'tokenStatuses'?: (_org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_TokenStatusRequest)[];
}

export interface _org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0__Output {
  'identities': (_org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_IdentityRequest__Output)[];
  'contracts': (_org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_ContractRequest__Output)[];
  'documents': (_org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_DocumentRequest__Output)[];
  'votes': (_org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_VoteStatusRequest__Output)[];
  'identityTokenBalances': (_org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_IdentityTokenBalanceRequest__Output)[];
  'identityTokenInfos': (_org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_IdentityTokenInfoRequest__Output)[];
  'tokenStatuses': (_org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_TokenStatusRequest__Output)[];
}

export interface _org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_IdentityRequest {
  'identityId'?: (Buffer | Uint8Array | string);
  'requestType'?: (_org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_IdentityRequest_Type);
}

export interface _org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_IdentityRequest__Output {
  'identityId': (Buffer);
  'requestType': (_org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_IdentityRequest_Type__Output);
}

export interface _org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_IdentityTokenBalanceRequest {
  'tokenId'?: (Buffer | Uint8Array | string);
  'identityId'?: (Buffer | Uint8Array | string);
}

export interface _org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_IdentityTokenBalanceRequest__Output {
  'tokenId': (Buffer);
  'identityId': (Buffer);
}

export interface _org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_IdentityTokenInfoRequest {
  'tokenId'?: (Buffer | Uint8Array | string);
  'identityId'?: (Buffer | Uint8Array | string);
}

export interface _org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_IdentityTokenInfoRequest__Output {
  'tokenId': (Buffer);
  'identityId': (Buffer);
}

export interface _org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_TokenStatusRequest {
  'tokenId'?: (Buffer | Uint8Array | string);
}

export interface _org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_TokenStatusRequest__Output {
  'tokenId': (Buffer);
}

// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

export const _org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_IdentityRequest_Type = {
  FULL_IDENTITY: 'FULL_IDENTITY',
  BALANCE: 'BALANCE',
  KEYS: 'KEYS',
  REVISION: 'REVISION',
} as const;

export type _org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_IdentityRequest_Type =
  | 'FULL_IDENTITY'
  | 0
  | 'BALANCE'
  | 1
  | 'KEYS'
  | 2
  | 'REVISION'
  | 3

export type _org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_IdentityRequest_Type__Output = typeof _org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_IdentityRequest_Type[keyof typeof _org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_IdentityRequest_Type]

export interface _org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_VoteStatusRequest {
  'contestedResourceVoteStatusRequest'?: (_org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_VoteStatusRequest_ContestedResourceVoteStatusRequest | null);
  'requestType'?: "contestedResourceVoteStatusRequest";
}

export interface _org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_VoteStatusRequest__Output {
  'contestedResourceVoteStatusRequest'?: (_org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0_VoteStatusRequest_ContestedResourceVoteStatusRequest__Output | null);
  'requestType': "contestedResourceVoteStatusRequest";
}

export interface GetProofsRequest {
  'v0'?: (_org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0 | null);
  'version'?: "v0";
}

export interface GetProofsRequest__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetProofsRequest_GetProofsRequestV0__Output | null);
  'version': "v0";
}
