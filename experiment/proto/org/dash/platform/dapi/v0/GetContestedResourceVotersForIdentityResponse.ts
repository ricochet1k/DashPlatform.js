// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

import type { Proof as _org_dash_platform_dapi_v0_Proof, Proof__Output as _org_dash_platform_dapi_v0_Proof__Output } from '../../../../../org/dash/platform/dapi/v0/Proof';
import type { ResponseMetadata as _org_dash_platform_dapi_v0_ResponseMetadata, ResponseMetadata__Output as _org_dash_platform_dapi_v0_ResponseMetadata__Output } from '../../../../../org/dash/platform/dapi/v0/ResponseMetadata';

export interface _org_dash_platform_dapi_v0_GetContestedResourceVotersForIdentityResponse_GetContestedResourceVotersForIdentityResponseV0_ContestedResourceVoters {
  'voters'?: (Buffer | Uint8Array | string)[];
  'finishedResults'?: (boolean);
}

export interface _org_dash_platform_dapi_v0_GetContestedResourceVotersForIdentityResponse_GetContestedResourceVotersForIdentityResponseV0_ContestedResourceVoters__Output {
  'voters': (Buffer)[];
  'finishedResults': (boolean);
}

export interface _org_dash_platform_dapi_v0_GetContestedResourceVotersForIdentityResponse_GetContestedResourceVotersForIdentityResponseV0 {
  'contestedResourceVoters'?: (_org_dash_platform_dapi_v0_GetContestedResourceVotersForIdentityResponse_GetContestedResourceVotersForIdentityResponseV0_ContestedResourceVoters | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof | null);
  'metadata'?: (_org_dash_platform_dapi_v0_ResponseMetadata | null);
  'result'?: "contestedResourceVoters"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetContestedResourceVotersForIdentityResponse_GetContestedResourceVotersForIdentityResponseV0__Output {
  'contestedResourceVoters'?: (_org_dash_platform_dapi_v0_GetContestedResourceVotersForIdentityResponse_GetContestedResourceVotersForIdentityResponseV0_ContestedResourceVoters__Output | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof__Output | null);
  'metadata': (_org_dash_platform_dapi_v0_ResponseMetadata__Output | null);
  'result': "contestedResourceVoters"|"proof";
}

export interface GetContestedResourceVotersForIdentityResponse {
  'v0'?: (_org_dash_platform_dapi_v0_GetContestedResourceVotersForIdentityResponse_GetContestedResourceVotersForIdentityResponseV0 | null);
  'version'?: "v0";
}

export interface GetContestedResourceVotersForIdentityResponse__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetContestedResourceVotersForIdentityResponse_GetContestedResourceVotersForIdentityResponseV0__Output | null);
  'version': "v0";
}
