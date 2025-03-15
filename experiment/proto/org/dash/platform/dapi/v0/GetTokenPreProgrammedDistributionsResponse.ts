// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

import type { Proof as _org_dash_platform_dapi_v0_Proof, Proof__Output as _org_dash_platform_dapi_v0_Proof__Output } from '../../../../../org/dash/platform/dapi/v0/Proof';
import type { ResponseMetadata as _org_dash_platform_dapi_v0_ResponseMetadata, ResponseMetadata__Output as _org_dash_platform_dapi_v0_ResponseMetadata__Output } from '../../../../../org/dash/platform/dapi/v0/ResponseMetadata';
import type { Long } from '@grpc/proto-loader';

export interface _org_dash_platform_dapi_v0_GetTokenPreProgrammedDistributionsResponse_GetTokenPreProgrammedDistributionsResponseV0 {
  'tokenDistributions'?: (_org_dash_platform_dapi_v0_GetTokenPreProgrammedDistributionsResponse_GetTokenPreProgrammedDistributionsResponseV0_TokenDistributions | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof | null);
  'metadata'?: (_org_dash_platform_dapi_v0_ResponseMetadata | null);
  'result'?: "tokenDistributions"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetTokenPreProgrammedDistributionsResponse_GetTokenPreProgrammedDistributionsResponseV0__Output {
  'tokenDistributions'?: (_org_dash_platform_dapi_v0_GetTokenPreProgrammedDistributionsResponse_GetTokenPreProgrammedDistributionsResponseV0_TokenDistributions__Output | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof__Output | null);
  'metadata': (_org_dash_platform_dapi_v0_ResponseMetadata__Output | null);
  'result': "tokenDistributions"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetTokenPreProgrammedDistributionsResponse_GetTokenPreProgrammedDistributionsResponseV0_TokenDistributionEntry {
  'recipientId'?: (Buffer | Uint8Array | string);
  'amount'?: (number | string | Long);
}

export interface _org_dash_platform_dapi_v0_GetTokenPreProgrammedDistributionsResponse_GetTokenPreProgrammedDistributionsResponseV0_TokenDistributionEntry__Output {
  'recipientId': (Buffer);
  'amount': (string);
}

export interface _org_dash_platform_dapi_v0_GetTokenPreProgrammedDistributionsResponse_GetTokenPreProgrammedDistributionsResponseV0_TokenDistributions {
  'tokenDistributions'?: (_org_dash_platform_dapi_v0_GetTokenPreProgrammedDistributionsResponse_GetTokenPreProgrammedDistributionsResponseV0_TokenTimedDistributionEntry)[];
}

export interface _org_dash_platform_dapi_v0_GetTokenPreProgrammedDistributionsResponse_GetTokenPreProgrammedDistributionsResponseV0_TokenDistributions__Output {
  'tokenDistributions': (_org_dash_platform_dapi_v0_GetTokenPreProgrammedDistributionsResponse_GetTokenPreProgrammedDistributionsResponseV0_TokenTimedDistributionEntry__Output)[];
}

export interface _org_dash_platform_dapi_v0_GetTokenPreProgrammedDistributionsResponse_GetTokenPreProgrammedDistributionsResponseV0_TokenTimedDistributionEntry {
  'timestamp'?: (number | string | Long);
  'distributions'?: (_org_dash_platform_dapi_v0_GetTokenPreProgrammedDistributionsResponse_GetTokenPreProgrammedDistributionsResponseV0_TokenDistributionEntry)[];
}

export interface _org_dash_platform_dapi_v0_GetTokenPreProgrammedDistributionsResponse_GetTokenPreProgrammedDistributionsResponseV0_TokenTimedDistributionEntry__Output {
  'timestamp': (string);
  'distributions': (_org_dash_platform_dapi_v0_GetTokenPreProgrammedDistributionsResponse_GetTokenPreProgrammedDistributionsResponseV0_TokenDistributionEntry__Output)[];
}

export interface GetTokenPreProgrammedDistributionsResponse {
  'v0'?: (_org_dash_platform_dapi_v0_GetTokenPreProgrammedDistributionsResponse_GetTokenPreProgrammedDistributionsResponseV0 | null);
  'version'?: "v0";
}

export interface GetTokenPreProgrammedDistributionsResponse__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetTokenPreProgrammedDistributionsResponse_GetTokenPreProgrammedDistributionsResponseV0__Output | null);
  'version': "v0";
}
