// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

import type { AllKeys as _org_dash_platform_dapi_v0_AllKeys, AllKeys__Output as _org_dash_platform_dapi_v0_AllKeys__Output } from '../../../../../org/dash/platform/dapi/v0/AllKeys';
import type { SpecificKeys as _org_dash_platform_dapi_v0_SpecificKeys, SpecificKeys__Output as _org_dash_platform_dapi_v0_SpecificKeys__Output } from '../../../../../org/dash/platform/dapi/v0/SpecificKeys';
import type { SearchKey as _org_dash_platform_dapi_v0_SearchKey, SearchKey__Output as _org_dash_platform_dapi_v0_SearchKey__Output } from '../../../../../org/dash/platform/dapi/v0/SearchKey';

export interface KeyRequestType {
  'allKeys'?: (_org_dash_platform_dapi_v0_AllKeys | null);
  'specificKeys'?: (_org_dash_platform_dapi_v0_SpecificKeys | null);
  'searchKey'?: (_org_dash_platform_dapi_v0_SearchKey | null);
  'request'?: "allKeys"|"specificKeys"|"searchKey";
}

export interface KeyRequestType__Output {
  'allKeys'?: (_org_dash_platform_dapi_v0_AllKeys__Output | null);
  'specificKeys'?: (_org_dash_platform_dapi_v0_SpecificKeys__Output | null);
  'searchKey'?: (_org_dash_platform_dapi_v0_SearchKey__Output | null);
  'request': "allKeys"|"specificKeys"|"searchKey";
}
