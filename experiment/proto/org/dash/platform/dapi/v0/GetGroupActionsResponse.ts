// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

import type { Proof as _org_dash_platform_dapi_v0_Proof, Proof__Output as _org_dash_platform_dapi_v0_Proof__Output } from '../../../../../org/dash/platform/dapi/v0/Proof';
import type { ResponseMetadata as _org_dash_platform_dapi_v0_ResponseMetadata, ResponseMetadata__Output as _org_dash_platform_dapi_v0_ResponseMetadata__Output } from '../../../../../org/dash/platform/dapi/v0/ResponseMetadata';
import type { Long } from '@grpc/proto-loader';

// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

export const _org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_EmergencyActionEvent_ActionType = {
  PAUSE: 'PAUSE',
  RESUME: 'RESUME',
} as const;

export type _org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_EmergencyActionEvent_ActionType =
  | 'PAUSE'
  | 0
  | 'RESUME'
  | 1

export type _org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_EmergencyActionEvent_ActionType__Output = typeof _org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_EmergencyActionEvent_ActionType[keyof typeof _org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_EmergencyActionEvent_ActionType]

export interface _org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_BurnEvent {
  'amount'?: (number | string | Long);
  'publicNote'?: (string);
  '_publicNote'?: "publicNote";
}

export interface _org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_BurnEvent__Output {
  'amount': (string);
  'publicNote'?: (string);
  '_publicNote': "publicNote";
}

export interface _org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_ContractEvent {
  'update'?: (_org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_ContractUpdateEvent | null);
  'type'?: "update";
}

export interface _org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_ContractEvent__Output {
  'update'?: (_org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_ContractUpdateEvent__Output | null);
  'type': "update";
}

export interface _org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_ContractUpdateEvent {
  'updatedContract'?: (Buffer | Uint8Array | string);
}

export interface _org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_ContractUpdateEvent__Output {
  'updatedContract': (Buffer);
}

export interface _org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_DestroyFrozenFundsEvent {
  'frozenId'?: (Buffer | Uint8Array | string);
  'amount'?: (number | string | Long);
  'publicNote'?: (string);
  '_publicNote'?: "publicNote";
}

export interface _org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_DestroyFrozenFundsEvent__Output {
  'frozenId': (Buffer);
  'amount': (string);
  'publicNote'?: (string);
  '_publicNote': "publicNote";
}

export interface _org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_DocumentCreateEvent {
  'createdDocument'?: (Buffer | Uint8Array | string);
}

export interface _org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_DocumentCreateEvent__Output {
  'createdDocument': (Buffer);
}

export interface _org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_DocumentEvent {
  'create'?: (_org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_DocumentCreateEvent | null);
  'type'?: "create";
}

export interface _org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_DocumentEvent__Output {
  'create'?: (_org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_DocumentCreateEvent__Output | null);
  'type': "create";
}

export interface _org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_EmergencyActionEvent {
  'actionType'?: (_org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_EmergencyActionEvent_ActionType);
  'publicNote'?: (string);
  '_publicNote'?: "publicNote";
}

export interface _org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_EmergencyActionEvent__Output {
  'actionType': (_org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_EmergencyActionEvent_ActionType__Output);
  'publicNote'?: (string);
  '_publicNote': "publicNote";
}

export interface _org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_FreezeEvent {
  'frozenId'?: (Buffer | Uint8Array | string);
  'publicNote'?: (string);
  '_publicNote'?: "publicNote";
}

export interface _org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_FreezeEvent__Output {
  'frozenId': (Buffer);
  'publicNote'?: (string);
  '_publicNote': "publicNote";
}

export interface _org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0 {
  'groupActions'?: (_org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_GroupActions | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof | null);
  'metadata'?: (_org_dash_platform_dapi_v0_ResponseMetadata | null);
  'result'?: "groupActions"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0__Output {
  'groupActions'?: (_org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_GroupActions__Output | null);
  'proof'?: (_org_dash_platform_dapi_v0_Proof__Output | null);
  'metadata': (_org_dash_platform_dapi_v0_ResponseMetadata__Output | null);
  'result': "groupActions"|"proof";
}

export interface _org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_GroupActionEntry {
  'actionId'?: (Buffer | Uint8Array | string);
  'event'?: (_org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_GroupActionEvent | null);
}

export interface _org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_GroupActionEntry__Output {
  'actionId': (Buffer);
  'event': (_org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_GroupActionEvent__Output | null);
}

export interface _org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_GroupActionEvent {
  'tokenEvent'?: (_org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_TokenEvent | null);
  'documentEvent'?: (_org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_DocumentEvent | null);
  'contractEvent'?: (_org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_ContractEvent | null);
  'eventType'?: "tokenEvent"|"documentEvent"|"contractEvent";
}

export interface _org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_GroupActionEvent__Output {
  'tokenEvent'?: (_org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_TokenEvent__Output | null);
  'documentEvent'?: (_org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_DocumentEvent__Output | null);
  'contractEvent'?: (_org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_ContractEvent__Output | null);
  'eventType': "tokenEvent"|"documentEvent"|"contractEvent";
}

export interface _org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_GroupActions {
  'groupActions'?: (_org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_GroupActionEntry)[];
}

export interface _org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_GroupActions__Output {
  'groupActions': (_org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_GroupActionEntry__Output)[];
}

export interface _org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_MintEvent {
  'amount'?: (number | string | Long);
  'recipientId'?: (Buffer | Uint8Array | string);
  'publicNote'?: (string);
  '_publicNote'?: "publicNote";
}

export interface _org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_MintEvent__Output {
  'amount': (string);
  'recipientId': (Buffer);
  'publicNote'?: (string);
  '_publicNote': "publicNote";
}

export interface _org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_PersonalEncryptedNote {
  'rootEncryptionKeyIndex'?: (number);
  'derivationEncryptionKeyIndex'?: (number);
  'encryptedData'?: (Buffer | Uint8Array | string);
}

export interface _org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_PersonalEncryptedNote__Output {
  'rootEncryptionKeyIndex': (number);
  'derivationEncryptionKeyIndex': (number);
  'encryptedData': (Buffer);
}

export interface _org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_SharedEncryptedNote {
  'senderKeyIndex'?: (number);
  'recipientKeyIndex'?: (number);
  'encryptedData'?: (Buffer | Uint8Array | string);
}

export interface _org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_SharedEncryptedNote__Output {
  'senderKeyIndex': (number);
  'recipientKeyIndex': (number);
  'encryptedData': (Buffer);
}

export interface _org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_TokenConfigUpdateEvent {
  'tokenConfigUpdateItem'?: (Buffer | Uint8Array | string);
  'publicNote'?: (string);
  '_publicNote'?: "publicNote";
}

export interface _org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_TokenConfigUpdateEvent__Output {
  'tokenConfigUpdateItem': (Buffer);
  'publicNote'?: (string);
  '_publicNote': "publicNote";
}

export interface _org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_TokenEvent {
  'mint'?: (_org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_MintEvent | null);
  'burn'?: (_org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_BurnEvent | null);
  'freeze'?: (_org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_FreezeEvent | null);
  'unfreeze'?: (_org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_UnfreezeEvent | null);
  'destroyFrozenFunds'?: (_org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_DestroyFrozenFundsEvent | null);
  'transfer'?: (_org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_TransferEvent | null);
  'emergencyAction'?: (_org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_EmergencyActionEvent | null);
  'tokenConfigUpdate'?: (_org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_TokenConfigUpdateEvent | null);
  'type'?: "mint"|"burn"|"freeze"|"unfreeze"|"destroyFrozenFunds"|"transfer"|"emergencyAction"|"tokenConfigUpdate";
}

export interface _org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_TokenEvent__Output {
  'mint'?: (_org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_MintEvent__Output | null);
  'burn'?: (_org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_BurnEvent__Output | null);
  'freeze'?: (_org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_FreezeEvent__Output | null);
  'unfreeze'?: (_org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_UnfreezeEvent__Output | null);
  'destroyFrozenFunds'?: (_org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_DestroyFrozenFundsEvent__Output | null);
  'transfer'?: (_org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_TransferEvent__Output | null);
  'emergencyAction'?: (_org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_EmergencyActionEvent__Output | null);
  'tokenConfigUpdate'?: (_org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_TokenConfigUpdateEvent__Output | null);
  'type': "mint"|"burn"|"freeze"|"unfreeze"|"destroyFrozenFunds"|"transfer"|"emergencyAction"|"tokenConfigUpdate";
}

export interface _org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_TransferEvent {
  'recipientId'?: (Buffer | Uint8Array | string);
  'publicNote'?: (string);
  'sharedEncryptedNote'?: (_org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_SharedEncryptedNote | null);
  'personalEncryptedNote'?: (_org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_PersonalEncryptedNote | null);
  'amount'?: (number | string | Long);
  '_publicNote'?: "publicNote";
  '_sharedEncryptedNote'?: "sharedEncryptedNote";
  '_personalEncryptedNote'?: "personalEncryptedNote";
}

export interface _org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_TransferEvent__Output {
  'recipientId': (Buffer);
  'publicNote'?: (string);
  'sharedEncryptedNote'?: (_org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_SharedEncryptedNote__Output | null);
  'personalEncryptedNote'?: (_org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_PersonalEncryptedNote__Output | null);
  'amount': (string);
  '_publicNote': "publicNote";
  '_sharedEncryptedNote': "sharedEncryptedNote";
  '_personalEncryptedNote': "personalEncryptedNote";
}

export interface _org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_UnfreezeEvent {
  'frozenId'?: (Buffer | Uint8Array | string);
  'publicNote'?: (string);
  '_publicNote'?: "publicNote";
}

export interface _org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0_UnfreezeEvent__Output {
  'frozenId': (Buffer);
  'publicNote'?: (string);
  '_publicNote': "publicNote";
}

export interface GetGroupActionsResponse {
  'v0'?: (_org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0 | null);
  'version'?: "v0";
}

export interface GetGroupActionsResponse__Output {
  'v0'?: (_org_dash_platform_dapi_v0_GetGroupActionsResponse_GetGroupActionsResponseV0__Output | null);
  'version': "v0";
}
