// Original file: ../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto

export const KeyPurpose = {
  AUTHENTICATION: 'AUTHENTICATION',
  ENCRYPTION: 'ENCRYPTION',
  DECRYPTION: 'DECRYPTION',
  TRANSFER: 'TRANSFER',
  VOTING: 'VOTING',
} as const;

export type KeyPurpose =
  | 'AUTHENTICATION'
  | 0
  | 'ENCRYPTION'
  | 1
  | 'DECRYPTION'
  | 2
  | 'TRANSFER'
  | 3
  | 'VOTING'
  | 5

export type KeyPurpose__Output = typeof KeyPurpose[keyof typeof KeyPurpose]
