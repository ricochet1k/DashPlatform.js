export type EvoKey = {
    id: Uint8;
    /**
     * - TODO constrain to members of KEY_TYPES
     */
    type: Uint8;
    /**
     * - TODO constrain to members of KEY_PURPOSES
     */
    purpose: Uint8;
    /**
     * - TODO constrain to members of KEY_LEVELS
     */
    securityLevel: Uint8;
    readOnly: boolean;
    publicKey: Uint8Array;
    privateKey: Uint8Array;
};
export type STKey = {
    id: Uint8;
    /**
     * - TODO constrain to members of KEY_TYPES
     */
    type: Uint8;
    /**
     * - TODO constrain to members of KEY_PURPOSES
     */
    purpose: Uint8;
    /**
     * - base64-encoded publicKey (compact)
     */
    data: Base64;
    /**
     * - TODO constrain to members of KEY_LEVELS
     */
    securityLevel: Uint8;
    readOnly: boolean;
};
export type Base58 = string;
export type Base64 = string;
export type Hex = string;
export type Uint53 = number;
export type Uint32 = number;
export type Uint8 = number;
