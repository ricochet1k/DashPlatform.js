/**
 * @typedef AssetLockChainProof
 * @prop {Number} core_chain_locked_height
 * @prop {Object} out_point
 * @prop {String} out_point.txid
 * @prop {Number} out_point.vout
 */
/**
 * @param {import('dashhd').HDWallet} assetKey
 * @param {import('dashhd').HDWallet} masterKey
 * @param {import('dashhd').HDWallet} otherKey
 * @param {String} identityIdHex
 * @param {String} txidHex
 * @param {DashBincode.AssetLockProof} [assetProof]
 */
export function createIdentityFromAssetLock(assetKey: any, masterKey: any, otherKey: any, identityIdHex: string, txidHex: string, assetLockProof: any): Promise<void>;
export type AssetLockChainProof = {
    core_chain_locked_height: number;
    out_point: {
        txid: string;
        vout: number;
    };
};
export type EvoKey = {
    id: Uint8;
    /**
     * - TODO constrain to members of KEY_TYPES
     */
    type: DashBincode.KeyType;
    /**
     * - TODO constrain to members of KEY_PURPOSES
     */
    purpose: DashBincode.Purpose;
    /**
     * - TODO constrain to members of KEY_LEVELS
     */
    securityLevel: DashBincode.SecurityLevel;
    readOnly: boolean;
    publicKey: Uint8Array;
    privateKey: Uint8Array;
};
export type STKey = {
    id: Uint8;
    /**
     * - TODO constrain to members of KEY_TYPES
     */
    type: DashBincode.KeyType;
    /**
     * - TODO constrain to members of KEY_PURPOSES
     */
    purpose: DashBincode.Purpose;
    /**
     * - base64-encoded publicKey (compact)
     */
    data: Base64;
    /**
     * - TODO constrain to members of KEY_LEVELS
     */
    securityLevel: DashBincode.SecurityLevel;
    readOnly: boolean;
};
export type Base58 = string;
export type Base64 = string;
export type HexString = string;
export type Uint53 = number;
export type Uint32 = number;
export type Uint8 = number;
import * as DashBincode from "./1.8.1/generated_bincode.js";
