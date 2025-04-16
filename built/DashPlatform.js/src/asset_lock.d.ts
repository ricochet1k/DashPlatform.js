/**
 * @param {{version: string}} hdOpts
 * @param {import("dashhd").HDWallet} walletKey
 * @param {number} identityIndex
 */
export function deriveAllCreateIdentityKeys(hdOpts: {
    version: string;
}, walletKey: any, identityIndex: number): Promise<{
    regFundKey: any;
    topupKey: any;
    assetWif: any;
    assetInfo: {
        wif: string;
        privateKey: any;
        privateKeyHex: any;
        publicKey: any;
        publicKeyHex: any;
        pubKeyHash: any;
        pubKeyHashHex: any;
        address: any;
    };
    assetKey: any;
    masterKey: any;
    otherKey: any;
}>;
/**
 * @param {import('dashhd').HDToAddressOpts} hdOpts
 * @param {import('dashhd').HDKey} regFundKey
 * @param {import('dashhd').HDKey} changeKey
 * @param {{publicKey: Uint8Array}} assetInfo
 */
export function createPlatformAssetLock(hdOpts: any, regFundKey: any, changeKey: any, assetInfo: {
    publicKey: Uint8Array;
}): Promise<{
    txidHex: any;
    identityIdHex: string;
    assetProof: DashBincode.AssetLockProof;
}>;
export function TODOgetUtxos(addresses: Array<string>): Promise<any>;
export type TransactionJson = {
    /**
     * - Whether specified block is in the active chain or not (only present with explicit "blockhash" argument)
     */
    in_active_chain: boolean | null;
    /**
     * - The serialized, hex-encoded data for 'txid'
     */
    hex: string;
    /**
     * - The transaction id (same as provided)
     */
    txid: string;
    /**
     * - The transaction hash (differs from txid for witness transactions)
     */
    hash: string;
    /**
     * - The serialized transaction size
     */
    size: number;
    /**
     * - The virtual transaction size (differs from size for witness transactions)
     */
    vsize: number;
    /**
     * - The transaction's weight (between vsize*4-3 and vsize*4)
     */
    weight: number;
    /**
     * - The version
     */
    version: number;
    /**
     * - The lock time
     */
    locktime: number;
    /**
     * - The transaction inputs
     */
    vin: Array<{
        txid?: string;
        vout?: number;
        scriptSig?: {
            asm: string;
            hex: string;
        };
        sequence: number;
        txinwitness?: Array<string>;
    }>;
    /**
     * - The transaction outputs
     */
    vout: Array<{
        value: number;
        n: number;
        scriptPubKey: {
            asm: string;
            hex: string;
            reqSigs?: number;
            type: string;
            addresses?: Array<string>;
        };
    }>;
    /**
     * - If the transaction has been included in a block on the local best block chain, this is the block height where the transaction was mined. Otherwise, this is -1. Not shown for mempool transactions.
     */
    height: number | null;
    /**
     * - The block hash
     */
    blockhash: string | null;
    /**
     * - The confirmations
     */
    confirmations: number | null;
    /**
     * - The block time expressed in UNIX epoch time
     */
    blocktime: number | null;
    /**
     * - Same as "blocktime"
     */
    time: number | null;
};
export type TransactionMetadata = {
    /**
     * - The block height or index
     */
    height: number;
};
export type TransactionJsonMetadata = TransactionJson & TransactionMetadata;
export type CheckData<T> = (message: unknown) => message is T;
export type Delta = {
    txid: string;
    index: Uint32;
    pubKeyHash: string;
    address: string;
    satoshis: Uint32;
};
export type Base58 = string;
export type Base64 = string;
export type HexString = string;
export type Uint53 = number;
export type Uint32 = number;
export type Uint8 = number;
import * as DashBincode from "../1.8.1/generated_bincode.js";
