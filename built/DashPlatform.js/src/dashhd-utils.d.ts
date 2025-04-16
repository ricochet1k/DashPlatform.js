/**
 * Returns the Identity Auth Wallet, which can be used to derive Identity Auth Keys
 * @param {import('dashhd').HDWallet} walletKey
 * @param {String} path
 */
export function deriveIdentAuthWalletPath(walletKey: any, path: string): Promise<any>;
/**
 * Returns a fully-derived Identity Auth Key
 * @param {import('dashhd').HDWallet} walletKey
 * @param {String} path
 */
export function deriveIdentAuthKeyPath(walletKey: any, path: string): Promise<any>;
/**
 * Returns a fully-derived Identity Registration Funding Key
 * @param {import('dashhd').HDWallet} walletKey
 * @param {String} path
 */
export function deriveIdentRegFundKeyPath(walletKey: any, path: string): Promise<any>;
/**
 * Returns a fully-derived Topup Funding Key
 * @param {import('dashhd').HDWallet} walletKey
 * @param {String} path
 */
export function deriveIdentTopupKeyPath(walletKey: any, path: string): Promise<any>;
export type HDPathPlatform = {
    path: string;
    paths: Array<string>;
    m: "m" | "m'";
    purpose: "9'";
    coinType: "5'" | "1'";
    feature: "5'";
    subFeature: "0'" | "1'" | "2'";
    keyType?: "1'" | "0'" | undefined;
    identityIndex?: string | undefined;
    keyIndex?: string | undefined;
    topupIndex?: string | undefined;
    fundRegIndex?: string | undefined;
};
export type Uint32 = number;
