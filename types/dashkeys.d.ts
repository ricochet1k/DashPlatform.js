declare module 'dashkeys' {
export default DashKeys;
const DashKeys: DashKeys;
export type BaseX = import("./base-x.types.js").BaseX;
export type BaseXCreate = import("./base-x.types.js").Create;
export type BaseXDecode = import("./base-x.types.js").Decode;
export type BaseXDecodeUnsafe = import("./base-x.types.js").DecodeUnsafe;
export type BaseXEncode = import("./base-x.types.js").Encode;
export type Base58Check = import("./base58check.types.js").Base58Check;
export type Base58CheckInstance = import("./base58check.types.js").base58Check;
export type Base58CheckChecksum = import("./base58check.types.js").Checksum;
export type Base58CheckCreate = import("./base58check.types.js").Create;
export type Base58CheckDecode = import("./base58check.types.js").Decode;
export type Base58CheckDecodeHex = import("./base58check.types.js").DecodeHex;
export type Base58CheckEncode = import("./base58check.types.js").Encode;
export type Base58CheckEncodeHex = import("./base58check.types.js").EncodeHex;
export type Base58CheckEncodeParts = import("./base58check.types.js").EncodeParts;
export type Base58CheckParts = import("./base58check.types.js").Parts;
export type Base58CheckPrivateParts = import("./base58check.types.js").PrivateParts;
export type Base58CheckPubKeyHashParts = import("./base58check.types.js").PubKeyHashParts;
export type Base58CheckXPrvParts = import("./base58check.types.js").XPrvParts;
export type Base58CheckXPubParts = import("./base58check.types.js").XPubParts;
export type Base58CheckVerify = import("./base58check.types.js").Verify;
export type Base58CheckVerifyHex = import("./base58check.types.js").VerifyHex;
export type RIPEMD160 = import("./ripemd160.types.js").RIPEMD160;
export type RIPEMD160Create = import("./ripemd160.types.js").Create;
export type RIPEMD160Digest = import("./ripemd160.types.js").Digest;
export type RIPEMD160Hash = import("./ripemd160.types.js").Hash;
export type RIPEMD160Update = import("./ripemd160.types.js").Update;
export type DashKeys = {
    decode: DecodeBase58Check;
    encodeKey: EncodeKeyUint8Array;
    addrToPkh: AddressToPubKeyHash;
    pkhToAddr: PubKeyHashToAddress;
    privKeyToWif: PrivateKeyToWif;
    pubkeyToAddr: PublicKeyToAddress;
    pubkeyToPkh: PublicKeyToPubKeyHash;
    wifToAddr: WifToAddress;
    wifToPrivKey: WifToPrivateKey;
    utils: DashKeysUtils;
    _encodeXKey: EncodeKeyUint8Array;
    _dash58check: Base58CheckInstance;
};
export type DashKeysUtils = {
    bytesToHex: Uint8ArrayToHex;
    generateWifNonHd: GenerateWif;
    hexToBytes: HexToUint8Array;
    ripemd160sum: Hasher;
    sha256sum: Hasher;
    toPublicKey: ToPublicKey;
};
export type DASH_PKH = "4c";
export type DASH_PKH_TESTNET = "8c";
export type DASH_PRIV_KEY = "cc";
export type DASH_PRIV_KEY_TESTNET = "ef";
export type XPRV = "0488ade4";
export type XPUB = "0488b21e";
export type TPRV = "04358394";
export type TPUB = "043587cf";
export type VERSION = "mainnet" | "testnet" | DASH_PKH | DASH_PRIV_KEY | DASH_PKH_TESTNET | DASH_PRIV_KEY_TESTNET | "xprv" | "tprv" | "xpub" | "tpub" | XPRV | XPUB | TPRV | TPUB;
export type VERSION_PRIVATE = "mainnet" | "cc" | "testnet" | "ef";
export type HexString = string;
export type AddressToPubKeyHash = (addr: string, opts?: DecodeOpts) => Promise<Uint8Array>;
export type DecodeBase58Check = (keyB58c: string, opts?: DecodeOpts) => Promise<Base58CheckParts>;
export type DecodeOpts = {
    /**
     * - throw if check fails, true by default
     */
    validate?: boolean;
    versions?: Array<VERSION | number>;
    version?: VERSION | number;
};
export type EncodeKeyUint8Array = (keyBytes: Uint8Array, opts?: EncodeKeyUint8ArrayOpts) => Promise<string>;
export type EncodeKeyUint8ArrayOpts = {
    /**
     * - needed for xprv and xpub, or testnet
     */
    version?: VERSION;
};
/**
 * Developer Convenience function for Generating Non-HD (NON-RECOVERABLE) WIFs
 */
export type GenerateWif = (opts?: PrivateKeyToWifOpts) => Promise<string>;
export type Hasher = (bytes: Uint8Array | Buffer) => Promise<Uint8Array>;
/**
 * Hex to JS Bytes Buffer (Uint8Array)
 */
export type HexToUint8Array = (hex: string) => Uint8Array;
export type PrivateKeyToWif = (privBytes: Uint8Array, opts?: PrivateKeyToWifOpts) => Promise<string>;
export type PrivateKeyToWifOpts = {
    /**
     * - "mainnet" ("cc") by default
     */
    version: VERSION_PRIVATE;
};
export type PubKeyHashToAddress = (shaRipeBytes: Uint8Array, opts: EncodeKeyUint8ArrayOpts) => Promise<string>;
export type PublicKeyToAddress = (pubBytes: Uint8Array, opts?: EncodeKeyUint8ArrayOpts) => Promise<string>;
export type PublicKeyToPubKeyHash = (pubBytes: Uint8Array | Buffer) => Promise<Uint8Array>;
export type ToPublicKey = (privBytes: Uint8Array) => Promise<Uint8Array>;
/**
 * JS Bytes Buffer (Uint8Array) to Hex
 */
export type Uint8ArrayToHex = (bytes: Uint8Array) => string;
/**
 * Converts a WIF-encoded PrivateKey to a PubKey Hash
 * (of the same coin type, of course)
 */
export type WifToAddress = (wif: string, opts?: EncodeKeyUint8ArrayOpts) => Promise<string>;
/**
 * Decodes a WIF-encoded PrivateKey to Bytes
 */
export type WifToPrivateKey = (wif: string, opts?: PrivateKeyToWifOpts) => Promise<Uint8Array>;
}