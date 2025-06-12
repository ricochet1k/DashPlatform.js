export const _types: true;
export type Base58Check = {
    create: Create;
};
export type Create = (opts?: Base58CheckOpts) => any;
export type base58Check = {
    checksum: Checksum;
    decode: Decode;
    decodeHex: DecodeHex;
    encode: Encode;
    encodeHex: EncodeHex;
    verify: Verify;
    verifyHex: VerifyHex;
    _checksumHexRaw: Function;
    _encodeXKey: Function;
    _encodePrivateKeyHex: Function;
    _encodePubKeyHashHex: Function;
    _setVersion: Function;
};
/**
 * Base58Check Options, see https://github.com/dashhive/dashkeys.js/blob/1f0f4e0d0aabf9e68d94925d660f00666f502391/dashkeys.js#L38 and see https://bitcoin.stackexchange.com/questions/38878/how-does-the-bip32-version-bytes-convert-to-base58
 */
export type Base58CheckOpts = {
    /**
     * - "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz" for Dash / Bitcoin Base58
     */
    dictionary?: string;
    /**
     * - "cc" for mainnet (default), "ef" for testnet, '80' for bitcoin
     */
    privateKeyVersion?: string;
    /**
     * - "4c" for mainnet (default), "8c" for testnet, "00" for bitcoin
     */
    pubKeyHashVersion?: string;
    /**
     * - "4c" for mainnet (default), "8c" for testnet, "00" for bitcoin
     */
    xprvVersion?: string;
    /**
     * - "0488b21e" for "xpub" on mainnet (default), "043587cf" for "tpub" on testnet
     */
    xpubVersion?: string;
};
export type Parts = PrivateParts | PubKeyHashParts | XPrvParts | XPubParts;
export type PrivatePartial = {
    privateKey: string;
};
export type PubKeyHashPartial = {
    pubKeyHash: string;
};
export type XPrvPartial = {
    xprv: string;
};
export type XPubPartial = {
    xpub: string;
};
export type PartsPartial = PrivatePartial | PubKeyHashPartial | XPrvPartial | XPubPartial;
export type PartsOptionalPartial = {
    check?: string;
    compressed?: true;
    version?: string;
};
export type EncodeParts = PartsPartial & PartsOptionalPartial;
export type KeyType = "private" | "pkh" | "xprv" | "xpub" | "";
export type PrivateParts = {
    /**
     * - the 4 checksum bytes
     */
    check: string;
    /**
     * - expect (public key) hash to be of the X value only
     */
    compressed: true;
    /**
     * - hex private key
     */
    privateKey: string;
    /**
     * - hex (public key) hash
     */
    pubKeyHash?: string;
    /**
     * - "private"
     */
    type?: KeyType;
    /**
     * - checksum passed
     */
    valid?: boolean;
    /**
     * - 1 magic bytes
     */
    version: string;
};
export type PubKeyHashParts = {
    /**
     * - the 4 checksum bytes
     */
    check: string;
    /**
     * - hex sha256-ripemd160 hash of public key
     */
    pubKeyHash: string;
    /**
     * - "pkh"
     */
    type?: KeyType;
    /**
     * - checksum passed
     */
    valid?: boolean;
    /**
     * - 1 magic bytes
     */
    version: string;
};
export type XPrvParts = {
    /**
     * - the 4 checksum bytes
     */
    check: string;
    /**
     * - hex extended private key
     */
    xprv: string;
    /**
     * - "xprv"
     */
    type?: KeyType;
    /**
     * - checksum passed
     */
    valid?: boolean;
    /**
     * - 4 magic bytes
     */
    version: string;
    /**
     * - hex extended public key
     */
    xpub?: string;
};
export type XPubParts = {
    /**
     * - the 4 checksum bytes
     */
    check: string;
    /**
     * - "xpub"
     */
    type?: KeyType;
    /**
     * - checksum passed
     */
    valid?: boolean;
    /**
     * - 4 magic bytes
     */
    version: string;
    /**
     * - hex extended public key
     */
    xpub: string;
};
export type Checksum = (parts: Parts | EncodeParts) => Promise<string>;
export type Decode = (base58check: string, opts: DecodeOpts) => Parts;
export type DecodeHex = (hex: string, opts?: DecodeOpts) => Parts;
export type DecodeOpts = {
    versions?: readonly [string, string];
    xversions?: readonly [string, string];
};
export type Verify = (base58check: string, opts?: VerifyOpts) => Promise<Parts>;
export type VerifyHex = (hex: string, opts?: VerifyOpts) => Promise<Parts>;
export type VerifyOpts = DecodeOpts & VerifyOptsPartial;
export type VerifyOptsPartial = {
    /**
     * - set 'false' to set 'valid' false rather than throw
     */
    verify?: boolean;
};
export type Encode = (parts: EncodeParts) => Promise<string>;
export type EncodeHex = (parts: EncodeParts) => Promise<string>;
