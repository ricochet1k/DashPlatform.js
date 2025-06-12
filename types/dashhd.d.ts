declare module 'dashhd' {
export default DashHd;
const DashHd: DashHD;
export type DashHD = {
    create: HDCreate;
    /**
     * - get the next child xkey (in a path segment)
     */
    deriveChild: HDDeriveChild;
    /**
     * - derive a full hd path from the given key
     */
    derivePath: HDDerivePath;
    _fingerprint: HDFingerprint;
    fromSeed: HDFromSeed;
    fromXKey: HDFromXKey;
    toId: HDToId;
    toIdBytes: HDToIdBytes;
    toAddr: HDToAddr;
    toWif: HDToWif;
    toXPrv: HDToXPrv;
    toXPrvBytes: HDToXKeyBytes;
    toXPub: HDToXPub;
    toXPubBytes: HDToXKeyBytes;
    _utils: HDUtils;
    /**
     * - randomizes private key buffer in-place
     */
    wipePrivateData: HDWipePrivates;
    /**
     * - returns public key
     */
    toPublic: HDToPublic;
    /**
     * - 0x80000000
     */
    HARDENED_OFFSET: number;
    /**
     * - 'xprv' & 'xpub'
     */
    MAINNET: HDVersions;
    /**
     * - 'tprv' & 'tpub'
     */
    TESTNET: HDVersions;
    /**
     * - for hardened derivation
     */
    HARDENED: true;
    /**
     * - for public derivation
     */
    PUBLIC: false;
    /**
     * - use 0 (external)
     */
    RECEIVE: number;
    /**
     * - use 1 (internal)
     */
    CHANGE: number;
    /**
     * - helper
     */
    _createAccount: HDCreateAccountKey;
    /**
     * - helper
     */
    _createXKey: HDCreateXKey;
    /**
     * - helper
     */
    _derive: HDDeriveHelper;
    /**
     * - helper
     */
    _toXBytes: HDToXBytes;
};
export type HDUtils = {
    privateKeyTweakAdd: HDKeyTweak;
    publicKeyTweakAdd: HDKeyTweak;
    publicKeyNormalize: HDKeyToKey;
    ripemd160sum: HDHasher;
    sha256sum: HDHasher;
    sha512hmac: HDHasher;
    bytesToBase64Url: HDBase64Url;
    toPublicKey: HDKeyToKey;
};
export type HDCreate = (opts: HDKeyOptions) => HDKey;
export type HDKey = {
    /**
     * - magic bytes for base58 prefix
     */
    versions: HDVersionsOption;
    /**
     * - of hd path - typically 0 is seed, 1-3 hardened, 4-5 public
     */
    depth: number;
    /**
     * - 32-bit int, slice of id, stored in child xkeys
     */
    parentFingerprint: number;
    /**
     * - the final segment of an HD Path, the index of the wif/addr
     */
    index: number;
    /**
     * - extra 32-bytes of shared entropy for xkeys
     */
    chainCode: Uint8Array;
    privateKey?: Uint8Array | (undefined | null);
    publicKey: Uint8Array;
};
export type HDKeyOptions = {
    versions?: HDVersionsOption | null;
    depth?: number | null;
    parentFingerprint?: number | null;
    index: number;
    chainCode: Uint8Array;
    privateKey?: Uint8Array | null;
    publicKey: Uint8Array;
};
export type HDAccount = HDKey & HDAccountPartial;
export type HDAccountPartial = {
    deriveXKey: HDDeriveXKey;
};
export type HDVersions = {
    /**
     * - 'mainnet', 'testnet', 'xprv' or 'tprv', or 4-byte hex or uint32
     */
    private: Uint32;
    /**
     * - 'mainnet', 'testnet', 'xpub' or 'tpub', or 4-byte hex or uint32
     */
    public: Uint32;
};
export type HDVersionsOption = {
    /**
     * - 'mainnet', 'testnet', 'xprv' or 'tprv', or 4-byte hex or uint32
     */
    private?: Uint32 | string;
    /**
     * - 'mainnet', 'testnet', 'xpub' or 'tpub', or 4-byte hex or uint32
     */
    public?: Uint32 | string;
};
export type HDXKey = HDKey & HDXKeyPartial;
export type HDXKeyPartial = {
    deriveAddress: HDDeriveAddress;
};
export type HDWallet = HDKey & HDWalletPartial;
export type HDWalletPartial = {
    deriveAccount: HDDeriveAccount;
};
export type HDCreateAccountKey = (walletKey: HDKey) => HDAccount;
export type HDCreateXKey = (accountKey: HDKey) => HDXKey;
export type HDDeriveAccount = (account: number) => Promise<HDAccount>;
export type HDDeriveChild = (hdkey: HDKey, index: number, hardened: boolean) => Promise<HDKey>;
export type HDDeriveHelper = (indexedKey: Uint8Array, xParent: HDDeriveHelperOptions) => Promise<HDDeriveHelperOptions>;
export type HDDeriveHelperOptions = {
    chainCode: Uint8Array;
    privateKey?: Uint8Array | (undefined | null);
    publicKey: Uint8Array;
};
export type HDDeriveAddress = (index: number) => Promise<HDKey>;
export type HDDerivePath = (hdkey: HDKey, path: string) => Promise<HDKey>;
export type HDDeriveXKey = (use: number) => Promise<HDXKey>;
export type HDFingerprint = (pubBytes: Uint8Array) => Promise<number>;
export type HDFromXKey = (xkey: string, opts?: HDFromXKeyOptions) => Promise<HDXKey>;
export type HDFromXKeyOptions = {
    versions?: HDVersionsOption;
    /**
     * - allow non-account depths
     */
    bip32?: boolean;
    /**
     * returns {Promise<HDKey>}
     */
    normalizePublicKey?: boolean;
};
export type HDFromSeed = (seedBytes: Uint8Array, opts?: HDFromSeedOptions) => Promise<HDWallet>;
export type HDFromSeedOptions = {
    /**
     * - 44 (BIP-44) by default
     */
    purpose?: number;
    /**
     * - 5 (DASH) by default
     */
    coinType?: number;
    /**
     * - mainnet ('xprv', 'xpub') by default
     */
    versions?: HDVersionsOption;
};
export type HDGetBuffer = () => Uint8Array;
export type HDToAddr = (pubBytes: Uint8Array, opts?: HDToAddressOpts) => Promise<string>;
export type HDToId = (hdkey: HDKey) => Promise<string>;
export type HDToIdBytes = (hdkey: HDKey) => Promise<Uint8Array>;
export type HDToXKeyBytes = (hdkey: HDKey, opts?: HDToXKeyBytesOpts) => Uint8Array;
export type HDToXKeyBytesOpts = {
    version?: number;
};
export type HDToXBytes = (hdkey: HDKey, keyBytes: Uint8Array | null) => Uint8Array;
export type HDToWif = (privBytes: Uint8Array, opts?: HDToAddressOpts) => Promise<string>;
export type HDToAddressOpts = import('dashkeys').EncodeKeyUint8ArrayOpts;
export type HDToXPrv = (hdkey: HDKey, opts?: {
    version?: string | Uint32;
}) => Promise<string>;
export type HDToXPub = (hdkey: HDKey, opts?: {
    version?: string | Uint32;
}) => Promise<string>;
export type HDBase64Url = (bytes: Uint8Array) => string;
export type HDHasher = (bytes: Uint8Array) => Promise<Uint8Array>;
export type HDHmac = (entropy: Uint8Array, data: Uint8Array) => Promise<Uint8Array>;
export type HDKeyToKey = (keyBytes: Uint8Array) => Promise<Uint8Array>;
export type HDKeyTweak = (keyBytes: Uint8Array, tweakBytes: Uint8Array) => Promise<Uint8Array>;
export type HDSecureErase = (buf: Uint8Array) => void;
export type HDToPublic = (hdkey: HDKey) => HDKey;
export type HDWipePrivates = (hdkey: HDKey) => HDKey;
type Uint32 = number;
}