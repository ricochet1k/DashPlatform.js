export function appraise(txInfo: TxInfo): TxFees;
export function toDash(satoshis: Uint53): Float64;
export function toSats(dash: Float64): Uint53;
/** @param {TxKeyUtils} keyUtils */
export function create(keyUtils: TxKeyUtils): {
    hashAndSignAll(txInfo: TxInfo, sigHashType?: Uint32): Promise<TxInfoSigned>;
    hashAndSignInput(privBytes: Uint8Array, txInfo: TxInfo, i: Uint32, sigHashType?: Uint32): Promise<TxInputSigned>;
    legacy: {
        draftSingleOutput({ utxos, inputs, output }: {
            inputs?: CoreUtxo[] | null | undefined;
            utxos?: CoreUtxo[] | null | undefined;
            output: TxOutput;
        }): TxDraft;
        finalizePresorted(txDraft: TxDraft): Promise<TxSummary>;
        _signToTarget(txDraft: TxDraft): Promise<TxInfoSigned>;
        _signFeeWalk(txDraft: TxDraft): Promise<TxInfoSigned>;
        _summarizeTx(txInfo: TxInfoSigned): TxSummary;
    };
};
/**
 * @param {TxInfo} txInfo
 * @param {Uint32} i - index of input to be signed
 * @param {Uint8} sigHashType
 */
export function selectSigHashInputs(txInfo: TxInfo, i: Uint32, sigHashType?: Uint8): TxInputForSig[];
/**
 * @param {TxInfo} txInfo
 * @param {Uint32} i - index of input to be signed
 * @param {Uint8} sigHashType
 */
export function selectSigHashOutputs(txInfo: TxInfo, i: Uint32, sigHashType?: Uint8): TxOutput[];
/**
 * Creates a transaction that is guaranteed to be signable.  Selects
 * the smallest coin that is bigger or equal to the amount sent + fees,
 * or the largest available coins until that total is met.
 */
export function createLegacyTx(coins: any, outputs: any, changeOutput: any, extraPayload: any): {
    version: number;
    type: number;
    inputs: TxInputUnspent[];
    outputs: any;
    changeIndex: any;
    locktime: number;
    extraPayload: any;
};
export function sortBySatsAsc(a: TxHasSats, b: TxHasSats): Uint8;
export function sortBySatsDsc(a: TxHasSats, b: TxHasSats): Uint8;
export function sortInputs(a: TxInputSortable, b: TxInputSortable): Uint8;
/**
 * Lexicographical Indexing of Transaction Inputs and Outputs
 * See <https://github.com/bitcoin/bips/blob/master/bip-0069.mediawiki>
 *
 * Note: this must be updated to support new types of script comparison.
 *
 * @param {TxOutputSortable} a
 * @param {TxOutputSortable} b
 * @returns {Uint32}
 */
export function sortOutputs(a: TxOutputSortable, b: TxOutputSortable): Uint32;
/**
 * @param {Object} txInfo
 * @param {Uint16} [txInfo.version]
 * @param {Uint16} [txInfo.type]
 * @param {Array<TxInputRaw>} txInfo.inputs
 * @param {Array<TxOutput>} txInfo.outputs
 * @param {Uint32} [txInfo.locktime]
 * @param {Hex} [txInfo.extraPayload]
 * @param {Boolean} [txInfo._debug] - bespoke debug output
 */
export function createRaw(txInfo: {
    version?: number | undefined;
    type?: number | undefined;
    inputs: Array<TxInputRaw>;
    outputs: Array<TxOutput>;
    locktime?: number | undefined;
    extraPayload?: string | undefined;
    _debug?: boolean | undefined;
}): {
    version?: number | undefined;
    type?: number | undefined;
    inputs: Array<TxInputRaw>;
    outputs: Array<TxOutput>;
    locktime?: number | undefined;
    extraPayload?: string | undefined;
    _debug?: boolean | undefined;
};
/**
 * @param {TxInputRaw} input
 * @param {Uint32} i
 */
export function createInputRaw(input: TxInputRaw, i: Uint32): {
    txid: string;
    txId: string;
    outputIndex: number;
};
/**
 * @param {TxInfo} txInfo
 * @param {Uint32} inputIndex - create hashable tx for this input
 * @param {Uint32} sigHashType - 0x01 for ALL, or 0x81 for ALL + ANYONECANPAY
 */
export function createForSig(txInfo: TxInfo, inputIndex: Uint32, sigHashType: Uint32): {
    indexForSig: number;
} & TxInfo;
/**
 * @param {TxInputForSig} input
 * @param {Uint32} i - create hashable tx for this input
 */
export function createInputForSig(input: TxInputForSig, i: Uint32): {
    txId: string;
    txid: string;
    outputIndex: number;
    pubKeyHash: string | undefined;
    sigHashType: number | undefined;
    script: string;
};
/**
 * @param {Hex} pubKeyHash
 * @returns {Hex}
 */
export function createPkhScript(pubKeyHash: Hex): Hex;
/**
 * @param {Object} txInfo
 * @param {Uint16} [txInfo.version]
 * @param {Uint16} [txInfo.type]
 * @param {Array<TxInputRaw|TxInputForSig|TxInputSigned>} txInfo.inputs
 * @param {Array<TxOutput>} txInfo.outputs
 * @param {Uint32} [txInfo.locktime]
 * @param {Hex?} [txInfo.extraPayload] - extra payload
 * @param {Boolean} [txInfo._debug] - bespoke debug output
 * @param {Uint32?} [sigHashType]
 */
export function serialize({ version, type, inputs, outputs, locktime, extraPayload, _debug, }: {
    version?: number | undefined;
    type?: number | undefined;
    inputs: Array<TxInputRaw | TxInputForSig | TxInputSigned>;
    outputs: Array<TxOutput>;
    locktime?: number | undefined;
    extraPayload?: string | null | undefined;
    _debug?: boolean | undefined;
}, sigHashType?: Uint32 | null): string;
/**
 * @param {Array<TxInput|TxInputRaw|TxInputForSig|TxInputSigned>} inputs
 * @param {Object} [_opts]
 * @param {Array<String>} [_opts._tx]
 * @param {String} [_opts._sep]
 */
export function serializeInputs(inputs: Array<TxInput | TxInputRaw | TxInputForSig | TxInputSigned>, _opts?: {
    _tx?: string[] | undefined;
    _sep?: string | undefined;
}): string[];
/**
 * @param {TxInput|TxInputRaw|TxInputForSig|TxInputSigned} input
 * @param {Uint32} i
 * @param {Object} [_opts]
 * @param {Array<String>} [_opts._tx]
 * @param {String} [_opts._sep]
 */
export function serializeInput(input: TxInput | TxInputRaw | TxInputForSig | TxInputSigned, i: Uint32, _opts?: {
    _tx?: string[] | undefined;
    _sep?: string | undefined;
}): string[];
export function serializeOutputs(txOutputs: Array<TxOutput>, _opts?: {
    _tx?: string[] | undefined;
    _sep?: string | undefined;
} | undefined): any;
/**
 * @param {TxOutput} output
 * @param {Uint32} i
 * @param {Object} [_opts]
 * @param {Array<String>} [_opts._tx]
 * @param {String} [_opts._sep]
 */
export function serializeOutput(output: TxOutput, i: Uint32, _opts?: {
    _tx?: string[] | undefined;
    _sep?: string | undefined;
}): string[];
/**
 * @param {Object} [opts]
 * @param {String?} [opts.message] - UTF-8 Memo String
 */
export function createDonationOutput(opts?: {
    message?: string | null | undefined;
}): {
    satoshis: number;
    message: string;
};
export function sum(coins: Array<TxHasSats>): Uint53;
/**
 * @param {String} txHex
 */
export function parseUnknown(txHex: string): TxInfo;
export const _OP_DUP_HEX: "76";
export const _OP_HASH160_HEX: "a9";
export const _OP_EQUALVERIFY_HEX: "88";
export const _OP_CHECKSIG_HEX: "ac";
export const _OP_RETURN_HEX: "6a";
export const _PKH_SIZE_HEX: string;
export const _PKH_SCRIPT_SIZE_HEX: string;
export const LEGACY_DUST: 2000;
export const HEADER_SIZE: number;
export const MIN_INPUT_SIZE: number;
export const MAX_INPUT_PAD: number;
export const MAX_INPUT_SIZE: number;
export const OUTPUT_SIZE: number;
export const SIGHASH_ALL: 1;
export const SIGHASH_NONE: 2;
export const SIGHASH_SINGLE: 3;
export const SIGHASH_ANYONECANPAY: 128;
export const SIGHASH_DEFAULT: number;
/**
 * Creates a transaction that is guaranteed to be signable.  Selects
 * the smallest coin that is bigger or equal to the amount sent + fees,
 * or the largest available coins until that total is met.
 */
export function legacyCreateTx(coins: any, outputs: any, changeOutput: any, extraPayload: any): {
    version: number;
    type: number;
    inputs: TxInputUnspent[];
    outputs: any;
    changeIndex: any;
    locktime: number;
    extraPayload: any;
};
/**
 * @param {Object} txInfo
 * @param {Uint16} [txInfo.version]
 * @param {Uint16} [txInfo.type]
 * @param {Array<TxInputRaw|TxInputForSig|TxInputSigned>} txInfo.inputs
 * @param {Array<TxOutput>} txInfo.outputs
 * @param {Uint32} [txInfo.locktime]
 * @param {Hex?} [txInfo.extraPayload] - extra payload
 * @param {Boolean} [txInfo._debug] - bespoke debug output
 * @param {Uint32?} [sigHashType]
 */
export function serializeForSig({ version, type, inputs, outputs, locktime, extraPayload, _debug, }: {
    version?: number | undefined;
    type?: number | undefined;
    inputs: Array<TxInputRaw | TxInputForSig | TxInputSigned>;
    outputs: Array<TxOutput>;
    locktime?: number | undefined;
    extraPayload?: string | null | undefined;
    _debug?: boolean | undefined;
}, sigHashType?: Uint32 | null): string;
/** @type {TxGetId} */
export const getId: TxGetId;
export function doubleSha256(bytes: Uint8Array): Promise<Uint8Array>;
export { TxUtils as utils };
export type TxCreate = (keyUtils: TxKeyUtils) => tx;
export type tx = {
    hashAndSignAll: TxHashAndSignAll;
    hashAndSignInput: TxHashAndSignInput;
};
export type Float64 = number;
export type Uint8 = number;
export type Uint16 = number;
export type Uint32 = number;
export type Uint53 = number;
export type Hex = string;
export type TxPrivateKey = Uint8Array;
export type TxPublicKey = Uint8Array;
export type TxSignature = Uint8Array;
export type CoreUtxo = {
    /**
     * - deprecated
     */
    txId?: string | undefined;
    txid: string;
    outputIndex: number;
    address: string;
    script: string;
    satoshis: number;
};
export type TxKeyUtils = {
    getPrivateKey: TxGetPrivateKey;
    /**
     * - efficiently get public key bytes
     */
    getPublicKey?: TxGetPublicKey | undefined;
    /**
     * - convert private bytes to pub bytes
     */
    toPublicKey: TxToPublicKey;
    sign: TxSign;
};
export type TxDeps = Required<TxKeyUtils>;
export type TxFees = {
    max: Uint53;
    mid: Uint53;
    min: Uint53;
};
export type TxInfo = {
    version?: number | undefined;
    type?: number | undefined;
    inputs: Array<TxInputForSig>;
    outputs: Array<TxOutput>;
    /**
     * - 0 by default
     */
    locktime?: number | undefined;
    /**
     * - extra payload bytes
     */
    extraPayload?: string | undefined;
    /**
     * - signed transaction hex
     */
    transaction?: string | undefined;
    /**
     * - bespoke debug output
     */
    _debug?: boolean | undefined;
};
export type TxDraft = TxInfo & TxDraftPartial;
export type TxDraftPartial = {
    change: TxOutput | null;
    feeTarget: Uint53;
    fullTransfer: boolean;
};
export type TxInfoSigned = {
    version: Uint16;
    type: Uint16;
    inputs: Array<TxInputSigned>;
    outputs: Array<TxOutput>;
    /**
     * - 0 by default
     */
    locktime: Uint32;
    /**
     * - extra payload bytes
     */
    extraPayload: Hex;
    /**
     * - signed transaction hex
     */
    transaction: string;
    /**
     * - bespoke debug output
     */
    _debug?: boolean | undefined;
};
export type TxSummary = TxInfoSigned & TxSummaryPartial;
export type TxSummaryPartial = {
    /**
     * - sum of all inputs
     */
    total: Uint53;
    /**
     * - sum of all outputs
     */
    sent: Uint53;
    /**
     * - actual fee
     */
    fee: Uint53;
    outputs: Array<TxOutput>;
    inputs: Array<TxInput>;
    /**
     * - alias of 'recipient' for backwards-compat
     */
    output: TxOutput;
    /**
     * - output to recipient
     */
    recipient: TxOutput;
    /**
     * - sent back to self
     */
    change: TxOutput;
};
export type TxInput = {
    /**
     * - BaseCheck58-encoded pubKeyHash
     */
    address?: string | undefined;
    /**
     * - deprecated
     */
    txId?: string | undefined;
    /**
     * - hex (not pre-reversed)
     */
    txid: string;
    /**
     * - index in previous tx's output (vout index)
     */
    outputIndex: Uint32;
    /**
     * - hex-encoded ASN.1 (DER) signature (starts with 0x30440220 or  0x30440221)
     */
    signature: string;
    /**
     * - the previous lock script (default: derived from public key as p2pkh)
     */
    script?: string | undefined;
    /**
     * - hex-encoded public key (typically starts with a 0x02 or 0x03 prefix)
     */
    publicKey: string;
    /**
     * - the 20-byte pubKeyHash (address without magic byte or checksum)
     */
    pubKeyHash?: string | undefined;
    /**
     * - the 4-byte sequence (typically ffffffff)
     */
    sequence?: string | undefined;
    /**
     * - typically 0x81 (SIGHASH_ALL|SIGHASH_ANYONECANPAY)
     */
    sigHashType: Uint32;
};
export type TxInputForSig = {
    /**
     * - BaseCheck58-encoded pubKeyHash
     */
    address?: string | undefined;
    /**
     * - (deprecated) see .txid
     */
    txId?: string | undefined;
    /**
     * - hex (not pre-reversed)
     */
    txid: string;
    /**
     * - index in previous tx's output (vout index)
     */
    outputIndex: Uint32;
    /**
     * - (included for convenience as type hack)
     */
    satoshis?: number | undefined;
    /**
     * - (included as type hack)
     */
    signature?: string | undefined;
    /**
     * - the previous lock script (default: derived from public key as p2pkh)
     */
    script?: string | undefined;
    /**
     * - hex-encoded public key (typically starts with a 0x02 or 0x03 prefix)
     */
    publicKey?: string | undefined;
    /**
     * - the 20-byte pubKeyHash (address without magic byte or checksum)
     */
    pubKeyHash?: string | undefined;
    /**
     * - the 4-byte sequence (typically ffffffff)
     */
    sequence?: string | undefined;
    /**
     * - typically 0x81 (SIGHASH_ALL|SIGHASH_ANYONECANPAY)
     */
    sigHashType?: number | undefined;
};
export type TxInputRaw = {
    /**
     * - BaseCheck58-encoded pubKeyHash
     */
    address?: string | undefined;
    /**
     * - for convenience
     */
    satoshis?: number | undefined;
    /**
     * - deprecated
     */
    txId?: string | undefined;
    /**
     * - hex (not pre-reversed)
     */
    txid: string;
    /**
     * - index in previous tx's output (vout index)
     */
    outputIndex: Uint32;
    /**
     * - the 4-byte sequence (typically ffffffff)
     */
    sequence?: string | undefined;
};
export type TxInputUnspent = {
    /**
     * - BaseCheck58-encoded pubKeyHash
     */
    address?: string | undefined;
    satoshis: Uint53;
    /**
     * - deprecated
     */
    txId?: string | undefined;
    /**
     * - hex (not pre-reversed)
     */
    txid: string;
    /**
     * - index in previous tx's output (vout index)
     */
    outputIndex: Uint32;
};
export type TxInputSortable = {
    /**
     * - deprecated
     */
    txId?: string | undefined;
    txid: string;
    outputIndex: Uint32;
};
export type TxHasSats = {
    satoshis: Uint53;
};
export type TxInputSigned = Pick<TxInput, "txId" | "txid" | "outputIndex" | "signature" | "publicKey" | "sequence" | "sigHashType">;
export type TxOutput = {
    /**
     * - hex bytes of a memo (incompatible with pubKeyHash / address)
     */
    memo?: string | null | undefined;
    /**
     * - memo, but as a UTF-8 string
     */
    message?: string | null | undefined;
    /**
     * - payAddr as Base58Check (human-friendly)
     */
    address?: string | undefined;
    /**
     * - payAddr's raw hex value (decoded, not Base58Check)
     */
    pubKeyHash?: string | undefined;
    /**
     * - the number of smallest units of the currency
     */
    satoshis: Uint53;
};
export type TxOutputSortable = {
    satoshis: Uint53;
    /**
     * - hex bytes in wire order
     */
    script?: string | undefined;
    /**
     * - 0x6a, hex bytes
     */
    memo?: string | null | undefined;
    /**
     * - 0x76, 0xa9, hex bytes
     */
    pubKeyHash?: string | undefined;
    /**
     * - 0x76, 0xa9, base58check bytes
     */
    address?: string | undefined;
};
export type TxAddrToPubKeyHash = (addr: string) => string;
/**
 * Calculate the min, mid, and max sizes, which are 25%, 75%, and 100% likely
 * to match the signed byte size (which varies randomly on each signing due to
 * padding bytes). If in doubt, start with the mid as the fee and if the signed
 * tx is larger, increment by one and repeat until the fee is greater than the
 * size.
 */
export type TxAppraise = (txInfo: TxInfo) => TxFees;
export type TxAppraiseCounts = (numInputs: Uint32, numOutputs: Uint32, extraSize?: number | undefined) => TxFees;
export type TxAppraiseMemos = (outputs: Array<TxOutput>) => Uint32;
export type TxCreatePkhScript = (pubKeyHash: Hex) => Hex;
export type TxGetId = (txHex: string) => Promise<string>;
export type TxGetPrivateKey = (txInput: TxInputForSig, i?: number | undefined, txInputs?: (TxInputForSig | TxInputRaw)[] | undefined) => Promise<TxPrivateKey | null>;
export type TxGetPublicKey = (txInput: TxInputForSig, i?: number | undefined, txInputs?: (TxInputForSig | TxInputRaw)[] | undefined) => Promise<TxPublicKey | null>;
export type TxHashAndSignAll = (txInfo: TxInfo, sigHashType?: number | undefined) => Promise<TxInfoSigned>;
export type TxHashAndSignInput = (privBytes: Uint8Array, txInfo: TxInfo, i: Uint32, sigHashType?: number | undefined) => Promise<TxInputSigned>;
export type TxDoubleSha256 = (txBytes: Uint8Array) => Promise<Uint8Array>;
export type TxHexToBytes = (hex: string) => Uint8Array;
export type TxCreateLegacyTx = (coins: Array<TxInputUnspent>, outputs: Array<TxOutput>, changeOutput: TxOutput) => Promise<TxInfo>;
export type TxParseRequest = (hex: Hex) => TxInfo;
export type TxParseSigHash = (hex: Hex) => TxInfo;
export type TxParseSigned = (hex: Hex) => TxInfo;
export type TxParseUnknown = (hex: Hex) => TxInfo;
export type TxReverseHex = (hex: string) => string;
export type TxSerializeOutputs = (txOutputs: Array<TxOutput>, _opts?: {
    _tx?: string[] | undefined;
    _sep?: string | undefined;
} | undefined) => any;
export type TxSign = (privateKey: TxPrivateKey, txHashBytes: Uint8Array) => Promise<TxSignature>;
export type TxSortBySats = (a: TxHasSats, b: TxHasSats) => Uint8;
export type TxSortInputs = (a: TxInputSortable, b: TxInputSortable) => Uint8;
export type TxSortOutputs = (a: TxOutputSortable, b: TxOutputSortable) => Uint8;
export type TxSum = (coins: Array<TxHasSats>) => Uint53;
export type TxToDash = (satoshis: Uint53) => Float64;
export type TxToSats = (dash: Float64) => Uint53;
export type TxToPublicKey = (privateKey: TxPrivateKey) => Promise<TxPublicKey>;
/**
 * Caution: JS can't handle 64-bit ints
 */
export type TxToVarInt = (n: bigint | Uint53) => string;
export type TxToVarIntSize = (n: bigint | Uint53) => Uint8;
export type TxBytesToHex = (buf: Uint8Array) => string;
export type TxStringToHex = (utf8: string) => string;
export type TxToUint32LE = (n: Uint32) => Hex;
export type TxToUint64LE = (n: Uint32) => Hex;
declare namespace TxUtils {
    /**
     * @param {String} hex
     * @param {Number} offset
     */
    function _parseVarIntHex(hex: string, offset: number): number[];
    /**
     * @param {string} basicAuthUrl - ex: https://api:token@trpc.digitalcash.dev/
     *                                    http://user:pass@localhost:19998/
     * @param {string} method - the rpc, such as 'getblockchaininfo',
     *                          'getaddressdeltas', or 'help'
     * @param {...any} params - the arguments for the specific rpc
     *                          ex: rpc(url, 'help', 'getaddressdeltas')
     */
    function rpc(basicAuthUrl: string, method: string, ...params: any[]): Promise<any>;
    /**
     * @param {String} hex
     */
    function hexToBytes(hex: string): Uint8Array<ArrayBuffer>;
    /**
     * @param {String} hex
     */
    function reverseHex(hex: string): string;
    function toVarInt(n: bigint | Uint53): string;
    /**
     * Just assumes that all target CPUs are Little-Endian,
     * which is true in practice, and much simpler.
     * @param {BigInt|Number} n - 16-bit positive int to encode
     */
    function _toUint16LE(n: bigint | number): string;
    /**
     * Just assumes that all target CPUs are Little-Endian,
     * which is true in practice, and much simpler.
     * @param {BigInt|Number} n - 32-bit positive int to encode
     */
    function toUint32LE(n: bigint | number): string;
    function _toUint32LE(n: any): string;
    /**
     * This can handle Big-Endian CPUs, which don't exist,
     * and looks too complicated.
     * @param {BigInt|Number} n - 64-bit BigInt or <= 53-bit Number to encode
     * @returns {String} - 8 Little-Endian bytes
     */
    function toUint64LE(n: bigint | number): string;
    function _toUint64LE(n: any): string;
    function toVarIntSize(n: bigint | Uint53): Uint8;
    function bytesToHex(buf: Uint8Array): string;
    function strToHex(utf8: string): string;
}
