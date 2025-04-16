/**
 * @param {String} id - typically address
 * @param {KeyInfo} keyInfo
 */
export function set(id: string, keyInfo: KeyInfo): void;
/**
 * @param {Uint8Array} privKeyBytes
 * @param {Uint8Array} hashBytes
 */
export function sign(privKeyBytes: Uint8Array, hashBytes: Uint8Array): Promise<any>;
/**
 * @param {Uint8Array} privKeyBytes
 * @param {Uint8Array} hashBytes
 */
export function signAsn1(privKeyBytes: Uint8Array, hashBytes: Uint8Array): Promise<any>;
/**
 * @param {Uint8Array} bytes
 */
export function doubleSha256(bytes: Uint8Array): Promise<Uint8Array<ArrayBuffer>>;
/**
 * @param {Uint8Array} bytes
 */
export function sha256(bytes: Uint8Array): Promise<Uint8Array<ArrayBuffer>>;
/**
 * Sha256 then RIPEMD-160
 * @param {Uint8Array} bytes
 */
export function pubkeyHash(bytes: Uint8Array): Promise<any>;
/**
 * This is called "Simple Sign" by the Rust SDK.
 * @param {Object} opts
 * @param {Uint8Array} opts.privKeyBytes
 * @param {Uint8Array} opts.doubleSha256Bytes
 */
export function magicSign({ privKeyBytes, doubleSha256Bytes }: {
    privKeyBytes: Uint8Array;
    doubleSha256Bytes: Uint8Array;
}): Promise<Uint8Array<ArrayBuffer>>;
/**
 * @param {Uint8Array} privKeyBytes
 * @param {Uint8Array} hashBytes
 * @param {Uint8Array} [sigBytes] - preallocated 64 bytes
 */
export function signP1363(privKeyBytes: Uint8Array, hashBytes: Uint8Array, sigBytes?: Uint8Array): Promise<Uint8Array<ArrayBufferLike>>;
/**
 * @param {Uint8Array} asn1
 * @param {Uint8Array} [p1363Signature]
 */
export function asn1ToP1363Signature(asn1: Uint8Array, p1363Signature?: Uint8Array): Uint8Array<ArrayBufferLike>;
/**
 * @param {{ address?: string; txid: any; outputIndex: any; }} input
 */
export function getPrivateKey(input: {
    address?: string;
    txid: any;
    outputIndex: any;
}): Promise<any>;
/**
 * @param {{ address?: string; txid: any; outputIndex: any; }} txInput
 * @param {any} i
 */
export function getPublicKey(txInput: {
    address?: string;
    txid: any;
    outputIndex: any;
}, i: any): Promise<any>;
/**
 * @param {Uint8Array} privKeyBytes
 */
export function toPublicKey(privKeyBytes: Uint8Array): Promise<any>;
export type KeyInfo = {
    address: string;
    privateKey: Uint8Array;
    publicKey: Uint8Array;
    pubKeyHash: string;
};
