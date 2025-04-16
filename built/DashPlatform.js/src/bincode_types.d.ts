import * as Bincode from './bincode.ts';
export type Option<T> = T | null | undefined;
/**
 * FixedBytes<N> is essentially a Uint8Array but when encoded it throws an error
 * if the length doesn't match, and is not length prefixed.
 * Equivalent to `[u8; N]` in Rust.
 */
export type FixedBytes<N extends number> = Uint8Array;
export type Hash = Uint8Array;
export type SocketAddr = typeof Bincode.SocketAddr extends Bincode.BinCodeable<infer T> ? T : never;
export declare const EncodeOnlyRawBytes: ((data: Uint8Array) => Uint8Array<ArrayBufferLike>) & {
    isValid(x: unknown): x is Uint8Array<ArrayBufferLike>;
    encode(bc: Bincode.BinCode, x: Uint8Array): void;
    decode(bc: Bincode.BinCode): never;
};
export declare const Transaction: ((data: Uint8Array) => Uint8Array<ArrayBufferLike>) & {
    isValid(x: unknown): x is Uint8Array<ArrayBufferLike>;
    encode(bc: Bincode.BinCode, x: Uint8Array): void;
    decode(bc: Bincode.BinCode): never;
};
export type Transaction = Uint8Array;
