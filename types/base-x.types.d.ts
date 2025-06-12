export const _types: true;
export type BaseX = {
    create: Create;
};
export type Create = (ALPHABET: string) => baseX;
export type baseX = {
    decode: Decode;
    encode: Encode;
};
export type Decode = (basex: string) => Uint8Array;
export type DecodeUnsafe = (basex: string) => Uint8Array | null;
export type Encode = (buf: Uint8Array) => string;
