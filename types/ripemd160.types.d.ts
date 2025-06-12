export const _types: true;
export type RIPEMD160 = {
    create: Create;
    hash: Hash;
};
export type Create = () => ripemd160;
export type Hash = (bytes: Uint8Array) => Uint8Array;
export type ripemd160 = {
    update: Update;
    digest: Digest;
};
export type Digest = () => Uint8Array;
export type Update = (data: Uint8Array) => ripemd160;
