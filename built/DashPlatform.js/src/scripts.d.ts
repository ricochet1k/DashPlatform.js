export declare function makeScript(...parts: (number | number[] | Uint8Array)[]): Uint8Array<ArrayBuffer>;
export declare function makeP2PK(pubkey: Uint8Array): Uint8Array<ArrayBuffer>;
export declare function makeP2SH(script_hash: Uint8Array): Uint8Array<ArrayBuffer>;
export declare function makeP2PKH(pubkey_hash: Uint8Array): Uint8Array<ArrayBuffer>;
export declare function makeOP_RETURN(data: Uint8Array): Uint8Array<ArrayBuffer>;
