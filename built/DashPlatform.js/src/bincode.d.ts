/**
 * The interface an object must conform to in order to be used by Bincode or
 * in another BinCode-able type.
 */
export interface BinCodeable<T> {
    /** The name of this type, used in error messages. */
    name: string;
    /** Return true if the given value is valid and can be encoded/decoded by this type. */
    isValid: (value: unknown) => boolean;
    /** Encode the given value into the BinCode stream. */
    encode: (bc: BinCode, value: T) => void;
    /** Decode the expected value from the BinCode stream. */
    decode: (bc: BinCode) => T;
}
/** Extra options can be passed to modify encoding/decoding behavior. */
export interface BinCodeOptions {
    signable?: Boolean;
}
/** Encode a BinCodeable value returning an ArrayBuffer of bytes */
export declare function encode<T>(_type: BinCodeable<T>, value: T, options?: BinCodeOptions): ArrayBuffer;
/** Decode the given type from the given buffer. */
export declare function decode<T>(_type: BinCodeable<T>, value: ArrayBuffer, options?: {}): T;
/**
 * BinCode is a wrapper around a DataView to make it easier to use as a stream.
 * It is only used inside the encode/decode implementations for a particular type.
 * If you are looking to just encode/decode some array of bytes then look at {@link encode} or {@link decode}.
 * It also holds the BinCodeOptions passed to encode/decode.
 */
export declare class BinCode {
    dataview: DataView<ArrayBuffer>;
    idx: number;
    options: BinCodeOptions;
    constructor(dataview: DataView<ArrayBuffer>, idx?: number, options?: BinCodeOptions);
    /**
     * Returns the slice from 0 to the current index, when done writing.
     */
    slice(): ArrayBuffer;
    _idxThenAdd(add: number): number;
    /**
     * Returns the current index, before advancing it by `add`. If there are not enough
     * bytes in the current dataview, replaces it a new one twice the size.
     */
    _idxThenAddExtend(add: number): number;
    _debug(msg: any): void;
}
export declare function Vec<T>(inner: BinCodeable<T>): BinCodeable<T[]>;
export declare function Tuple<T extends BinCodeable<any>[]>(...inners: T): BinCodeable<T>;
declare const BincodeMap: <K, V>(keyType: BinCodeable<K>, valueType: BinCodeable<V>) => BinCodeable<Map<K, V>>;
export { BincodeMap as Map };
type BinCodeableStructTuple<N extends string, T extends BinCodeable<any>[]> = {
    (...data: UnBinCodeable<T>): UnBinCodeable<T> & {
        readonly $$type: N;
    };
    fields: T;
};
/**
 * A BinCodeable type that is a struct with named fields.
 */
type BinCodeableStruct<N extends string, T extends {
    [k: string]: BinCodeable<any>;
} | BinCodeable<any>[]> = BinCodeable<UnBinCodeable<T>> & (T extends BinCodeable<any>[] ? BinCodeableStructTuple<N, T> : {
    (data: UnBinCodeable<T>): UnBinCodeable<T> & {
        readonly $$type: N;
    };
    fields: T;
});
export declare function Struct<N extends string, T extends {
    [k: string]: BinCodeable<any>;
}>(name: N, fields: T): BinCodeableStruct<N, T>;
export declare function StructTuple<N extends string, T extends BinCodeable<any>[]>(name: N, ...fields: T): BinCodeableStruct<N, T>;
/**
 * Extract the object type from a Record of BinCodeable types.
 */
type UnBinCodeable<T extends {
    [f: string]: BinCodeable<any>;
} | BinCodeable<any>[]> = {
    [k in keyof T]: T[k] extends BinCodeable<infer U> ? U : never;
};
/**
 * Extract the union type from a Record of Variants of Bincodeable types.
 */
type EnumType<T extends {
    [k: string]: {
        [f: string]: BinCodeable<any>;
    } | BinCodeable<any>[];
}> = {
    [k in keyof T]: UnBinCodeable<T[k]>;
}[keyof T];
type EnumVariantStruct<N extends string, V extends string, T extends {
    [f: string]: BinCodeable<any>;
}> = {
    (data: UnBinCodeable<T>): UnBinCodeable<T> & {
        [ENUM]: N;
        [VARIANT]: V;
        [DISCRIMINANT]: number;
    };
    discriminant: number;
    fields: T;
};
type EnumVariantTuple<N extends string, V extends string, T extends BinCodeable<any>[]> = {
    (...data: UnBinCodeable<T>): UnBinCodeable<T> & {
        [ENUM]: N;
        [VARIANT]: V;
        [DISCRIMINANT]: number;
    };
    discriminant: number;
    fields: T;
};
type EnumVariant<N extends string, V extends string, T extends BinCodeable<any>[] | {
    [f: string]: BinCodeable<any>;
}> = T extends BinCodeable<any>[] ? EnumVariantTuple<N, V, T> : T extends {
    [f: string]: BinCodeable<any>;
} ? EnumVariantStruct<N, V, T> : never;
type BinCodeableEnum<N extends string, T extends {
    [k: string]: {
        [f: string]: BinCodeable<any>;
    } | BinCodeable<any>[];
}> = BinCodeable<EnumType<T>> & {
    $$type: {
        [ENUM]: N;
    };
    variants: T;
} & {
    [V in keyof T & string]: EnumVariant<N, V, T[V]>;
};
export declare const ENUM: unique symbol;
export declare const VARIANTS: unique symbol;
export declare const VARIANT: unique symbol;
export declare const VARIANT_NAME: unique symbol;
export declare const DISCRIMINANT: unique symbol;
type MatchFns<Variants, R> = {
    [k in keyof Variants]: (x: Variants[k] extends (data: any) => infer V ? V : never) => R;
};
export declare function match<Enum, T>(value: Enum, fns: Enum extends {
    [VARIANTS]: any;
} ? MatchFns<Enum[typeof VARIANTS], T> : never): T;
export declare function Enum<N extends string, T extends {
    [k: string]: {
        [f: string]: BinCodeable<any>;
    } | BinCodeable<any>[];
}>(name: N, definitions: T): BinCodeableEnum<N, T>;
export declare function VariantDiscriminant<T>(v: T, discriminant: number): T;
export declare const TODO: BinCodeable<never>;
export declare const Nothing: BinCodeable<undefined>;
export declare function Option<T>(inner: BinCodeable<T>): ((data: T | undefined) => T | undefined) & {
    isValid(data: unknown): boolean;
    encode(bc: BinCode, data: T | undefined | null): void;
    decode(bc: BinCode): T | undefined;
};
export declare function Lazy<T>(name: string, makeBincodeable: () => BinCodeable<T>): BinCodeable<T> & {
    unlazy: () => BinCodeable<T>;
};
export declare namespace Lazy {
    var unlazy: <T>(val: BinCodeable<T>) => BinCodeable<T>;
}
export declare const Null: BinCodeable<null>;
export declare const Uint8: BinCodeable<number>;
export declare const Uint16: BinCodeable<number>;
export declare const Uint32: BinCodeable<number>;
export declare const Uint64: BinCodeable<bigint>;
export declare const Uint128: BinCodeable<bigint>;
export declare const Int8: BinCodeable<number>;
/** @type {BinCodeable<number>} */
export declare const Int16: BinCodeable<number>;
export declare const Int32: BinCodeable<number>;
export declare const Int64: BinCodeable<bigint>;
export declare const Int128: BinCodeable<bigint>;
export declare const Float64: BinCodeable<number>;
export declare const VarUint: BinCodeable<number | bigint>;
export declare const VarInt: BinCodeable<number | bigint>;
export declare const Bool: BinCodeable<boolean>;
export declare const Bytes: BinCodeable<Uint8Array>;
export declare const String: BinCodeable<string>;
export declare function FixedBytes(length: number): BinCodeable<Uint8Array>;
/**
 * @template T
 * @param {BinCodeable<T>} inner
 * @returns {BinCodeable<T | undefined>}
 */
export declare function NotSignable<T>(inner: BinCodeable<T>): BinCodeable<T | undefined>;
/**
 * @template T
 * @param {BinCodeable<T>} inner
 */
export declare function Range<T>(inner: BinCodeable<T>): BinCodeable<[BinCodeable<T>, BinCodeable<T>]>;
export declare const Ipv4Addr: BinCodeableStruct<"Ipv4Addr", {
    octets: BinCodeable<Uint8Array<ArrayBufferLike>>;
}>;
export declare const SocketAddrV4: BinCodeableStruct<"SocketAddrV4", {
    ip: BinCodeableStruct<"Ipv4Addr", {
        octets: BinCodeable<Uint8Array<ArrayBufferLike>>;
    }>;
    port: BinCodeable<number>;
}>;
export declare const Ipv6Addr: BinCodeableStruct<"Ipv6Addr", {
    octets: BinCodeable<Uint8Array<ArrayBufferLike>>;
}>;
export declare const SocketAddrV6: BinCodeableStruct<"SocketAddrV6", {
    ip: BinCodeableStruct<"Ipv6Addr", {
        octets: BinCodeable<Uint8Array<ArrayBufferLike>>;
    }>;
    port: BinCodeable<number>;
    flowinfo: BinCodeable<number>;
    scope_id: BinCodeable<number>;
}>;
export declare const SocketAddr: BinCodeableEnum<"SocketAddr", {
    /** An IPv4 socket address. */
    V4: BinCodeableStruct<"SocketAddrV4", {
        ip: BinCodeableStruct<"Ipv4Addr", {
            octets: BinCodeable<Uint8Array<ArrayBufferLike>>;
        }>;
        port: BinCodeable<number>;
    }>[];
    /** An IPv6 socket address. */
    V6: BinCodeableStruct<"SocketAddrV6", {
        ip: BinCodeableStruct<"Ipv6Addr", {
            octets: BinCodeable<Uint8Array<ArrayBufferLike>>;
        }>;
        port: BinCodeable<number>;
        flowinfo: BinCodeable<number>;
        scope_id: BinCodeable<number>;
    }>[];
}>;
