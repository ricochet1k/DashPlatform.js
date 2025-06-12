/**
 * This is the core of an implementation of Rust's [Bincode](https://github.com/bincode-org/bincode) in Typescript.
 * If you are looking for how to use this module, your entry point is the {@link encode} and {@link decode} functions.
 * @module
 * 
 * @example
 * ```js
 * import * as Bincode from 'dashplatform/bincode'
 * 
 * let input = -42
 * let encoded_bytes = Bincode.encode(Bincode.VarInt, input)
 * let decoded_value = Bincode.decode(Bincode.VarInt, encoded_bytes)
 * console.assert(input === decoded_value)
 * ```
 */
import { toHex } from "./hex.js";

const DEBUG = false;
const LITTLE_ENDIAN = false;

/**
 * The interface an object must conform to in order to be used by Bincode or 
 * in another BinCode-able type.
 */
export interface BinCodeable<T> {
  /** The name of this type, used in error messages. */
  name: string
  /** Return true if the given value is valid and can be encoded/decoded by this type. */
  isValid: (value: unknown) => boolean
  /** Encode the given value into the BinCode stream. */
  encode: (bc: BinCode, value: T) => void
  /** Decode the expected value from the BinCode stream. */
  decode: (bc: BinCode) => T
}

/** Extra options can be passed to modify encoding/decoding behavior. */
export interface BinCodeOptions {
  signable?: Boolean
}

/** Encode a BinCodeable value returning an ArrayBuffer of bytes */
export function encode<T>(_type: BinCodeable<T>, value: T, options: BinCodeOptions = {}) {
  let ab = new ArrayBuffer(16);
  let dv = new DataView(ab);
  const bc = new BinCode(dv, 0, options);
  _type.encode(bc, value);
  return bc.slice();
}

/** Decode the given type from the given buffer. */
export function decode<T>(_type: BinCodeable<T>, value: ArrayBuffer, options = {}) {
  const bc = new BinCode(new DataView(value), 0, options);
  return _type.decode(bc);
}

/** 
 * BinCode is a wrapper around a DataView to make it easier to use as a stream.
 * It is only used inside the encode/decode implementations for a particular type.
 * If you are looking to just encode/decode some array of bytes then look at {@link encode} or {@link decode}.
 * It also holds the BinCodeOptions passed to encode/decode.
 */
export class BinCode {
  dataview: DataView<ArrayBuffer>
  idx: number
  options: BinCodeOptions

  constructor(dataview: DataView<ArrayBuffer>, idx: number = 0, options: BinCodeOptions = {}) {
    this.dataview = dataview;
    this.idx = idx;
    this.options = options;
  }

  /**
   * Returns the slice from 0 to the current index, when done writing.
   */
  slice() {
    return this.dataview.buffer.slice(0, this.idx);
  }

  _idxThenAdd(add: number) {
    let idx = this.idx;
    this.idx += add;
    return idx;
  }

  /**
   * Returns the current index, before advancing it by `add`. If there are not enough
   * bytes in the current dataview, replaces it a new one twice the size.
   */
  _idxThenAddExtend(add: number) {
    let idx = this.idx;
    this.idx += add;
    if (this.idx > this.dataview.byteLength) {
      // not enough space, extend the dataview
      let newlen = Math.max(this.dataview.byteLength * 2, this.idx + add);
      newlen = newlen < 16 ? 32 : newlen;
      let newab = new ArrayBuffer(newlen);
      new Uint8Array(newab).set(new Uint8Array(this.dataview.buffer), 0);
      // console.log("Extending BinCode dataview: ", this.idx, add, this.dataview.byteLength, this.dataview.buffer, ' -> ', newab);
      this.dataview = new DataView(newab);
    }
    return idx;
  }

  _debug(msg: any) {
    console.log(
      "DEBUG: " +
        msg +
        " at " +
        this.idx +
        ": " +
        toHex(this.dataview.buffer.slice(0, this.idx))
        + " " + 
        toHex(this.dataview.buffer.slice(this.idx)),
    );
  }
}

export function Vec<T>(inner: BinCodeable<T>): BinCodeable<T[]> {
  return {
    name: "Vec<" + inner.name + ">",
    isValid(value){
      return Array.isArray(value);
    },
    encode(bc, val) {
      VarUint.encode(bc, val.length);
      for (let i = 0; i < val.length; i++) {
        inner.encode(bc, val[i]);
      }
    },
    decode(bc) {
      let len = VarUint.decode(bc);
      /** @type {any[]} */
      let val: any[] = new Array(len);
      for (let i = 0; i < len; i++) {
        val[i] = inner.decode(bc);
      }
      return val;
    },
  }
}

export function Tuple<T extends BinCodeable<any>[]>(...inners: T): BinCodeable<T> {
  return {
    name: "(" + inners.map(t => t.name).join(', ') + ")",
    isValid(value){
      return Array.isArray(value);
    },
    encode(bc, val) {
      for (let i = 0; i < inners.length; i++) {
        inners[i].encode(bc, val[i]);
      }
    },
    decode(bc) {
      /** @type {*} */
      let val: any = new Array(inners.length);
      for (let i = 0; i < inners.length; i++) {
        val[i] = inners[i].decode(bc);
      }
      return val;
    },
  };
}

const BincodeMap = function BincodeMap<K, V>(keyType: BinCodeable<K>, valueType: BinCodeable<V>): BinCodeable<Map<K, V>> {
  return {
    name: "Map<" + keyType.name + ", " + valueType.name + ">",
    isValid(value){
      return Array.isArray(value);
    },
    encode(bc, val) {
      VarUint.encode(bc, val.size);
      for (const [k, v] of val.entries()) {
        keyType.encode(bc, k);
        valueType.encode(bc, v);
      }
    },
    decode(bc) {
      let len = VarUint.decode(bc);
      const val = new globalThis.Map<K, V>();
      for (let i = 0; i < len; i++) {
        const key = keyType.decode(bc);
        const value = valueType.decode(bc);
        val.set(key, value);
      }
      return val;
    },
  };
}

export { BincodeMap as Map };

// Typescript is a bit buggy with conditional, mapped tuple types as rest parameters so this has to be separate
type BinCodeableStructTuple<N extends string, T extends BinCodeable<any>[]> = {
  (...data: UnBinCodeable<T>): UnBinCodeable<T> & {readonly $$type: N}
  fields: T
}

function testIt() {
  let Test : BinCodeableStructTuple<"Foo", [typeof Uint8, typeof String]> = StructTuple("Foo", Uint8, String);
  let Test2 = StructTuple("Foo", Uint8, String);

  let test = Test(1, "hello");
  let test2 = Test2(1, "hello");
}

/**
 * A BinCodeable type that is a struct with named fields.
 */
type BinCodeableStruct<N extends string, T extends {[k: string]: BinCodeable<any>} | BinCodeable<any>[]> = BinCodeable<UnBinCodeable<T>> & 
  (T extends BinCodeable<any>[] ? BinCodeableStructTuple<N, T> : 
  {
    (data: UnBinCodeable<T>): UnBinCodeable<T> & {readonly $$type: N}
    fields: T
  })

export function Struct<N extends string, T extends {[k: string]: BinCodeable<any>}>(name: N, fields: T): BinCodeableStruct<N, T> {
  /** @type {BinCodeableStruct<T>} */
  // @ts-ignore
  const strct: BinCodeableStruct<T> = {
    [name]: function(data: T) {
      // if (!(this instanceof strct)) {
      //   return new strct(data);
      // }
      const instance = Object.create(strct.prototype);
      for (const key in fields) {
        if (!(key in data) && !fields[key].isValid(undefined)) {
          throw new Error("Struct " + name + " missing key: " + key);
        }
        instance[key] = data[key];
      }
      return instance;
    }
  }[name];

  strct.prototype = Object.create(Object.prototype, {
    constructor: {
      enumerable: false,
      configurable: true,
      writable: true,
      value: strct,
    },
    "$$type": {
      value: name,
      writable: false,
      enumerable: false,
      configurable: false,
    },
  });

  strct.fields = fields;

  strct.isValid = function isValid(value: unknown): boolean{
    if (!value || typeof value !== 'object') return false;
    for (const innerKey in fields) {
      // @ts-ignore
      if (!fields[innerKey].isValid(value[innerKey])) {
        return false;
      }
    }
    return true;
  }

  strct.encode = {[name+"_encode"]: function(bc: BinCode, val: T) {
    for (const innerKey in fields) {
      fields[innerKey].encode(bc, val[innerKey]);
    }
  }}[name+"_encode"]

  strct.decode = function decode(bc: BinCode): T {
    /** @type {any} */
    let val: any = {};
    for (const innerKey in fields) {
      if (DEBUG) bc._debug(`  decoding ${name}.${innerKey} (${fields[innerKey].name})`)
      val[innerKey] = fields[innerKey].decode(bc);
      if (DEBUG) bc._debug(`  decoded ${name}.${innerKey} (${fields[innerKey].name}) to ${val[innerKey]}`)
    }
    // if (DEBUG) bc._debug(`decoded ${name} to ${JSON.stringify(val)}`)
    return strct(val);
  }

  return strct;
}

export function StructTuple<N extends string, T extends BinCodeable<any>[]>(name: N, ...fields: T): BinCodeableStruct<N, T> {
  /** @type {BinCodeableStruct<T>} */
  // @ts-ignore
  const strct: BinCodeableStruct<T> = {
    [name]: function(this: T, ...data: T) {
      if (!(this instanceof strct)) {
        return new strct(...data);
      }

      // Array.call(this);

      if (data.length !== fields.length) {
        throw new Error("Struct " + name + " expected " + fields.length + " fields, got " + data.length);
      }

      // const instance = this;
      // We have to explicitly set the length property since Array's don't really subclass well
      this.length = data.length;
      for (const key in fields) {
        this[key] = data[key];
      }
      // return instance;
    }
  }[name];

  strct.prototype = Object.create(Array.prototype, {
    constructor: {
      enumerable: false,
      configurable: true,
      writable: true,
      value: strct,
    },
    "$$type": {
      value: name,
      writable: false,
      enumerable: false,
      configurable: false,
    },
  });

  strct.prototype.toJSON = function() {
    return Array.from(this)
  }

  strct.fields = fields;

  strct.isValid = function isValid(value: unknown): boolean{
    if (!value || typeof value !== 'object') return false;
    for (const innerKey in fields) {
      // @ts-ignore
      if (!fields[innerKey].isValid(value[innerKey])) {
        return false;
      }
    }
    return true;
  }

  strct.encode = {[name+"_encode"]: function(bc: BinCode, val: T) {
    for (let innerKey = 0; innerKey < fields.length; innerKey++) {
      fields[innerKey].encode(bc, val[innerKey]);
    }
  }}[name+"_encode"]

  strct.decode = {[name+"_decode"]: function(bc: BinCode): T {
    /** @type {any} */
    let val: any = [];
    for (let innerKey = 0; innerKey < fields.length; innerKey++) {
      if (DEBUG) bc._debug(`  decoding ${name}.${innerKey} (${fields[innerKey].name})`)
      val[innerKey] = fields[innerKey].decode(bc);
      // if (DEBUG) bc._debug(`  decoded ${name}.${innerKey} (${fields[innerKey].name}) to ${JSON.stringify(val[innerKey])}`)
    }
    // if (DEBUG) bc._debug(`decoded ${name} to ${JSON.stringify(val)}`)
    return strct(...val);
  }}[name+"_decode"]

  return strct;
}

/**
 * Extract the object type from a Record of BinCodeable types.
 */
type UnBinCodeable<T extends {[f: string]: BinCodeable<any>} | BinCodeable<any>[]> = {
  [k in keyof T]: T[k] extends BinCodeable<infer U> ? U : never
}

/**
 * Extract the union type from a Record of Variants of Bincodeable types.
 */
type EnumType<T extends {[k: string]: {[f: string]: BinCodeable<any>} | BinCodeable<any>[]}> = {
  [k in keyof T]: UnBinCodeable<T[k]>
}[keyof T]

type EnumVariantStruct<N extends string, V extends string, T extends {[f: string]: BinCodeable<any>}> = {
  (data: UnBinCodeable<T>): UnBinCodeable<T> & {[ENUM]: N, [VARIANT]: V, [DISCRIMINANT]: number}
  discriminant: number
  fields: T
}

type EnumVariantTuple<N extends string, V extends string, T extends BinCodeable<any>[]> = {
  (...data: UnBinCodeable<T>): UnBinCodeable<T> & {[ENUM]: N, [VARIANT]: V, [DISCRIMINANT]: number}
  discriminant: number
  fields: T
}

type EnumVariant<N extends string, V extends string, T extends BinCodeable<any>[] | {[f: string]: BinCodeable<any>}> = 
  T extends BinCodeable<any>[]? EnumVariantTuple<N, V, T> : 
  T extends {[f: string]: BinCodeable<any>}? EnumVariantStruct<N, V, T> : never;

type BinCodeableEnum<N extends string, T extends { [k: string]: { [f: string]: BinCodeable<any>; } | BinCodeable<any>[]; }> = BinCodeable<EnumType<T>> & {
  $$type: {[ENUM]: N};
  variants: T;
} & { [V in keyof T & string]: EnumVariant<N, V, T[V]> }

export const ENUM = Symbol("ENUM")
export const VARIANTS = Symbol("VARIANTS")
export const VARIANT = Symbol("VARIANT")
export const VARIANT_NAME = Symbol("VARIANT_NAME")
export const DISCRIMINANT = Symbol("DISCRIMINANT")

type MatchFns<Variants, R> = {[k in keyof Variants]: (x: Variants[k] extends (data: any) => infer V ? V : never) => R};
export function match<Enum, T>(value: Enum, fns: Enum extends {[VARIANTS]: any} ? MatchFns<Enum[typeof VARIANTS], T> : never): T {
  const anyValue = value as any;
  const variantName = anyValue[VARIANT];
  const fn = fns[variantName];
  if (!fn) {
    throw new Error("No match for " + variantName);
  }
  return fn(anyValue)
}

export function Enum<N extends string, T extends {[k: string]: {[f: string]: BinCodeable<any>} | BinCodeable<any>[]}>(name: N, definitions: T): BinCodeableEnum<N, T> {
  const enumClass: any = {[name]: function() {
    // console.log("DEBUG:", "Enum", name, {this: this});
  }}[name];

  enumClass.variants = {};

  Object.defineProperties(enumClass.prototype, {
    [ENUM]: {
      value: name,
      writable: false,
      enumerable: false,
      configurable: false,
    },
    [VARIANTS]: enumClass.variants,
  });

  enumClass.isValid = function isValid(value: unknown): boolean{
    // We need to check that exactly one of the definitions is valid
    // if there are multiple valid definitions, the value is ambiguous
    let valid = 0;
    for (const key in definitions) {
      if (enumClass.variants[key].isValid(value)) {
        valid += 1;
      }
    }
    return valid == 1;
  }

  enumClass.encode = {[name+"_encode"]: function(bc: BinCode, val: EnumType<T>) {
    const variant = Object.getPrototypeOf(val).constructor;
    const discriminant = variant.discriminant;
    VarUint.encode(bc, discriminant);
    variant.encode(bc, val);
  }}[name+"_encode"]

  enumClass.decode = function decode(bc: BinCode): EnumType<T> {
    const discriminant = Number(VarUint.decode(bc));
    const variantName = Object.keys(enumClass.variants)[discriminant];
    if (DEBUG) bc._debug(`decoded ${name} variant: ${discriminant} ${variantName}`)
    if (!variantName)
      throw new Error(
        "Enum " + this.name + " decode failed, bad discriminant: " + discriminant,
      );

    return enumClass.variants[variantName].decode(bc);
  }

  let prevDiscriminant = 0;
  for (const [variantName, fields] of Object.entries(definitions)) {
    const theDiscriminant = (fields as any)[VARIANT_DISCRIMINANT] ?? prevDiscriminant;
    prevDiscriminant = theDiscriminant + 1;

    const variantClassName = name + '.' + variantName;

    const fieldsKeys = Object.keys(fields);
    const numFields = fieldsKeys.length;
    const isTuple = Array.isArray(fields);

    /** @type {*} */
    const variantClass: any = isTuple ? {
      [variantClassName]: function(...data: any) {
          // console.log("DEBUG:", "EnumVariant", variantName, {this: this});
          if (!(this instanceof variantClass)) {
            // @ts-ignore
            return new variantClass(...data);
          }

          enumClass.call(this);

          if (data.length != numFields) {
            throw new Error("Variant " + name + " expected " + numFields + " fields, got " + data.length + ": " + JSON.stringify(data));
          }

          for (let i = 0; i < numFields; i++) {
            this[i] = data[i];
          }

          // console.log("DEBUG:", "EnumVariant done", variantName, this);
      }
    }[variantClassName]
     :
{
      [variantClassName]: function(data: any) {
          // console.log("DEBUG:", "EnumVariant", variantName, {this: this});
          if (!(this instanceof variantClass)) {
            // @ts-ignore
            return new variantClass(data);
          }

          enumClass.call(this);

          for (const key in fields) {
            if (!(key in data)) {
              throw new Error("Struct " + name + " missing key: " + key);
            }
            this[key] = data[key];
          }

          // console.log("DEBUG:", "EnumVariant done", variantName, this);
      }
    }[variantClassName];

    // console.log('DEBUG:', variantClass, variantClass.prototype, Object.create(variantClass.prototype));

    variantClass.prototype = Object.create(enumClass.prototype, {
      constructor: {
        enumerable: false,
        configurable: true,
        writable: true,
        value: variantClass,
      },
      [VARIANT]: {
        value: variantName,
        writable: false,
        enumerable: false,
        configurable: false,
      },
      [DISCRIMINANT]: {
        value: theDiscriminant,
        writable: false,
        enumerable: false,
        configurable: false,
      },
    });

    // Object.defineProperty(variantClass.prototype, 'constructor', {
    //   enumerable: false,
    //   configurable: true,
    //   writable: true,
    //   value: variantClass,
    // });
    // console.log('DEBUG:', variantClass, variantClass.prototype, Object.create(variantClass.prototype))

    // console.log('DEBUG:', 'vc.p', Object.getOwnPropertyDescriptors(variantClass.prototype));
    // console.log('DEBUG:', 'vc.p.p', Object.getOwnPropertyDescriptors(enumClass.prototype));

    variantClass.discriminant = theDiscriminant;

    variantClass.prototype.toJSON = function() {
      if (numFields == 0) {
        return ''+theDiscriminant;
        // return variantName;
      }
      if (isTuple) {
        if (numFields == 1) {
          // return {[variantName]: this[0]};
          return {$version: ''+theDiscriminant, ...this[0]}
        }
        return {[variantName]: Array.from(this)}
      }
      return {$version: ''+theDiscriminant, ...this}
      // return {[variantName]: {...this}}
    }

    const variantStruct = isTuple ? StructTuple(name + '.' + variantName, ...fields) : Struct(name + '.' + variantName, fields);

    variantClass.isValid = function isValid(val: any) {
      return variantStruct.isValid(val);
    }

    variantClass.decode = {[name+variantName+"_decode"]: function(bc: BinCode) {
      const data = variantStruct.decode(bc);
      // if (DEBUG) bc._debug(`decoded ${name}.${variantName} to ${JSON.stringify(data)}`)
      if (isTuple)
        return variantClass(...data as any);
      else
        return variantClass(data);
    }}[name+variantName+"_decode"]

    variantClass.encode = {[name+variantName+"_encode"]: function(bc: BinCode, val: any) {
      return variantStruct.encode(bc, val);
    }}[name+variantName+"_encode"]

    enumClass[variantName] = variantClass;
    enumClass.variants[variantName] = variantClass;
  }

  // console.log("Done constructing Enum", name, enumClass);

  return enumClass;
}

const VARIANT_DISCRIMINANT = Symbol("VARIANT_DISCRIMINANT")
// Wrap the variant in this to set a custom discriminant
export function VariantDiscriminant<T>(v: T, discriminant: number): T {
  (v as any)[VARIANT_DISCRIMINANT] = discriminant;
  return v;
}

export const TODO: BinCodeable<never> = {
  name: "TODO",
  // @ts-ignore
  isValid(value){
    throw new Error("TODO");
  },
  // @ts-ignore
  encode(bc, num) {
    throw new Error("TODO");
  },
  // @ts-ignore
  decode(bc) {
    throw new Error("TODO");
  },
};

export const Nothing: BinCodeable<undefined> = {
  name: "Nothing",
  isValid(value){
    return value === undefined;
  },
  encode(bc, num) {},
  decode(bc) {},
};

export function Option<T>(inner: BinCodeable<T>) {
  let name = `Option<${inner.name}>`;
  return Object.assign({[name]: function(data: T | undefined) {
    return data
  }}[name],
  {
    isValid(data: unknown) {
      if (data === null || data === undefined) return true;
      return inner.isValid(data);
    },
    encode(bc: BinCode, data: T | undefined | null) {
      if (data == null) {
        Uint8.encode(bc, 0);
      } else {
        Uint8.encode(bc, 1);
        inner.encode(bc, data);
      }
    },
    decode(bc: BinCode): T | undefined {
      const disc = Uint8.decode(bc);
      if (disc == 0) {
        return;
      } else if (disc == 1) {
        return inner.decode(bc);
      }
      throw new Error("Bad discriminant for " + name + ": " + disc);
    }
  })
}

export function Lazy<T>(name: string, makeBincodeable: () => BinCodeable<T>): BinCodeable<T> & { unlazy: () => BinCodeable<T> } {
  /** @type {BinCodeable<T> | undefined} */
  let bincodeable: BinCodeable<T> | undefined = undefined;
  function unlazy() {
    if (!bincodeable) bincodeable = makeBincodeable();
    return bincodeable;
  }
  return {
    name,
    unlazy,
    isValid(value){
      return unlazy().isValid(value);
    },
    encode(bc, val) {
      unlazy().encode(bc, val);
    },
    decode(bc) {
      return unlazy().decode(bc);
    },
  };
}

Lazy.unlazy = function unlazy<T>(val: BinCodeable<T>): BinCodeable<T> {
  // @ts-ignore
  if ('unlazy' in val) return val.unlazy();
  return val;
}

export const Null: BinCodeable<null> = {
  name: "Null",
  isValid(value){
    return value === null || value === undefined;
  },
  encode(bc, num) {},
  decode(bc) {
    return null;
  },
};

// /**
//  * Constant expects to be a single number, but does not encode or decode any bytes.
//  * @template T
//  * @param {T} value
//  * @returns {BinCodeable<T> & {value: T}}
//  */
// export function Constant(value) {
//   return {
//     name: "Constant<" + value + ">",
//     value,
//     // @ts-ignore
//     isValid(val){
//       return val === value;
//     },
//     // @ts-ignore
//     encode(bc, num) {
//     },
//     // @ts-ignore
//     decode(bc) {
//       return value;
//     },
//   };
// }

export const Uint8: BinCodeable<number> = {
  name: "Uint8",
  isValid(value){
    return typeof value === "number" && value >= 0 && value <= 0xFF && (value | 0) === value;
  },
  encode(bc, num) {
    const idx = bc._idxThenAddExtend(1)
    bc.dataview.setUint8(idx, num);
  },
  decode(bc) {
    return bc.dataview.getUint8(bc._idxThenAdd(1));
  },
};

export const Uint16: BinCodeable<number> = {
  name: "Uint16",
  isValid(value){
    return typeof value === "number" && value >= 0 && value <= 0xFFFF && (value | 0) === value;
  },
  encode(bc, num) {
    bc.dataview.setUint16(bc._idxThenAddExtend(2), num, LITTLE_ENDIAN);
  },
  decode(bc) {
    return bc.dataview.getUint16(bc._idxThenAdd(2), LITTLE_ENDIAN);
  },
};

export const Uint32: BinCodeable<number> = {
  name: "Uint32",
  isValid(value){
    return typeof value === "number" && value >= 0 && value <= 0xFFFFFFFF && (value | 0) === value;
  },
  encode(bc, num) {
    bc.dataview.setUint32(bc._idxThenAddExtend(4), num, LITTLE_ENDIAN);
  },
  decode(bc) {
    return bc.dataview.getUint32(bc._idxThenAdd(4), LITTLE_ENDIAN);
  },
};

export const Uint64: BinCodeable<bigint> = {
  name: "Uint64",
  isValid(value){
    if (typeof value === "bigint") return value >= 0n && value <= 0xFFFFFFFFFFFFFFFFn;
    return typeof value === "number" && value >= 0 && (value | 0) === value;
  },
  encode(bc, num) {
    const idx = bc._idxThenAddExtend(8);
    bc.dataview.setBigUint64(idx, num, LITTLE_ENDIAN);
  },
  decode(bc) {
    return bc.dataview.getBigUint64(bc._idxThenAdd(8), LITTLE_ENDIAN);
  },
};

export const Uint128: BinCodeable<bigint> = {
  name: "Uint128",
  isValid(value){
    if (typeof value === "bigint") return value >= 0n && value <= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFn;
    return typeof value === "number" && value >= 0 && (value | 0) === value;
  },
  encode(bc, num) {
    let a = BigInt.asUintN(64, num);
    let b = BigInt.asUintN(64, num >> 64n);
    // TODO: This probably isn't right when switching endian
    let idx = bc._idxThenAddExtend(8)
    bc.dataview.setBigUint64(idx, a, LITTLE_ENDIAN);
    idx = bc._idxThenAddExtend(8)
    bc.dataview.setBigUint64(idx, b, LITTLE_ENDIAN);
  },
  decode(bc) {
    // TODO: This probably isn't right when switching endian
    let a = bc.dataview.getBigUint64(bc._idxThenAdd(8), LITTLE_ENDIAN);
    let b = bc.dataview.getBigUint64(bc._idxThenAdd(8), LITTLE_ENDIAN);
    return BigInt(a.toString() + b.toString());
  },
};

export const Int8: BinCodeable<number> = {
  name: "Int8",
  isValid(value){
    return typeof value === "number" && value >= -0x8F && value <= 0x8F && (value | 0) === value;
  },
  encode(bc, num) {
    bc.dataview.setInt8(bc._idxThenAddExtend(1), num);
  },
  decode(bc) {
    return bc.dataview.getInt8(bc._idxThenAdd(1));
  },
};

/** @type {BinCodeable<number>} */
export const Int16: BinCodeable<number> = {
  name: "Int16",
  isValid(value){
    return typeof value === "number" && value >= -0x8FFF && value <= 0x8FFF && (value | 0) === value;
  },
  encode(bc, num) {
    bc.dataview.setInt16(bc._idxThenAddExtend(2), num, LITTLE_ENDIAN);
  },
  decode(bc) {
    return bc.dataview.getInt16(bc._idxThenAdd(2), LITTLE_ENDIAN);
  },
};

export const Int32: BinCodeable<number> = {
  name: "Int32",
  isValid(value){
    return typeof value === "number" && value >= -0x8FFFFFFF && value <= 0x8FFFFFFF && (value | 0) === value;
  },
  encode(bc, num) {
    bc.dataview.setInt32(bc._idxThenAddExtend(4), num, LITTLE_ENDIAN);
  },
  decode(bc) {
    return bc.dataview.getInt32(bc._idxThenAdd(4), LITTLE_ENDIAN);
  },
};

export const Int64: BinCodeable<bigint> = {
  name: "Int64",
  isValid(value){
    if (typeof value === "bigint") return value >= -0x8FFFFFFFFFFFFFFFn && value <= 0x8FFFFFFFFFFFFFFFn;
    return typeof value === "number" && value >= 0 && (value | 0) === value;
  },
  encode(bc, num) {
    bc.dataview.setBigInt64(bc._idxThenAddExtend(8), num, LITTLE_ENDIAN);
  },
  decode(bc) {
    return bc.dataview.getBigInt64(bc._idxThenAdd(8), LITTLE_ENDIAN);
  },
};

export const Int128: BinCodeable<bigint> = {
  name: "Int128",
  isValid(value){
    if (typeof value === "bigint") return value >= -0x8FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFn && value <= 0x8FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFn;
    return typeof value === "number" && value >= 0 && (value | 0) === value;
  },
  encode(bc, num) {
    let a = BigInt.asIntN(64, num);
    let b = BigInt.asIntN(64, num >> 64n);
    // TODO: this probably isn't right when switching endian?
    bc.dataview.setBigInt64(bc._idxThenAddExtend(8), a, LITTLE_ENDIAN);
    bc.dataview.setBigInt64(bc._idxThenAddExtend(8), b, LITTLE_ENDIAN);
  },
  decode(bc) {
    // TODO: this probably isn't right when switching endian?
    let a = bc.dataview.getBigInt64(bc._idxThenAdd(8), LITTLE_ENDIAN);
    let b = bc.dataview.getBigInt64(bc._idxThenAdd(8), LITTLE_ENDIAN);
    return BigInt(a.toString() + b.toString());
  },
};

export const Float64: BinCodeable<number> = {
  name: "Float64",
  isValid(value){
    return typeof value === "number";
  },
  encode(bc, num) {
    bc.dataview.setFloat64(bc._idxThenAddExtend(8), num, true);
  },
  decode(bc) {
    return bc.dataview.getFloat64(bc._idxThenAdd(8));
  },
};

function _zigzag(u: bigint) {
  if (u == 0n) return 0n;

  // To avoid the edge case of Signed::min_value()
  // !n is equal to `-n - 1`, so this is:
  // !n * 2 + 1 = 2(-n - 1) + 1 = -2n - 2 + 1 = -2n - 1
  if (u < 0) return (-u - 1n) * 2n - 1n;
  if (u > 0) return u * 2n;
  throw new Error("_zigzag error: " + u);
}

function _unzigzag(u: bigint) {
  if (u % 2n == 0n) {
    // positive number
    return u >> 1n;
  } else {
    // negative number
    // !m * 2 + 1 = u
    // !m * 2 = u - 1
    // !m = (u - 1) / 2
    // m = !((u - 1) / 2)
    // since we have u is odd, we have floor(u / 2) = floor((u - 1) / 2)
    return (-u >> 1n) - 1n;
  }
}

function _fitsInNumber(value: bigint) {
  return value <= Number.MAX_SAFE_INTEGER && value >= Number.MIN_SAFE_INTEGER;
}

export const VarUint: BinCodeable<number | bigint> = {
  name: "VarUint",
  isValid(value){
    if (typeof value === "bigint") return value >= 0n && value <= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFn;
    return typeof value === "number" && value >= 0 && (value | 0) === value;
  },
  encode(bc, num) {
    if (typeof num === "number" && !Number.isInteger(num))
      throw new Error("VarUint.encode: not an integer:" + num);
    if (num < 0) throw new Error("VarUint.encode: negative:" + num);

    // console.log('DEBUG:', 'VarUint.encode', num);

    if (num < 251) Uint8.encode(bc, Number(num));
    else if (251 <= num && num < 2 ** 16) {
      Uint8.encode(bc, 251);
      Uint16.encode(bc, Number(num));
    } else if (2 ** 16 <= num && num < 2 ** 32) {
      Uint8.encode(bc, 252);
      Uint32.encode(bc, Number(num));
    }
    // TODO: Bignum for the rest of these
    else if (2 ** 32 <= num && num < 2 ** 64) {
      Uint8.encode(bc, 253);
      Uint64.encode(bc, BigInt(num));
    } else if (2 ** 64 <= num && num < 2 ** 128) {
      Uint8.encode(bc, 254);
      Uint128.encode(bc, BigInt(num));
    } else {
      throw new Error("VarUint.encode error: " + num);
    }
  },

  decode(bc) {
    let u = BigInt(Uint8.decode(bc));
    if (u < 251) {
    } else if (u == 251n) u = BigInt(Uint16.decode(bc));
    else if (u == 252n) u = BigInt(Uint32.decode(bc));
    // TODO: Bignum for the rest of these
    else if (u == 253n) u = Uint64.decode(bc);
    else if (u == 254n) u = Uint128.decode(bc);
    else throw new Error("VarUint.decode error: " + u);

    if (_fitsInNumber(u)) return Number(u);
    return u;
  },
};

export const VarInt: BinCodeable<number | bigint> = {
  name: "VarInt",
  isValid(value){
    if (typeof value === "bigint") return value >= -0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFn && value <= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFn;
    return typeof value === "number" && (value | 0) === value;
  },
  encode(bc, num) {
    if (typeof num === "number" && (num | 0) !== num)
      throw new Error("VarInt.encode: not an integer:" + num);

    let bnum = BigInt(num);
    bnum = _zigzag(bnum);
    if (bnum < 251) Uint8.encode(bc, Number(bnum));
    else if (251 <= bnum && bnum < 2 ** 16) {
      Uint8.encode(bc, 251);
      Uint16.encode(bc, Number(bnum));
    } else if (2 ** 16 <= bnum && bnum < 2 ** 32) {
      Uint8.encode(bc, 252);
      Uint32.encode(bc, Number(bnum));
    }
    // TODO: Bignum for the rest of these
    else if (2 ** 32 <= bnum && bnum < 2 ** 64) {
      Uint8.encode(bc, 253);
      Uint64.encode(bc, bnum);
    } else if (2 ** 64 <= bnum && bnum < 2 ** 128) {
      Uint8.encode(bc, 254);
      Uint128.encode(bc, bnum);
    } else {
      throw new Error("VarInt.encode error: " + bnum);
    }
  },

  decode(bc) {
    let u = BigInt(Uint8.decode(bc));
    if (u < 251) {
    } else if (u == 251n) u = BigInt(Uint16.decode(bc));
    else if (u == 252n) u = BigInt(Uint32.decode(bc));
    // TODO: Bignum for the rest of these
    else if (u == 253n) u = Uint64.decode(bc);
    else if (u == 254n) u = Uint128.decode(bc);
    else throw new Error("VarInt.decode error: " + u);

    u = _unzigzag(u);
    if (_fitsInNumber(u)) return Number(u);
    return u;
  },
};

export const Bool: BinCodeable<boolean> = {
  name: "Bool",
  isValid(value){
    return typeof value === "boolean";
  },
  encode(bc, val) {
    return Uint8.encode(bc, val ? 1 : 0);
  },
  decode(bc) {
    const val = Uint8.decode(bc);
    if (val !== 0 && val !== 1) throw new Error("Bool decode error: " + val);
    return !!val;
  },
};

export const Bytes: BinCodeable<Uint8Array> = {
  name: "Bytes",
  isValid(value){
    return value instanceof Uint8Array;
  },
  encode(bc, val) {
    VarUint.encode(bc, val.length);
    let idx = bc._idxThenAddExtend(val.length);
    new Uint8Array(bc.dataview.buffer).set(val, idx)
  },
  decode(bc) {
    let length = Number(VarUint.decode(bc));
    let idx = bc._idxThenAdd(length);
    return new Uint8Array(bc.dataview.buffer, idx, length);
  },
};

export const String: BinCodeable<string> = {
  name: "String",
  isValid(value){
    return typeof value === "string";
  },
  encode(bc, val) {
    const bytes = new TextEncoder().encode(val);
    Bytes.encode(bc, bytes);
  },
  decode(bc) {
    const bytes = Bytes.decode(bc);
    return new TextDecoder().decode(bytes);
  },
};

export function FixedBytes(length: number): BinCodeable<Uint8Array> {
  return {
    name: "FixedBytes<" + length + ">",
    isValid(value){
      return value instanceof Uint8Array;
    },
    encode(bc, val) {
      if (val.length !== length) {
        throw new Error(`Expected exactly ${length} bytes, got ${val.length}`)
      }
      let idx = bc._idxThenAddExtend(length);
      let bytes = new Uint8Array(bc.dataview.buffer);
      // console.log(`DEBUG val, idx`, val, idx);
      bytes.set(val, idx);
    },
    decode(bc) {
      let idx = bc._idxThenAdd(length);
      return new Uint8Array(bc.dataview.buffer, idx, length);
    },
  };
}



/**
 * @template T
 * @param {BinCodeable<T>} inner
 * @returns {BinCodeable<T | undefined>}
 */
export function NotSignable<T>(inner: BinCodeable<T>): BinCodeable<T | undefined> {
    return {
        name: "NotSignable<" + inner.name + ">",
        isValid(value) {
            // TODO: Need options.signable to be passed in
            return inner.isValid(value)
        },
        encode(bc, value) {
            // console.log(`DEBUG NotSignable<${inner.name}>`, bc, value)
            if (!bc.options.signable) {
                if (value === undefined) {
                    throw new Error("NotSignable.encode: undefined value")
                }
                inner.encode(bc, value)
            }
        },
        decode(bc) {
            if (!bc.options.signable) {
                return inner.decode(bc)
            }
        },
    }
}

/**
 * @template T
 * @param {BinCodeable<T>} inner 
 */
export function Range<T>(inner: BinCodeable<T>) {
  return Tuple(inner, inner)
}

export const Ipv4Addr = Struct("Ipv4Addr", {
  octets: FixedBytes(4),
})

export const SocketAddrV4 = Struct("SocketAddrV4", {
  ip: Ipv4Addr,
  port: Uint16,
})

export const Ipv6Addr = Struct("Ipv6Addr", {
  octets: FixedBytes(16),
})

export const SocketAddrV6 = Struct("SocketAddrV6", {
  ip: Ipv6Addr,
  port: Uint16,
  flowinfo: Uint32,
  scope_id: Uint32,
})

export const SocketAddr = Enum("SocketAddr", {
  /** An IPv4 socket address. */
  V4: [SocketAddrV4],
  /** An IPv6 socket address. */
  V6: [SocketAddrV6],
})

export function typedArrayToBuffer(array: Uint8Array): ArrayBuffer {
    return (array.buffer as ArrayBuffer).slice(array.byteOffset, array.byteLength + array.byteOffset)
}
