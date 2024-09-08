import { toHex } from "./hex"

/**
 * @template T
 * @typedef BinCodeable
 * @prop {string} name
 * @prop {(bc: BinCode, value: T) => void} encode
 * @prop {(bc: BinCode) => T} decode
 */

/**
 * @template T
 * @param {BinCodeable<T>} _type
 * @param {T} value
 */
export function encode(_type, value) {
  const bc = new BinCode(new DataView(new ArrayBuffer(16)));
  _type.encode(bc, value);
  return bc.slice();
}

/**
 * @template T
 * @param {BinCodeable<T>} _type
 * @param {ArrayBuffer} value
 */
export function decode(_type, value) {
  const bc = new BinCode(new DataView(value));
  return _type.decode(bc);
}


export class BinCode {
  /**
   * 
   * @param {DataView} dataview 
   * @param {number} idx 
   */
  constructor(dataview, idx=0) {
    this.dataview = dataview;
    this.idx = idx;
  }

  /**
   * Returns the slice from 0 to the current index, when done writing.
   */
  slice() {
    return this.dataview.buffer.slice(0, this.idx);
  }

  /**
   * @param {number} add
   */
  _idxThenAdd(add) {
    let idx = this.idx;
    this.idx += add;
    return idx;
  }

  /**
   * Returns the current index, before advancing it by `add`. If there are not enough
   * bytes in the current dataview, replaces it a new one twice the size.
   * @param {number} add
   */
  _idxThenAddExtend(add) {
    let idx = this.idx;
    this.idx += add;
    if (this.idx > this.dataview.byteLength) {
      // not enough space, extend the dataview
      let newlen = Math.max(this.dataview.byteLength * 2, this.idx + add);
      let newab = new ArrayBuffer(newlen < 16? 32 : newlen);
      new Uint8Array(newab).set(new Uint8Array(this.dataview.buffer), 0);
      // console.log("Extending BinCode dataview: ", this.idx, add, this.dataview.byteLength, this.dataview.buffer, ' -> ', newab);
      this.dataview = new DataView(newab);
    }
    return idx;
  }

  /**
   * @param {any} msg
   */
  _debug(msg) {
    console.log('DEBUG: ' + msg + ' at ' + this.idx + ': ' + toHex(this.dataview.buffer.slice(this.idx)));
  }
}

/**
 * @template T
 * @param {BinCodeable<T>} inner
 * @returns {BinCodeable<T[]>}
 */
export function Vec(inner) {
  return {
    name: 'Vec<' + inner.name + '>',
    encode(bc, val) {
      VarUint.encode(bc, val.length);
      for (let i = 0; i < val.length; i++) {
        inner.encode(bc, val[i]);
      }
    },
    decode(bc) {
      let len = VarUint.decode(bc);
      let val = new Array(len);
      for (let i = 0; i < len; i++) {
        val[i] = inner.decode(bc);
      }
      return val;
    }
  }
}
  
/**
 * @template {{}} T
 * @param {string} name
 * @param {{[k in keyof T]: BinCodeable<T[k]>}} inner
 * @returns {BinCodeable<T>}
 */
export function Struct(name, inner) {
  return {
    name,
    encode(bc, val) {
      for (const innerKey in inner) {
        // const startIdx = bc.idx;
        inner[innerKey].encode(bc, val[innerKey]);
        // console.log('DEBUG:', 'encode', name + '.' + innerKey, '=', val[innerKey], 'at', startIdx, toHex(bc.dataview.buffer.slice(startIdx, bc.idx)));
      }
    },
    decode(bc) {
      /** @type {any} */
      let val = {};
      for (const innerKey in inner) {
        // bc._debug('decode ' + name + '.' + innerKey + ' as ' + inner[innerKey].name);
        val[innerKey] = inner[innerKey].decode(bc);
        // console.log('DEBUG:', 'decode', name + '.' + innerKey, '=', val[innerKey]);
      }
      return val;
    }
  }
}
  
/**
 * @template T
 * @param {string} name
 * @param {(val: T) => number} toDiscriminant
 * @param {{[k: number]: BinCodeable<T>}} definitions
 * @returns {BinCodeable<T>}
 */
export function Enum(name, toDiscriminant, definitions) {
  return {
    name,
    encode(bc, val) {
      const discriminant = toDiscriminant(val);
      VarUint.encode(bc, discriminant);
      definitions[discriminant].encode(bc, val);
    },
    decode(bc) {
      const discriminant = Number(VarUint.decode(bc));
      if (!(discriminant in definitions))
        throw new Error("Enum " + name + " decode failed, bad discriminant: " + discriminant);
      return definitions[discriminant].decode(bc);
    }
  }
}

/**
 * @template T
 * @param {BinCodeable<T>} inner
 * @returns {BinCodeable<T | null>}
 */
export function Option(inner) {
  return Enum('Option<' + inner.name + '>', x => x == null? 0 : 1, {
    0: Null,
    1: inner,
  })
}

/**
 * @template T
 * @param {() => BinCodeable<T>} makeBincodeable
 * @returns {BinCodeable<T>}
 */
export function Lazy(makeBincodeable) {
  /** @type {BinCodeable<T> | undefined} */
  let bincodeable = undefined;
  return {
    get name() {
      if (!bincodeable) bincodeable = makeBincodeable();
      return bincodeable.name;
    },
    encode(bc, val) {
      if (!bincodeable) bincodeable = makeBincodeable();
      bincodeable.encode(bc, val);
    },
    decode(bc) {
      if (!bincodeable) bincodeable = makeBincodeable();
      return bincodeable.decode(bc);
    }
  }
}

/** @type {BinCodeable<undefined>} */
export const TODO = {
  name: 'TODO',
  encode(bc, num) {
    throw new Error("TODO");
  },
  decode(bc) {
    throw new Error("TODO");
  }
}

/** @type {BinCodeable<undefined>} */
export const Nothing = {
  name: 'Nothing',
  encode(bc, num) {},
  decode(bc) {}
}

/** @type {BinCodeable<undefined>} */
export const Null = {
  name: 'Null',
  encode(bc, num) {},
  decode(bc) { return null; }
}

/** 
 * Constant doesn't encode or decode any bytes, it just always decodes to the constant value.
 * @template T
 * @param {T} value
 * @returns {BinCodeable<T>}
 */
export function Constant(value) {
  return {
    name: 'Constant<'+value+'>',
    encode(bc, num) {},
    decode(bc) { return value; }
  }
}

/** @type {BinCodeable<number>} */
export const Uint8 = {
  name: 'Uint8',
  encode(bc, num) {
    bc.dataview.setUint8(bc._idxThenAddExtend(1), num);
  },
  decode(bc) {
    return bc.dataview.getUint8(bc._idxThenAdd(1));
  }
}

/** @type {BinCodeable<number>} */
export const Uint16 = {
  name: 'Uint16',
  encode(bc, num) {
    bc.dataview.setUint16(bc._idxThenAddExtend(2), num, true);
  },
  decode(bc) {
    return bc.dataview.getUint16(bc._idxThenAdd(2));
  }
}

/** @type {BinCodeable<number>} */
export const Uint32 = {
  name: 'Uint32',
  encode(bc, num) {
    bc.dataview.setUint32(bc._idxThenAddExtend(4), num, true);
  },
  decode(bc) {
    return bc.dataview.getUint32(bc._idxThenAdd(4));
  }
}

/** @type {BinCodeable<bigint>} */
export const Uint64 = {
  name: 'Uint64',
  encode(bc, num) {
    bc.dataview.setBigUint64(bc._idxThenAddExtend(8), num, true);
  },
  decode(bc) {
    return bc.dataview.getBigUint64(bc._idxThenAdd(8));
  }
}

/** @type {BinCodeable<bigint>} */
export const Uint128 = {
  name: 'Uint128',
  encode(bc, num) {
    let a = BigInt.asUintN(64, num);
    let b = BigInt.asUintN(64, num>>64n);
    bc.dataview.setBigUint64(bc._idxThenAddExtend(8), a, true);
    bc.dataview.setBigUint64(bc._idxThenAddExtend(8), b, true);
  },
  decode(bc) {
    let a = Uint64.decode(bc);
    let b = Uint64.decode(bc);
    return BigInt(a.toString() + b.toString());
  }
}

/**
 * @param {bigint} u
 */
function _zigzag(u) {
  if (u == 0n) return 0n;

  // To avoid the edge case of Signed::min_value()
  // !n is equal to `-n - 1`, so this is:
  // !n * 2 + 1 = 2(-n - 1) + 1 = -2n - 2 + 1 = -2n - 1
  if (u < 0) return (-u - 1n) * 2n - 1n;
  if (u > 0) return u * 2n;
  throw new Error("_zigzag error: " + u);
}

/**
 * @param {bigint} u
 */
function _unzigzag(u) {
  if (u % 2n == 0n) {
      // positive number
      return u >> 1n
  } else {
      // negative number
      // !m * 2 + 1 = u
      // !m * 2 = u - 1
      // !m = (u - 1) / 2
      // m = !((u - 1) / 2)
      // since we have u is odd, we have floor(u / 2) = floor((u - 1) / 2)
      return ((-u) >> 1n) - 1n
  }
}

/**
 * @param {bigint} value
 */
function _fitsInNumber(value) {
  return value <= Number.MAX_SAFE_INTEGER && value >= Number.MIN_SAFE_INTEGER
}

/** @type {BinCodeable<number | bigint>} */
export const VarUint = {
  name: 'VarUint',
  encode(bc, num) {
    if (typeof num === 'number' && (num|0) !== num)
      throw new Error("VarUint.encode: not an integer:" + num);
    if (num < 0)
      throw new Error("VarUint.encode: negative:" + num);

    // console.log('DEBUG:', 'VarUint.encode', num);

    if (num < 251) Uint8.encode(bc, Number(num));
    else if (251 <= num && num < 2**16) {
      Uint8.encode(bc, 251);
      Uint16.encode(bc, Number(num));
    }
    else if (2**16 <= num && num < 2**32) {
      Uint8.encode(bc, 252);
      Uint32.encode(bc, Number(num));
    }
    // TODO: Bignum for the rest of these
    else if (2**32 <= num && num < 2**64) {
      Uint8.encode(bc, 253);
      Uint64.encode(bc, BigInt(num));
    }
    else if (2**64 <= num && num < 2**128) {
      Uint8.encode(bc, 254);
      Uint128.encode(bc, BigInt(num));
    } else {
      throw new Error("VarUint.encode error: " + num);
    }
  },

  decode(bc) {
    let u = BigInt(Uint8.decode(bc));
    if (u < 251) {}
    else if (u == 251n)
      u = BigInt(Uint16.decode(bc));
    else if (u == 252n)
      u = BigInt(Uint32.decode(bc));
    // TODO: Bignum for the rest of these
    else if (u == 253n)
      u = Uint64.decode(bc);
    else if (u == 254n)
      u = Uint128.decode(bc);
    else
      throw new Error("VarUint.decode error: " + u);

    if (_fitsInNumber(u)) return Number(u);
    return u;
  }
}

/** @type {BinCodeable<number | bigint>} */
export const VarInt = {
  name: 'VarInt',
  encode(bc, num) {
    if (typeof num === 'number' && (num|0) !== num)
      throw new Error("VarInt.encode: not an integer:" + num);

    let bnum = BigInt(num)
    bnum = _zigzag(bnum);
    if (bnum < 251) Uint8.encode(bc, Number(bnum));
    else if (251 <= bnum && bnum < 2**16) {
      Uint8.encode(bc, 251);
      Uint16.encode(bc, Number(bnum));
    }
    else if (2**16 <= bnum && bnum < 2**32) {
      Uint8.encode(bc, 252);
      Uint32.encode(bc, Number(bnum));
    }
    // TODO: Bignum for the rest of these
    else if (2**32 <= bnum && bnum < 2**64) {
      Uint8.encode(bc, 253);
      Uint64.encode(bc, bnum);
    }
    else if (2**64 <= bnum && bnum < 2**128) {
      Uint8.encode(bc, 254);
      Uint128.encode(bc, bnum);
    } else {
      throw new Error("VarInt.encode error: " + bnum);
    }
  },

  decode(bc) {
    let u = BigInt(Uint8.decode(bc));
    if (u < 251) {}
    else if (u == 251n)
      u = BigInt(Uint16.decode(bc));
    else if (u == 252n)
      u = BigInt(Uint32.decode(bc));
    // TODO: Bignum for the rest of these
    else if (u == 253n)
      u = Uint64.decode(bc);
    else if (u == 254n)
      u = Uint128.decode(bc);
    else
      throw new Error("VarInt.decode error: " + u);

    u = _unzigzag(u);
    if (_fitsInNumber(u)) return Number(u);
    return u;
  }
}

/** @type {BinCodeable<boolean>} */
export const Bool = {
  name: 'Bool',
  encode(bc, val) {
    return Uint8.encode(bc, val ? 1 : 0);
  },
  decode(bc) {
    const val = Uint8.decode(bc);
    if (val !== 0 && val !== 1) throw new Error("Bool decode error: " + val)
    return !!val;
  }
}

/** @type {BinCodeable<Uint8Array>} */
export const Bytes = {
  name: 'Bytes',
  encode(bc, val) {
    // console.log('Bytes.encode', val, val.length);
    // bc._debug('Bytes.encode length')
    VarUint.encode(bc, val.length);
    // console.log('After slice', bc.slice())
    let idx = bc._idxThenAddExtend(val.length);
    new Uint8Array(bc.dataview.buffer).set(val, idx);
  },
  decode(bc) {
    let length = Number(VarUint.decode(bc));
    let idx = bc._idxThenAdd(length);
    return new Uint8Array(bc.dataview.buffer, idx, length);
  }
}

/** @type {BinCodeable<string>} */
export const String = {
  name: 'String',
  encode(bc, val) {
    const bytes = new TextEncoder().encode(val);
    Bytes.encode(bc, bytes);
  },
  decode(bc) {
    const bytes = Bytes.decode(bc);
    return new TextDecoder().decode(bytes);
  }
}

/**
 * @param {number} length
 * @returns {BinCodeable<Uint8Array>}
 */
export function FixedBytes(length) {
  return {
    name: 'FixedBytes<'+length+'>',
    encode(bc, val) {
      let idx = bc._idxThenAddExtend(length);
      new Uint8Array(bc.dataview.buffer).set(val, idx);
    },
    decode(bc) {
      let idx = bc._idxThenAdd(length);
      return new Uint8Array(bc.dataview.buffer, idx, length);
    }
  }
}

export const IdentityCreateTransitionSignable = Lazy(() => 
  Enum('IdentityCreateTransitionSignable', x => 0, {
    0: Struct('IdentityCreateTransitionV0Signable', {
      $version: Constant('0'),
      // // When signing, we don't sign the signatures for keys
      // #[platform_signable(into = "Vec<IdentityPublicKeyInCreationSignable>")]
      public_keys: Vec(IdentityPublicKeyInCreationSignable),
      asset_lock_proof: RawAssetLockProof,
      user_fee_increase: UserFeeIncrease,
      // #[platform_signable(exclude_from_sig_hash)]
      // signature: BinaryData,
      // #[cfg_attr(feature = "state-transition-serde-conversion", serde(skip))]
      // #[platform_signable(exclude_from_sig_hash)]
      // identity_id: Identifier,
    })
  })
)

export const IdentityCreateTransition = Lazy(() => 
  Enum('IdentityCreateTransition', x => 0, {
    0: Struct('IdentityCreateTransitionV0', {
      $version: Constant('0'),
      // // When signing, we don't sign the signatures for keys
      // #[platform_signable(into = "Vec<IdentityPublicKeyInCreationSignable>")]
      public_keys: Vec(IdentityPublicKeyInCreation),
      asset_lock_proof: RawAssetLockProof,
      user_fee_increase: UserFeeIncrease,
      // #[platform_signable(exclude_from_sig_hash)]
      signature: BinaryData,
      // #[cfg_attr(feature = "state-transition-serde-conversion", serde(skip))]
      // #[platform_signable(exclude_from_sig_hash)]
      identity_id: Identifier,
    })
  })
)

export const KeyID = VarUint;
export const Identifier = FixedBytes(32);
export const BinaryData = Bytes;
export const UserFeeIncrease = VarUint; //Uint16;
export const TimestampMillis = VarUint; //Uint64;

export const KeyType = VarUint; // enum
export const KeyType_values = [
  'ECDSA_SECP256K1',
  'BLS12_381',
  'ECDSA_HASH160',
  'BIP13_SCRIPT_HASH',
  'EDDSA_25519_HASH160',
];

export const Purpose = VarUint; // enum
export const Purpose_values = [
  'AUTHENTICATION',
  'ENCRYPTION',
  'DECRYPTION',
  'TRANSFER',
  'SYSTEM',
  'VOTING',
];

export const SecurityLevel = VarUint; // enum
export const SecurityLevel_values = [
  'MASTER',
  'CRITICAL',
  'HIGH',
  'MEDIUM',
];

export const ContractBounds = Lazy(() => 
  Enum('ContractBounds', x => 'document_type_name' in x? 1 : 0, {
    0: Struct('ContractBounds0', {
      id: Identifier,
    }),
    1: Struct('ContractBounds1', {
      id: Identifier,
      document_type_name: String,
    })
  })
)

export const IdentityPublicKeyInCreationSignable = Enum('IdentityPublicKeyInCreationSignable', x => x.$version, {
  0: Struct('IdentityPublicKeyInCreationV0Signable', {
    $version: Constant('0'),
    id: KeyID,
    type: KeyType,
    purpose: Purpose,
    security_level: SecurityLevel,
    contract_bounds: Option(ContractBounds),
    read_only: Bool,
    data: BinaryData,
    // /// The signature is needed for ECDSA_SECP256K1 Key type and BLS12_381 Key type
    // #[platform_signable(exclude_from_sig_hash)]
    // signature: BinaryData,
  }),
})

export const IdentityPublicKeyInCreation = Enum('IdentityPublicKeyInCreation', x => x.$version, {
  0: Struct('IdentityPublicKeyInCreationV0', {
    $version: Constant('0'),
    id: KeyID,
    type: KeyType,
    purpose: Purpose,
    security_level: SecurityLevel,
    contract_bounds: Option(ContractBounds),
    read_only: Bool,
    data: BinaryData,
    // /// The signature is needed for ECDSA_SECP256K1 Key type and BLS12_381 Key type
    // #[platform_signable(exclude_from_sig_hash)]
    signature: BinaryData,
  })
})

export const Txid = FixedBytes(32);
export const CycleHash = FixedBytes(32);
export const BLSSignature = FixedBytes(96);
export const ScriptBuf = Bytes;

export const OutPoint = Struct('OutPoint', {
    txid: Txid,
    vout: Uint32,
})

export const InstantLock = Struct('InstantLock', {
    version: Uint8,
    inputs: Vec(OutPoint),
    txid: Txid,
    cyclehash: CycleHash,
    signature: BLSSignature,
})

export const Witness = Struct('Witness', {
  content: Bytes,
  witness_elements: Uint64,
  indices_start: Uint64,
})

export const TxIn = Struct('TxIn', {
    previous_output: OutPoint,
    script_sig: ScriptBuf,
    sequence: Uint32,
    witness: Witness
})

export const TxOut = Struct('TxOut', {
  value: Uint64,
  script_pubkey: ScriptBuf,
})

export const TransactionPayload = Enum('TransactionPayload', x => -1, {
  // TODO
})

export const Transaction = Struct('Transaction', {
  version: Uint16,
  lock_time: Uint32,
  input: Vec(TxIn),
  output: Vec(TxOut),
  special_transaction_payload: Option(TransactionPayload),
})

export const InstantAssetLockProof = Struct('InstantAssetLockProof', {
    instant_lock: InstantLock,
    transaction: Transaction,
    output_index: Uint32,
})

export const RawInstantLockProof = Struct('RawInstantLockProof', {
  instant_lock: BinaryData,
  transaction: BinaryData,
  output_index: VarUint, //Uint32,
})

export const ChainAssetLockProof = Struct('ChainAssetLockProof', {
  core_chain_locked_height: Uint32,
  out_point: OutPoint,
})

export const AssetLockProof = Enum('AssetLockProof', x => 0, {
  0: InstantAssetLockProof,
  1: ChainAssetLockProof,
})

export const RawAssetLockProof = Enum('RawAssetLockProof', x => 0, {
  0: RawInstantLockProof,
  1: ChainAssetLockProof,
})

export const IdentityPublicKey = Enum('IdentityPublicKey', x => 0, {
  0: Struct('IdentityPublicKeyV0', {
    $version: Constant('0'),
    id: KeyID,
    purpose: Purpose,
    security_level: SecurityLevel,
    contract_bounds: Option(ContractBounds),
    type: KeyType,
    read_only: Bool,
    data: BinaryData,
    disabled_at: Option(TimestampMillis),
  }),
})

/**
 * This is a JSON.stringify replacer that converts keys to camelCase
 * and Uint8Array to regular Array to match what to_json* does.
 * @param {string} key
 * @param {any} value
 */
function jsonCamelCaseReplacer(key, value) {
  if (value instanceof Uint8Array) {
    return Array.from(value)
  }
  if (value && typeof value === 'object') {
    /** @type {any} */
    let replacement = {};
    for (let k of Object.keys(value)) {
      let newkey = k.replace(/_[a-z]/g, val => val[1].toUpperCase())
      replacement[newkey] = value[k];
    }
    return replacement;
  }
  return value;
}
/**
 * @param {any} value
 */
export function toJsonCamelCase(value) {
  return JSON.stringify(value, jsonCamelCaseReplacer)
}



// TODO!
export const StateTransition = Enum('StateTransition', x => 3, {
  // 0: DataContractCreateTransition, //DataContractCreate(DataContractCreateTransition),
  // 1: DataContractUpdateTransition, //DataContractUpdate(DataContractUpdateTransition),
  // 2: DocumentsBatchTransition, //DocumentsBatch(DocumentsBatchTransition),
  3: IdentityCreateTransition, //IdentityCreate(IdentityCreateTransition),
  // 4: IdentityTopUpTransition, //IdentityTopUp(IdentityTopUpTransition),
  // 5: IdentityCreditWithdrawalTransition, //IdentityCreditWithdrawal(IdentityCreditWithdrawalTransition),
  // 6: IdentityUpdateTransition, //IdentityUpdate(IdentityUpdateTransition),
  // 7: IdentityCreditTransferTransition, //IdentityCreditTransfer(IdentityCreditTransferTransition),
  // 8: MasternodeVoteTransition, //MasternodeVote(MasternodeVoteTransition),
})

export const StateTransitionSignable = Enum('StateTransition', x => 3, {
  // 0: DataContractCreateTransition, //DataContractCreate(DataContractCreateTransition),
  // 1: DataContractUpdateTransition, //DataContractUpdate(DataContractUpdateTransition),
  // 2: DocumentsBatchTransition, //DocumentsBatch(DocumentsBatchTransition),
  3: IdentityCreateTransitionSignable, //IdentityCreate(IdentityCreateTransition),
  // 4: IdentityTopUpTransition, //IdentityTopUp(IdentityTopUpTransition),
  // 5: IdentityCreditWithdrawalTransition, //IdentityCreditWithdrawal(IdentityCreditWithdrawalTransition),
  // 6: IdentityUpdateTransition, //IdentityUpdate(IdentityUpdateTransition),
  // 7: IdentityCreditTransferTransition, //IdentityCreditTransfer(IdentityCreditTransferTransition),
  // 8: MasternodeVoteTransition, //MasternodeVote(MasternodeVoteTransition),
})
