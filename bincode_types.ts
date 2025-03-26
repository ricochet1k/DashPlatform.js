// import DashTx from 'dashtx'
import * as Bincode from './bincode.ts'


export type Option<T> = T | null | undefined;

/**
 * FixedBytes<N> is essentially a Uint8Array but when encoded it throws an error
 * if the length doesn't match, and is not length prefixed.
 * Equivalent to `[u8; N]` in Rust.
 */
export type FixedBytes<N extends number> = Uint8Array;

export type Hash = Uint8Array; //FixedBytes<32>;

export type SocketAddr = typeof Bincode.SocketAddr extends Bincode.BinCodeable<infer T> ? T : never;

export const EncodeOnlyRawBytes = Object.assign(
  function EncodeOnlyRawBytes(data: Uint8Array) {
    return data
  },
  {
    // name: 'EncodeOnlyRawBytes',
    isValid(x: unknown) {
      return x instanceof Uint8Array
    },
    encode(bc: Bincode.BinCode, x: Uint8Array) {
      new Uint8Array(bc.dataview.buffer).set(x, bc._idxThenAddExtend(x.byteLength))
    },
    decode(bc: Bincode.BinCode) {
      throw new Error("Unable to decode an EncodeOnlyRawBytes (how many bytes to decode?)");
    }
  },
)

export const Transaction = EncodeOnlyRawBytes;
export type Transaction = Uint8Array;
