/**
 * ex: 01 01 40420f00 00000000 19 76a914cdfca4ae1cf2333056659a2c 8dc656f36d228402
 * @param {Object} opts
 * @param {Uint8} [opts.version]
 * @param {Array<DashTx.TxOutput>} opts.creditOutputs
 */
export function packAssetLock({ version, creditOutputs }: {
    version?: number | undefined;
    creditOutputs: Array<DashTx.TxOutput>;
}): string;
export type Uint32 = number;
export type Uint8 = number;
export type Hex = string;
import * as DashTx from 'dashtx';
