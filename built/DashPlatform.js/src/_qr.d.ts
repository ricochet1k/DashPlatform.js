/**
 * @param {String} data
 * @param {QrOpts} opts
 */
export function quadAscii(data: string, opts: QrOpts): string;
/**
 * @param {String} data
 * @param {QrOpts} opts
 */
export function ascii(data: string, opts: QrOpts): string;
export type QrOpts = {
    background?: string | undefined;
    color?: string | undefined;
    ecl?: string | undefined;
    height?: number | undefined;
    indent?: number | undefined;
    padding?: number | undefined;
    size?: "full" | "mini" | "micro" | undefined;
    width?: number | undefined;
};
export type BlockMap = any;
