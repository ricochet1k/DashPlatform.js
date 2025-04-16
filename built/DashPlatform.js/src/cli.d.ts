export function loadWallet(): Promise<any>;
/**
 * @param {String} fundingAddress
 * @param {Number} needSats
 */
export function promptQr(fundingAddress: string, needSats: number): void;
/**
 * Reads a hex file as text, stripping comments (anything including and after a non-hex character), removing whitespace, and joining as a single string
 * @param {String} path
 */
export function readHex(path: string): Promise<string>;
/**
 * @param {String} path
 */
export function readWif(path: string): Promise<string>;
