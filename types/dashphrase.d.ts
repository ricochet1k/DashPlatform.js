declare module "dashphrase" {
export default DashPhrase;

var DashPhrase: DashPhrase;
// namespace DashPhrase {
//     export { DashPhrase, EntropyEncode, PhraseVerify, PhraseDecode, PhraseDecodeOpts, PhraseGenerate, PhraseToSeed, PhraseToSeedOptions };
// }
type DashPhrase = {
    base2048: Array<string>;
    /**
     * - deprecated (use verify)
     */
    checksum: PhraseVerify;
    decode: PhraseDecode;
    encode: EntropyEncode;
    generate: PhraseGenerate;
    toSeed: PhraseToSeed;
    verify: PhraseVerify;
    CATMONIC: string;
    ZOOMONIC: string;
    ZECRET: string;
    ZEED: string;
    /**
     * - magic salt prefix
     */
    _mword: string;
    /**
     * - strings to NFKD form
     */
    _normalize: Function;
    /**
     * - the raw PBKDF2 function
     */
    _pbkdf2: Function;
    /**
     * - mnemonic word separators
     */
    _sep: RegExp;
    /**
     * - the raw SHA256 function
     */
    _sha256: Function;
};
export type EntropyEncode = (bytes: Uint8Array | Array<number>) => Promise<string>;
export type PhraseVerify = (recoveryPhrase: string) => Promise<boolean>;
export type PhraseDecode = (recoveryPhrase: string, opts?: PhraseDecodeOpts) => Promise<Uint8Array>;
export type PhraseDecodeOpts = {
    /**
     * - true by default, set to false to ignore checksum
     */
    verify: boolean;
};
export type PhraseGenerate = (bitLen?: number) => Promise<string>;
export type PhraseToSeed = (recoveryPhrase: string, salt: string, opts?: PhraseToSeedOptions) => Promise<Uint8Array>;
export type PhraseToSeedOptions = {
    verify?: boolean | null;
};
}
