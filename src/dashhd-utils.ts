// import DashHd from "dashhd";
// import type { HDKey } from "dashhd";

// // https://github.com/dashpay/dips/blob/master/dip-0009.md
// const PURPOSE_FEATURE_PATHS = "9'"; // DIP9
// // https://github.com/dashpay/dips/blob/master/dip-0013.md
// const FEATURE_IDENTITY = "5'"; // DIP13
// // https://github.com/satoshilabs/slips/blob/master/slip-0044.md
// const COIN_TYPE_DASH = "5'"; // SLIP44
// const COIN_TYPE_TESTNET = "1'"; // SLIP44
// const SUB_FEATURE_AUTH = "0'"; // DIP13
// const KEY_TYPE_ECDSA = "0'"; // DIP13
// const KEY_TYPE_BLS = "1'"; // DIP13
// const SUB_FEATURE_REG = "1'"; // DIP13
// const SUB_FEATURE_TOPUP = "2'"; // DIP13

export type HDPathSegment = number | `${number}` | `${number}'`;

export enum Purpose {
  FeaturePaths = "9'",
}

export enum CoinType {
  Mainnet = "5'",
  Testnet = "1'",
}

export enum Feature {
  Identity = "5'",
}

export enum SubFeature {
  Auth = "0'",
  Reg = "1'",
  Topup = "2'",
}

export enum KeyType {
  ECDSA = "0'",
  BLS = "1'",
}

    

// 0=m/1=purpose'/2=coin-type'/3=feature'/4=sub-feature'/5=identity-index
export function makeHDKeyPath(coinType: CoinType, feature: Feature, subfeature: SubFeature, identityIndex: number, subkey?: HDPathSegment) {
  let path = `m/${Purpose.FeaturePaths}/${coinType}/${feature}/${subfeature}/${identityIndex}`
  if (subkey != undefined) {
    path += `/${subkey}`
  }
  return path
}

  // `an identity wallet identity auth path must be in the form \`m/9'/<coin-type>/5'/0'/<key-type>/<identity-index>' where coin-type is 5' (DASH mainnet) or 1' (testnet), key-type is 0' (ECDSA) or 1' (BLS), and identity index must have a trailing apostrophe`,
export function makeIdentityAuthPath(coinType: CoinType, keyType: KeyType, identityIndex: number): string {
  let path = `m/${Purpose.FeaturePaths}/${coinType}/${Feature.Identity}/${SubFeature.Auth}/${keyType}/${identityIndex}'`
  // if (subkey != undefined) {
  //   path += `/${subkey}`
  // }
  return path
}

// m/9'/<coin-type>/5'/<sub-feature>
// const PREFIX_IDENT = `m/${PURPOSE_FEATURE_PATHS}/${COIN_TYPE_DASH}/${FEATURE_IDENTITY}`;
// const PREFIX_IDENT_TESTNET = `m/${PURPOSE_FEATURE_PATHS}/${COIN_TYPE_TESTNET}/${FEATURE_IDENTITY}`;
// const PREFIX_AUTH = `${PREFIX_IDENT}/${SUB_FEATURE_AUTH}/${KEY_TYPE_ECDSA}`;
// const PREFIX_AUTH_TESTNET = `${PREFIX_IDENT_TESTNET}/${SUB_FEATURE_AUTH}/${KEY_TYPE_ECDSA}`;
// const PREFIX_REG = `${PREFIX_IDENT}/${SUB_FEATURE_REG}`;
// const PREFIX_REG_TESTNET = `${PREFIX_IDENT_TESTNET}/${SUB_FEATURE_REG}`;
// const PREFIX_TOPUP = `${PREFIX_IDENT}/${SUB_FEATURE_TOPUP}`;
// const PREFIX_TOPUP_TESTNET = `${PREFIX_IDENT_TESTNET}/${SUB_FEATURE_TOPUP}`;

// /**
//  * Returns the Identity Auth Wallet, which can be used to derive Identity Auth Keys
//  */
// export async function deriveIdentAuthWalletPath(walletKey: HDKey, path: string) {
//   let hdpath = _parseIdentityWallet(path);
//   let identAuthKey = await _deriveIdentAuthPath(walletKey, hdpath);

//   return identAuthKey;
// };

// /**
//  * Returns a fully-derived Identity Auth Key
//  */
// export async function deriveIdentAuthKeyPath(walletKey: HDKey, path: string) {
//   const INDEX_AUTH_IDENTITY_KEY = 7;

//   let hdpath = _parseIdentityWallet(path);
//   let hasAuthKey =
//     hdpath.paths.length > INDEX_AUTH_IDENTITY_KEY &&
//     hdpath.paths[INDEX_AUTH_IDENTITY_KEY].endsWith("'");
//   if (!hasAuthKey) {
//     throw new Error(
//       `an auth wallet key path must be in the form \`m/9'/<coin-type>/5'/0'/<key-type>/<identity-index>/<key-index>'\` where the key index must have a trailing apostrophe`,
//     );
//   }

//   let authWalletKey = await _deriveIdentAuthPath(walletKey, hdpath);
//   let authKey = await authWalletKey.deriveAuthKey(hdpath);

//   return authKey;
// };

// /**
//  * @typedef HDPathPlatform
//  * @prop {String} path
//  * @prop {Array<String>} paths
//  * @prop {"m"|"m'"} m
//  * @prop {"9'"} purpose
//  * @prop {"5'"|"1'"} coinType
//  * @prop {"5'"} feature
//  * @prop {"0'"|"1'"|"2'"} subFeature
//  * @prop {"0'"|"1'"} [keyType]
//  * @prop {String} [identityIndex]
//  * @prop {String} [keyIndex]
//  * @prop {String} [topupIndex]
//  * @prop {String} [fundRegIndex]
//  */

// async function _deriveIdentAuthPath(walletKey: HDKey, hdpath: {paths: string[], coinType: string}) {
//   const INDEX_KEY_TYPE = 5;
//   const INDEX_AUTH_IDENTITY = 6;

//   let keyType = hdpath.paths[INDEX_KEY_TYPE];
//   let isValidKeyType = keyType === KEY_TYPE_ECDSA || keyType === KEY_TYPE_BLS;
//   let hasIdentity =
//     hdpath.paths.length > INDEX_AUTH_IDENTITY &&
//     hdpath.paths[INDEX_AUTH_IDENTITY].endsWith("'");
//   let isIdentity = isValidKeyType && hasIdentity;
//   if (!isIdentity) {
//     throw new Error(
//       `an identity wallet identity auth path must be in the form \`m/9'/<coin-type>/5'/0'/<key-type>/<identity-index>' where coin-type is 5' (DASH mainnet) or 1' (testnet), key-type is 0' (ECDSA) or 1' (BLS), and identity index must have a trailing apostrophe`,
//     );
//   }

//   // 0=m/1=purpose'/2=coin-type'/3=feature'/4=sub-feature'/5=key-type'/6=identity-index'
//   let authWalletPath = `m/9'/${hdpath.coinType}/5'/0'/${keyType}/${hdpath.paths[INDEX_AUTH_IDENTITY]}`;
//   let _authWalletKey = await DashHd.derivePath(walletKey, authWalletPath);

//   let authWalletKey = Object.assign(_authWalletKey, {
//     deriveAuthKey: async function (authKeyIndex: number) {
//       let authKey = await DashHd.deriveChild(
//         _authWalletKey,
//         authKeyIndex,
//         DashHd.HARDENED,
//       );
//       return authKey;
//     },
//   });

//   return authWalletKey;
// }

// /**
//  * Returns a fully-derived Identity Registration Funding Key
//  * @param {import('dashhd').HDWallet} walletKey
//  * @param {String} path
//  */
// export async function deriveIdentRegFundKeyPath(walletKey: HDKey, path: string) {
//   const INDEX_REG_FUND_KEY = 5;

//   let hdpath = _parseIdentityWallet(path);
//   let hasIdentity =
//     hdpath.paths.length > INDEX_REG_FUND_KEY &&
//     !hdpath.paths[INDEX_REG_FUND_KEY].endsWith("'");
//   if (!hasIdentity) {
//     throw new Error(
//       `an identity wallet identity reg path must be in the form \`m/9'/<coin-type>/5'/1'/<identity-index>\` where the identity index MUST NOT have a trailing apostrophe`,
//     );
//   }

//   // 0=m/1=purpose'/2=coin-type'/3=feature'/4=sub-feature'/5=identity-index
//   let identRegFundPath = `m/9'/${hdpath.coinType}/5'/1'/${hdpath.paths[INDEX_REG_FUND_KEY]}`;
//   let identRegFundKey = await DashHd.derivePath(walletKey, identRegFundPath);

//   return identRegFundKey;
// };

// async function deriveIdentTopupWallet(walletKey, path) {
// }

// /**
//  * Returns a fully-derived Topup Funding Key
//  * @param {import('dashhd').HDWallet} walletKey
//  * @param {String} path
//  */
// export async function deriveIdentTopupKeyPath(walletKey, path) {
//   const INDEX_TOPUP_KEY = 5;

//   let hdpath = _parseIdentityWallet(path);
//   let hasIdentity =
//     hdpath.paths.length > INDEX_TOPUP_KEY &&
//     !hdpath.paths[INDEX_TOPUP_KEY].endsWith("'");
//   if (!hasIdentity) {
//     throw new Error(
//       `an identity wallet identity reg path must be in the form \`m/9'/<coin-type>/5'/2'/<topup-index>\` where the topup index MUST NOT have a trailing apostrophe`,
//     );
//   }

//   // 0=m/1=purpose'/2=coin-type'/3=feature'/4=sub-feature'/5=topup-index
//   let identTopupPath = `m/9'/${hdpath.coinType}/5'/2'/${hdpath.paths[INDEX_TOPUP_KEY]}`;
//   let identTopupKey = await DashHd.derivePath(walletKey, identTopupPath);

//   return identTopupKey;
// };

// function _parseIdentityWallet(path: string) {
//   let paths = path.split("/");
//   let [m, purpose, coinType, feature, subFeature] = paths;
//   let hasMaster = m === "m" || m === "m'";
//   let hasPurpose = purpose === PURPOSE_FEATURE_PATHS;
//   let hasCoinType =
//     coinType === COIN_TYPE_DASH || coinType === COIN_TYPE_TESTNET;
//   let hasFeature = feature === FEATURE_IDENTITY;
//   let hasSubFeature = [
//     SUB_FEATURE_AUTH,
//     SUB_FEATURE_REG,
//     SUB_FEATURE_TOPUP,
//   ].includes(subFeature);

//   let hasValidPrefix =
//     hasMaster && hasPurpose && hasCoinType && hasFeature && hasSubFeature;
//   if (!hasValidPrefix) {
//     throw new Error(
//       `identity wallet paths must be in the form \`m/9'/<coin-type>/5'/<sub-feature>' where coin-type is 5' (DASH mainnet) or 1' (testnet) and sub-feature is 0' (auth), 1' (registration), or 2' (topup)`,
//     );
//   }

//   return { path, paths, m, purpose, coinType, feature, subFeature };
// }
