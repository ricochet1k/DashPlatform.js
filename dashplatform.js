//@ts-ignore
var DashPlatform = ("object" === typeof module && exports) || {};
(function (window, DashPlatform) {
  "use strict";

  let DashTx = window.DashTx || require("dashtx");

  let Tx = {};

  /**
   * ex: 01 01 40420f00 00000000 19 76a914cdfca4ae1cf2333056659a2c 8dc656f36d228402
   * @param {Object} opts
   * @param {Uint8} [opts.version]
   * @param {Array<import('dashtx').TxOutput>} opts.creditOutputs
   */
  Tx.packAssetLock = function ({ version = 1, creditOutputs }) {
    let versionHex = DashTx.utils.toUint32LE(version);
    versionHex = versionHex.slice(0, 2);

    let lenHex = DashTx.utils.toUint32LE(creditOutputs.length);
    lenHex = lenHex.slice(0, 2);

    let hexes = [`${versionHex}${lenHex}`];
    for (let creditOutput of creditOutputs) {
      //@ts-ignore - TODO check type of TxOutput
      let script = creditOutput.script;
      let satsHexLE = DashTx.utils.toUint64LE(creditOutput.satoshis);
      if (!script) {
        script = `${satsHexLE}1976a914${creditOutput.pubKeyHash}88ac`;
      }
      let assetLock = `${script}`;
      hexes.push(assetLock);
    }

    return hexes.join("");
  };

  //@ts-ignore
  DashPlatform.Tx = Tx;

  // @ts-ignore
  window.DashPlatform = DashPlatform;
})(("object" === typeof window && window) || {}, DashPlatform);
if ("object" === typeof module) {
  module.exports = DashPlatform;
}

/** @typedef {Number} Uint32 */
/** @typedef {Number} Uint8 */
/** @typedef {String} Hex */
