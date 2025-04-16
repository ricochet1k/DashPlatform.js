import DashHd from "dashhd";
import * as DashHdUtils from "./dashhd-utils.js";
import * as DashBincode from "../1.8.1/generated_bincode.js";
import DashKeys from "dashkeys";
import * as DashTx from "dashtx";
import * as DashPlatform from "./dashplatform.js";
import * as KeyUtils from "./key-utils.js";
import { COIN_TYPE, L1_VERSION_PLATFORM, rpcAuthUrl, TYPE_ASSET_LOCK, VERSION_ASSET_LOCK, VERSIONS_TESTNET, zmqAuthUrl } from "./constants.js";
import { promptQr } from "./cli.js";
import EventSourcePackage from "launchdarkly-eventsource";
const EventSourceShim = EventSourcePackage.EventSource;
/**
 * @param {{version: string}} hdOpts
 * @param {import("dashhd").HDWallet} walletKey
 * @param {number} identityIndex
 */
export async function deriveAllCreateIdentityKeys(hdOpts, walletKey, identityIndex) {
    let regFundAddressPath = `m/9'/${COIN_TYPE}'/5'/1'/${identityIndex}`;
    let regFundKey = await DashHdUtils.deriveIdentRegFundKeyPath(walletKey, regFundAddressPath);
    let topupAddressPath = `m/9'/${COIN_TYPE}'/5'/2'/0`;
    let topupKey = await DashHdUtils.deriveIdentTopupKeyPath(walletKey, topupAddressPath);
    let assetKey = await DashHd.deriveChild(regFundKey, 0, DashHd.HARDENED);
    let assetWif = await DashHd.toWif(assetKey.privateKey, hdOpts);
    let assetInfo = await wifToInfo(assetWif, "testnet");
    let authWalletPath = `m/9'/${COIN_TYPE}'/5'/0'/0'/${identityIndex}'`;
    let authWallet = await DashHdUtils.deriveIdentAuthWalletPath(walletKey, authWalletPath);
    let masterKey = await authWallet.deriveAuthKey(0);
    let otherKey = await authWallet.deriveAuthKey(1);
    return {
        // these are used to create the AssetLock
        regFundKey,
        topupKey, // TODO next change key from wallet
        assetWif,
        assetInfo,
        // these are used to create the Identity with the lock proof
        assetKey,
        masterKey,
        otherKey,
    };
}
/**
 * @param {import('dashhd').HDToAddressOpts} hdOpts
 * @param {import('dashhd').HDKey} regFundKey
 * @param {import('dashhd').HDKey} changeKey
 * @param {{publicKey: Uint8Array}} assetInfo
 */
export async function createPlatformAssetLock(hdOpts, regFundKey, changeKey, assetInfo) {
    let dashTx = DashTx.create(KeyUtils);
    if (!regFundKey.privateKey) {
        throw new Error("'regFundKey' is missing 'privateKey'");
    }
    let fundingWif = await DashHd.toWif(regFundKey.privateKey, hdOpts);
    let fundingInfo = await wifToInfo(fundingWif, "testnet");
    {
        let fundingDeltas = await DashTx.utils.rpc(rpcAuthUrl, "getaddressdeltas", {
            addresses: [fundingInfo.address],
        });
        let memDeltas = await DashTx.utils.rpc(rpcAuthUrl, "getaddressmempool", {
            addresses: [fundingInfo.address],
        });
        let totalUses = fundingDeltas.length + memDeltas.length;
        // if (totalUses >= 2) {
        //   throw new Error(`funding key has been used 2+ times`)
        // }
    }
    KeyUtils.set(fundingInfo.address, {
        address: fundingInfo.address,
        privateKey: fundingInfo.privateKey,
        publicKey: fundingInfo.publicKey,
        pubKeyHash: fundingInfo.pubKeyHashHex,
    });
    if (!changeKey.privateKey) {
        throw new Error("'topupKey' is missing 'privateKey'");
    }
    let changeWif = await DashHd.toWif(changeKey.privateKey, hdOpts);
    let changeInfo = await wifToInfo(changeWif, "testnet");
    let fundingUtxos = await TODOgetUtxos([fundingInfo.address]);
    for (let utxo of fundingUtxos) {
        utxo.squence = "00000000"; // ??
    }
    // TODO list transactions from funding address and check for
    //      - check the funding address for transactions
    let fundingTotal = DashTx.sum(fundingUtxos);
    console.log();
    console.log(`funding utxos (${fundingTotal})`);
    console.log(fundingUtxos);
    let transferSats = 100000000;
    let feeSats = 500; // enough for 1 input and 2 outputs + extrapayload
    let changeSats = fundingTotal + -transferSats + -feeSats;
    let burnOutput = { memo: "", satoshis: transferSats };
    /** @type {Array<import('dashtx').TxOutput>} */
    let outputs = [burnOutput];
    if (changeSats >= 10000) {
        outputs.push({
            satoshis: changeSats,
            pubKeyHash: changeInfo.pubKeyHashHex,
        });
    }
    else if (changeSats < 250) {
        let needSats = 250 - changeSats;
        promptQr(fundingInfo.address, needSats);
        process.exit(1);
        // throw new Error(
        //   `too few sats for test: ${fundingTotal} (needs at least 100000000 + 250 + 10000)`,
        // );
    }
    // Comes from new_p2pkh
    // TODO: hash160?!
    let pubkeyhash = await KeyUtils.pubkeyHash(assetInfo.publicKey);
    // let script = Scripts.makeP2PKH(pubkeyhash)
    // console.log('assetInfo.publicKey', toHex(assetInfo.publicKey));
    // console.log('pubkeyhash', toHex(pubkeyhash));
    // console.log('p2pkh script', toHex(script));
    // let assetLockPayload = DashBincode.AssetLockPayload({
    //   version: VERSION_ASSET_LOCK,
    //   credit_outputs: [DashBincode.TxOut({
    //     value: BigInt(transferSats),
    //     script_pubkey: DashBincode.ScriptBuf(script),
    //   })]
    // })
    // let assetLockPayloadBytes = Bincode.encode(DashBincode.AssetLockPayload, assetLockPayload);
    // let assetLockPayloadHex = DashTx.utils.bytesToHex(new Uint8Array(assetLockPayloadBytes));
    /** @type {DashTx.TxOutput} */
    let assetExtraOutput = {
        satoshis: transferSats,
        pubKeyHash: DashTx.utils.bytesToHex(pubkeyhash),
    };
    let assetLockScript = DashPlatform.packAssetLock({
        version: VERSION_ASSET_LOCK,
        creditOutputs: [assetExtraOutput],
    });
    console.log('assetLockScript      ', assetLockScript);
    // console.log('assetLockPayloadBytes', assetLockPayloadHex);
    let txDraft = {
        version: L1_VERSION_PLATFORM,
        type: TYPE_ASSET_LOCK,
        inputs: fundingUtxos,
        outputs: outputs, // burnOutput, changeOutput
        extraPayload: assetLockScript,
    };
    console.log();
    console.log(`Transaction Draft:`);
    console.log(txDraft);
    // to guarantee order
    // txDraft.inputs.sort(DashTx.sortInputs);
    // txDraft.outputs.sort(DashTx.sortOutputs);
    let vout = txDraft.outputs.indexOf(burnOutput);
    console.log(`DEBUG fundingInfo`, fundingInfo);
    console.log();
    let txProof = DashTx.createRaw(txDraft);
    // // @ts-expect-error - TxInputRaw is returned, transform to TxInputForSig?
    // txProof.inputs[0].script = DashTx.utils.bytesToHex(new Uint8Array([OP.OP_RETURN])); //`76a914${fundingInfo.pubKeyHashHex}88ac`;
    txProof.inputs[0].sequence = "00000000"; // Non-final DashTx.NON_FINAL = "00000000"
    console.log(`Transaction Proof:`);
    console.log(txProof);
    console.log();
    let txProofHex = await DashTx.serialize(txProof, null);
    console.log(`Transaction Proof Hex:`);
    console.log(txProofHex);
    console.log();
    console.log(`Ready-to-Broadcast (Signed) Transaction:`);
    console.log(`('sendrawtransaction' via https://rpc.digitalcash.dev or https://trpc.digitalcash.dev)`);
    let txSigned = await dashTx.hashAndSignAll(txDraft);
    console.log(txSigned.transaction);
    console.log();
    console.log(`Funding Outpoint Info (BE, internal)`);
    let outpoint = await getFundingOutPoint(txSigned.transaction, vout);
    console.log(outpoint);
    let txidHex = await DashTx.utils.rpc(rpcAuthUrl, "sendrawtransaction", txSigned.transaction);
    console.log("DEBUG send result (txidHex) (LE, for RPC)", txidHex);
    /** @type {DashBincode.AssetLockProof} */
    let assetProof;
    {
        // TODO: These are commented out to help debugging the ChainProof version
        let assetInstantEvent = startEventSource(zmqAuthUrl, "rawtxlocksig", createCheckDataIsProof(txSigned));
        let assetChainPoll = pollAssetLockChainProof(txidHex);
        assetProof = await Promise.race([
            assetInstantEvent.promise,
            assetChainPoll.promise,
        ]);
        console.error('assetProof', assetProof);
        assetInstantEvent.source.close();
        assetChainPoll.source.close();
    }
    console.log();
    console.log(`Funding Outpoint Hex`);
    let fundingOutPointHex = `${outpoint.txid}${outpoint.voutHex}`;
    console.log(fundingOutPointHex);
    let identityId = await createIdentityId(fundingOutPointHex);
    let identityIdHex = DashTx.utils.bytesToHex(identityId);
    return {
        txidHex,
        identityIdHex,
        assetProof,
    };
}
/**
 * @param {String} wif
 * @param {DashKeys.VERSION_PRIVATE} version - mainnet, testnet
 */
async function wifToInfo(wif, version) {
    let privateKey = await DashKeys.wifToPrivKey(wif, { version });
    let publicKey = await KeyUtils.toPublicKey(privateKey);
    let pubKeyHash = await DashKeys.pubkeyToPkh(publicKey);
    let address = await DashKeys.pkhToAddr(pubKeyHash, {
        version,
    });
    let privateKeyHex = DashKeys.utils.bytesToHex(privateKey);
    let publicKeyHex = DashKeys.utils.bytesToHex(publicKey);
    let pubKeyHashHex = DashKeys.utils.bytesToHex(pubKeyHash);
    let info = {
        wif,
        privateKey,
        privateKeyHex,
        publicKey,
        publicKeyHex,
        pubKeyHash,
        pubKeyHashHex,
        address,
    };
    // console.log(info);
    // process.exit(1);
    return info;
}
/**
 * @param {import("dashkeys").HexString} txSignedHex
 * @param {import("dashhd").Uint32} outputIndex
 */
async function getFundingOutPoint(txSignedHex, outputIndex) {
    let txBytes = DashTx.utils.hexToBytes(txSignedHex);
    let txidBytes = await DashTx.doubleSha256(txBytes);
    let txidBE = DashTx.utils.bytesToHex(txidBytes);
    let voutLE = DashTx.utils.toUint32LE(outputIndex);
    return { txid: txidBE, voutHex: voutLE, vout: outputIndex };
}
/**
 * @param {import("dashkeys").HexString} fundingOutPointHex
 */
function createIdentityId(fundingOutPointHex) {
    let fundingOutPointBytes = DashTx.utils.hexToBytes(fundingOutPointHex);
    let identityHashBytes = DashTx.doubleSha256(fundingOutPointBytes);
    // let identityId = b58.encode(identityHashBytes);
    // return identityId;
    return identityHashBytes;
}
/**
 * @param {import('dashtx').TxInfoSigned} txProofSigned
 * @returns {CheckData<{raw: string}>}
 */
function createCheckDataIsProof(txProofSigned) {
    /**
     * @param {unknown} txlocksig
     * @returns {txlocksig is {raw: string}}
     */
    function checkDataIsProof(txlocksig) {
        // @ts-expect-error
        const raw = txlocksig?.raw;
        console.log("checkDataIsProof", txlocksig, raw, 'startsWith?', txProofSigned.transaction.slice(0, 16));
        if (typeof raw !== 'string') {
            console.warn(`unknown data:`, txlocksig);
            return false;
        }
        return raw.startsWith(txProofSigned.transaction);
    }
    return checkDataIsProof;
}
/**
 * @param {String} txidHex
 */
function pollAssetLockChainProof(txidHex) {
    let isActive = true;
    /** @type {any} */
    let timeoutToken;
    /**
     * @param {any} token
     */
    function setTimeoutToken(token) {
        timeoutToken = token;
    }
    /**
     * @type {Promise<DashBincode.AssetLockProof>}
     */
    let promise = new Promise(async function (resolve, reject) {
        let timeout = 1000;
        for (;;) {
            console.log(`pollAssetLockChainProof: sleeping for ${(timeout / 1000) | 0}s...`);
            await sleep(timeout, setTimeoutToken);
            timeout = Math.min(15000, timeout * 2); // exponential backoff.
            if (!isActive) {
                reject("cancelled");
                return;
            }
            let txCore = await getTransactionJson(txidHex);
            if (!txCore)
                continue;
            const txInfo = txCore;
            let vout = txInfo.vout.findIndex(voutInfo => voutInfo.scriptPubKey?.hex === "6a00" // TODO match the burn
            );
            let assetLockChainProof = DashBincode.ChainAssetLockProof({
                core_chain_locked_height: txInfo.height,
                out_point: {
                    // The hex encoding of a transaction id is reversed for some unknown reason.
                    txid: DashBincode.Txid(DashTx.utils.hexToBytes(DashTx.utils.reverseHex(txidHex))),
                    vout: vout,
                },
            });
            console.log("assetLockChainProof", assetLockChainProof);
            const proof = DashBincode.AssetLockProof.Chain(assetLockChainProof);
            resolve(proof);
            return;
        }
    });
    let source = {
        close: function () {
            isActive = false;
            clearTimeout(timeoutToken);
        },
    };
    return {
        promise,
        source,
    };
}
/**
 * @typedef {Object} TransactionJson
 * @property {boolean?} in_active_chain - Whether specified block is in the active chain or not (only present with explicit "blockhash" argument)
 * @property {string} hex - The serialized, hex-encoded data for 'txid'
 * @property {string} txid - The transaction id (same as provided)
 * @property {string} hash - The transaction hash (differs from txid for witness transactions)
 * @property {number} size - The serialized transaction size
 * @property {number} vsize - The virtual transaction size (differs from size for witness transactions)
 * @property {number} weight - The transaction's weight (between vsize*4-3 and vsize*4)
 * @property {number} version - The version
 * @property {number} locktime - The lock time
 * @property {Array<{
 *   txid?: string,
 *   vout?: number,
 *   scriptSig?: { asm: string, hex: string },
 *   sequence: number,
 *   txinwitness?: Array<string>
 * }>} vin - The transaction inputs
 * @property {Array<{
 *   value: number,
 *   n: number,
 *   scriptPubKey: {
 *     asm: string,
 *     hex: string,
 *     reqSigs?: number,
 *     type: string,
 *     addresses?: Array<string>
 *   }
 * }>} vout - The transaction outputs
 * @property {number?} height - If the transaction has been included in a block on the local best block chain, this is the block height where the transaction was mined. Otherwise, this is -1. Not shown for mempool transactions.
 * @property {string?} blockhash - The block hash
 * @property {number?} confirmations - The confirmations
 * @property {number?} blocktime - The block time expressed in UNIX epoch time
 * @property {number?} time - Same as "blocktime"
 */
/**
 * @typedef {Object} TransactionMetadata
 * @property {number} height - The block height or index
 */
/**
 * @typedef {TransactionJson & TransactionMetadata} TransactionJsonMetadata
 */
/**
 * @param {import("dashkeys").HexString} txidHex
 * @returns {Promise<TransactionJsonMetadata | null>}
 */
async function getTransactionJson(txidHex) {
    const E_NO_TX = -5;
    let getJson = true;
    console.log('getTransactionJson: Looking for transaction...', txidHex);
    /** @type {TransactionJson | null} */
    let txInfo = await DashTx.utils
        .rpc(rpcAuthUrl, "getrawtransaction", txidHex, getJson)
        .catch(
    /** @param {Error} err */
    function (err) {
        //@ts-expect-error - it may have .code
        if (err.code === E_NO_TX) {
            return null;
        }
        throw err;
    });
    // console.log('getTransactionJson: txInfo', txInfo)
    if (!txInfo?.vout || txInfo?.blockhash == undefined || txInfo?.height == undefined) {
        return null;
    }
    // console.log('getTransactionJson: Getting block height...')
    // /**
    //  * @type {{
    //  *  height: number,
    //  * }} 
    //  */
    // let blockInfo = await DashTx.utils
    //   .rpc(rpcAuthUrl, "getblock", txInfo.blockhash, "1" /* verbosity */)
    //   .catch(
    //     /** @param {Error & {code?: number}} err */
    //     function (err) {
    //       // TODO: is this the right error code for getblock?
    //       console.error("getblock error", err.code, err);
    //       // if (err.code === E_NO_TX) {
    //       //   return null
    //       // }
    //       throw err
    //     },
    //   )
    // return {
    //   ...txInfo,
    //   height: blockInfo.height,
    // }
    // @ts-expect-error - we know height is set now
    return txInfo;
}
// TODO: This sleep with setTimeoutToken is an obnoxious leaky abstraction. And is unref() really
// the right thing to do?
/**
 * @param {import("dashhd").Uint32} ms
 * @param {Function} setTimeoutToken
 */
async function sleep(ms, setTimeoutToken) {
    return await new Promise(function (resolve) {
        let token = setTimeout(resolve, ms);
        // if (token.unref) {
        //   token.unref()
        // }
        if (setTimeoutToken) {
            setTimeoutToken(token);
        }
    });
}
/**
 * @template T
 * @callback CheckData
 * @param {unknown} message
 * @returns {message is T}
 */
/**
 * @template T
 * @param {String} url
 * @param {String} eventName
 * @param {CheckData<T>} checkData
 */
function startEventSource(url, eventName, checkData) {
    let isActive = true;
    let tickerHeartbeatMs = 5 * 1000;
    // in case of a network hiccup lasting several seconds
    let tickerHeartbeatTimeout = 3 * tickerHeartbeatMs;
    let source = new EventSourceShim(url, {
        readTimeoutMillis: tickerHeartbeatTimeout,
    });
    /** @type {Promise<DashBincode.AssetLockProof>} */
    let promise = new Promise(async function (resolve, reject) {
        let basicAuth = btoa(`api:null`);
        let resp = await fetch(zmqAuthUrl, {
            method: "PUT",
            headers: {
                Authorization: `Basic ${basicAuth}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ topics: ["debug:ticker", eventName] }),
        }).catch(reject);
        if (!resp) {
            // rejected;
            return null;
        }
        let result = await resp.text();
        console.log(`[DEBUG] status: ${result}`);
        /** @param {MessageEvent} event */
        async function onMessage(event) {
            if (!isActive) {
                console.log("EventSource: received message after close");
                source.close();
                return;
            }
            console.log(`DEBUG MessageEvent`, event);
            /** @type {T} */
            let data = JSON.parse(event.data);
            try {
                let isValidData = checkData(data);
                if (!isValidData) {
                    return;
                }
            }
            catch (err) {
                console.error(`error checking event source data`);
                console.error(err);
                return false;
            }
            const txlocksigHex = data.raw;
            {
                let len = txlocksigHex.length / 2;
                console.log();
                console.log(`Tx Lock Sig Hex (${len}):`);
                console.log(txlocksigHex);
            }
            let vout = -1;
            let instantLockTxHex = "";
            let instantLockSigHex = "";
            {
                let txlocksig = DashTx.parseUnknown(txlocksigHex);
                vout = 0;
                //vout = txlocksig.extraPayload.outputs.findIndex(function (output) {
                //  //@ts-expect-error
                //  return output.script === "6a00";
                //});
                // console.log(txlocksig.extraPayload.outputs);
                //@ts-expect-error
                instantLockSigHex = txlocksig.sigHashTypeHex;
                let isLen = instantLockSigHex.length / 2;
                let len = txlocksigHex.length / 2;
                len -= isLen;
                instantLockTxHex = txlocksigHex.slice(0, len * 2);
                console.log();
                console.log(`Tx Hex (${len})`);
                console.log(instantLockTxHex);
                console.log();
                console.log(`Tx Lock Sig Instant Lock Hex (${isLen})`);
                //@ts-expect-error
                console.log(txlocksig.sigHashTypeHex);
            }
            let assetLockInstantProof = DashBincode.RawInstantLockProof({
                instant_lock: DashBincode.BinaryData(DashTx.utils.hexToBytes(instantLockSigHex)),
                transaction: DashBincode.BinaryData(DashTx.utils.hexToBytes(instantLockTxHex)), // TODO this may need the proof, not the signed tx
                output_index: vout,
            });
            const proof = DashBincode.AssetLockProof.Instant(assetLockInstantProof);
            resolve(proof);
            source.close();
        }
        console.log(`EventSource: listening for debug:ticker`);
        source.addEventListener("debug:ticker", function (/** @type {any} */ event) {
            console.log("EventSource: ticker", event);
        });
        if (eventName) {
            console.log(`EventSource: listening for ${eventName}`);
            source.addEventListener(eventName, onMessage);
        }
        else {
            console.log(`EventSource: listening for all messages`);
            source.addEventListener("message", onMessage);
        }
        source.addEventListener("error", function (/** @type {any} */ err) {
            if (!isActive) {
                console.log("EventSource: received error after close (probably okay)");
                source.close();
                return;
            }
            console.error("error: disconnected from EventSource", err);
            // TODO reconnect?
        });
        source.addEventListener("close", function () {
            console.log("DEBUG: closed EventSource");
        });
    });
    return {
        promise: promise,
        source: {
            close: function () {
                isActive = false;
                source.close();
            },
        },
    };
}
/**
 * @typedef Delta
 * @prop {String} txid
 * @prop {Uint32} index
 * @prop {String} pubKeyHash
 * @prop {String} address
 * @prop {Uint32} satoshis
 */
/**
 * THIS IS PROBABLY WRONG
 * We'd actually need to do getaddresstxids, getrawtransaction, getaddressutxos, getaddressmempool to get all of the data to pair the coins properly
 * @param {Array<String>} addresses
 */
export const TODOgetUtxos = async function (addresses) {
    // let oldDeltas = await DashTx.utils.rpc(rpcAuthUrl, "getaddressdeltas", {
    let utxos = await DashTx.utils.rpc(rpcAuthUrl, "getaddressutxos", {
        addresses: addresses,
    });
    console.log(`DEBUG utxos`);
    console.log(utxos);
    let memDeltas = await DashTx.utils.rpc(rpcAuthUrl, "getaddressmempool", {
        addresses: addresses,
    });
    let oldTotal = DashTx.sum(utxos);
    let newTotal = DashTx.sum(memDeltas);
    let total = newTotal + oldTotal;
    if (total === 0) {
        return [];
    }
    else if (total < 0) {
        throw new Error("sanity fail: double spend detected");
    }
    for (let delta of memDeltas) {
        if (delta.satoshis < 0) {
            throw new Error("dev error: reconciling instant-send debits is not yet supported");
        }
        // TODO expose decodeUnchecked(), rename 'pubKeyHash' (data) to 'hex'
        let pubKeyHashCheck = DashKeys._dash58check.decode(delta.address, {
            //@ts-expect-error
            versions: VERSIONS_TESTNET,
        });
        let utxo = {
            address: delta.address,
            //@ts-expect-error - needs better abstraction
            pubKeyHash: pubKeyHashCheck.pubKeyHash,
            txid: delta.txid,
            outputIndex: delta.index,
            satoshis: delta.satoshis,
            //@ts-expect-error - needs better abstraction
            script: `76a914${pubKeyHashCheck.pubKeyHash}88ac`,
        };
        utxos.push(utxo);
    }
    return utxos;
};
// /**
//  * @param {String} path
//  */
// async function readWif(path) {
//   let wif = await Fs.readFile(path, "utf8");
//   wif = wif.trim();
//   return wif;
// }
/** @typedef {String} Base58 */
/** @typedef {String} Base64 */
/** @typedef {String} HexString */
/** @typedef {Number} Uint53 */
/** @typedef {Number} Uint32 */
/** @typedef {Number} Uint8 */
