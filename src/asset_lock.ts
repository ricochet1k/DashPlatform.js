import DashHd from "dashhd"
import type { HDWallet, HDKey, HDToAddressOpts } from "dashhd"
import * as DashHdUtils from "./dashhd-utils.ts"
import * as DashBincode from "../1.8.1/generated_bincode.js"
import DashKeys from "dashkeys"
import type { VERSION_PRIVATE, HexString, VERSION } from "dashkeys"
import * as DashTx from "dashtx"
import * as DashPlatform from "./dashplatform.js"
import * as KeyUtils from "./key-utils.js"
import { L1_VERSION_PLATFORM, RPC_AUTH_URL, TYPE_ASSET_LOCK, VERSION_ASSET_LOCK, VERSIONS_TESTNET, ZMQ_AUTH_URL } from "./constants.ts"
import { promptQr } from "./cli.ts"
import { TRPC } from "./rpc.ts"
import type { AddressDelta, AddressMempoolDelta } from "./rpc.ts"
import { createEventSource } from "eventsource-client"
import { base58 } from "./util/base58.ts"

export async function deriveAllCreateIdentityKeys(
  hdOpts: { version?: VERSION },
  walletKey: HDWallet,
  identityIndex: number
) {
  const regFundAddressPath = DashHdUtils.makeHDKeyPath(
    DashHdUtils.CoinType.Testnet,
    DashHdUtils.Feature.Identity,
    DashHdUtils.SubFeature.Reg,
    identityIndex
  )
  const regFundKey = await DashHd.derivePath(walletKey, regFundAddressPath)

  // TODO: Should we be using Topup for the change key?
  const changeAddressPath = //`m/9'/${COIN_TYPE}'/5'/2'/0`
    DashHdUtils.makeHDKeyPath(
      DashHdUtils.CoinType.Testnet,
      DashHdUtils.Feature.Identity,
      DashHdUtils.SubFeature.Topup,
      identityIndex
    )
  const changeKey = await DashHd.derivePath(
    walletKey,
    changeAddressPath,
  )

  const assetKey = await DashHd.deriveChild(regFundKey, 0, DashHd.HARDENED)
  // const assetWif = await DashHd.toWif(assetKey.privateKey!, hdOpts)
  // const assetInfo = await wifToInfo(assetWif, "testnet")

  const authWallet = await DashHd.derivePath(
    walletKey,
    DashHdUtils.makeIdentityAuthPath(
      DashHdUtils.CoinType.Testnet,
      DashHdUtils.KeyType.ECDSA,
      identityIndex,
    ),
  )
  const masterKey = await DashHd.deriveChild(authWallet, 0, true)
  const otherKey = await DashHd.deriveChild(authWallet, 1, true)

  return {
    regFundKey,
    changeKey,
    assetKey,

    masterKey,
    otherKey,
  }
}

/**
 * @param regFundKey Source funds for the asset lock are here
 * @param changeKey Any leftover change from the lock transaction will go here
 * @param assetInfo This is the asset key that will be "locked"
 */
export async function createPlatformAssetLock(
  hdOpts: HDToAddressOpts,
  regFundKey: HDKey,
  changeKey: HDKey,
  assetKey: HDKey,
  //   node: NodeConnection,
  rpc: TRPC,
): Promise<{
  txidHex: string,
  identityId: Uint8Array,
  assetLockProof: any // DashBincode.AssetLockProof
}> {
  const dashTx = DashTx.create(KeyUtils)

  if (!regFundKey.privateKey) {
    throw new Error("'regFundKey' is missing 'privateKey'")
  }

  const transferSats = 100000000
  const feeSats = 500 // enough for 1 input and 2 outputs + extrapayload
  const totalSats = transferSats + feeSats

  const fundingWif = await DashHd.toWif(regFundKey.privateKey, hdOpts)
  const fundingInfo = await wifToInfo(fundingWif, "testnet")
  const fundingAddr = await DashHd.toAddr(regFundKey.publicKey, { version: 'testnet' })
  {
    const [fundingDeltas, memDeltas] = await Promise.all([
      rpc.getAddressDeltas({ addresses: [fundingAddr] }),
      rpc.getAddressMempool({ addresses: [fundingAddr] }),
    ]);
    console.log('deltas', fundingDeltas, memDeltas);
    // let totalUses = fundingDeltas.length + memDeltas.length
    // if (totalUses >= 2) {
    //   // TODO: Check for asset lock transactions that don't have an identity from them yet
    //   // getTransactionJson()

    //   throw new Error(`funding key has been used 2+ times`)
    // }

    for (const delta of (fundingDeltas as (AddressMempoolDelta | AddressDelta)[]).concat(memDeltas)) {
      if (delta.satoshis <= -transferSats) {
        // this might be an asset lock transaction
        const tx = await rpc.getRawTransaction({ txid: delta.txid, verbose: true })
        console.log('tx', tx)
        console.log('tx.vout', tx.vout)
        // const guessTxId = await DashTx.doubleSha256(fromHex(tx.hex));
        // console.log('guessTxId?', toHex(guessTxId))
        if (tx.assetLockTx) {
          console.log('assetLockTx', tx.assetLockTx)

          const assetLockOutIndex = (tx.vout as any[]).findIndex(o => o?.scriptPubKey?.hex === '6a00')
          if (assetLockOutIndex !== -1) {
            
            const identityId = await createIdentityId(DashTx.utils.reverseHex(delta.txid), assetLockOutIndex);
            console.log('identityId', base58.encode(identityId));
          } else {
            console.log('assetLockOutIndex', assetLockOutIndex);
          }
        }
      }
    }
  }

  KeyUtils.set(fundingAddr, {
    address: fundingAddr,
    privateKey: regFundKey.privateKey,
    publicKey: regFundKey.publicKey,
    pubKeyHash: fundingInfo.pubKeyHashHex,
  })

  if (!changeKey.privateKey) {
    throw new Error("'topupKey' is missing 'privateKey'")
  }
  let changeWif = await DashHd.toWif(changeKey.privateKey, hdOpts)
  let changeInfo = await wifToInfo(changeWif, "testnet")

  let fundingUtxos = await TODOgetUtxos(rpc, [fundingAddr])
  for (let utxo of fundingUtxos) {
    utxo.squence = "00000000" // ??
  }

  // TODO list transactions from funding address and check for
  //      - check the funding address for transactions
  const fundingTotal = DashTx.sum(fundingUtxos)
  console.log()
  console.log(`funding utxos (${fundingTotal})`)
  console.log(fundingUtxos)

  const changeSats = fundingTotal - totalSats

  const burnOutput = { memo: "", satoshis: transferSats }

  const outputs: Array<DashTx.TxOutput> = [burnOutput]
  if (changeSats >= 10000) {
    // If there's enough change left over to bother with...
    outputs.push({
      satoshis: changeSats,
      pubKeyHash: changeInfo.pubKeyHashHex,
    })
  } else if (changeSats < 250) {
    // If there's not enough change leftover...

    let needSats = 250 - changeSats
    promptQr(fundingInfo.address, needSats)
    throw new Error("need funds");
  }

  // Comes from new_p2pkh
  // TODO: hash160?!
  let pubkeyhash = await KeyUtils.pubkeyHash(assetKey.publicKey)
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
  let assetExtraOutput: DashTx.TxOutput = {
    satoshis: transferSats,
    pubKeyHash: DashTx.utils.bytesToHex(pubkeyhash),
  }
  let assetLockScript = DashPlatform.packAssetLock({
    version: VERSION_ASSET_LOCK,
    creditOutputs: [assetExtraOutput],
  })

  let txDraft = {
    version: L1_VERSION_PLATFORM,
    type: TYPE_ASSET_LOCK,
    inputs: fundingUtxos,
    outputs: outputs, // burnOutput, changeOutput
    extraPayload: assetLockScript,
  }
  console.log()
  console.log(`Transaction Draft:`)
  console.log(txDraft)

  // to guarantee order
  // txDraft.inputs.sort(DashTx.sortInputs);
  // txDraft.outputs.sort(DashTx.sortOutputs);
  const vout = txDraft.outputs.indexOf(burnOutput)

  console.log(`DEBUG fundingInfo`, fundingInfo)

  console.log()
  const txProof = DashTx.createRaw(txDraft)
  // // @ts-expect-error - TxInputRaw is returned, transform to TxInputForSig?
  // txProof.inputs[0].script = DashTx.utils.bytesToHex(new Uint8Array([OP.OP_RETURN])); //`76a914${fundingInfo.pubKeyHashHex}88ac`;
  txProof.inputs[0].sequence = "00000000" // Non-final DashTx.NON_FINAL = "00000000"
  console.log(`Transaction Proof:`)
  console.log(txProof)

  // console.log()
  // const txProofHex = DashTx.serialize(txProof, null)

  console.log()
  const txSigned = await dashTx.hashAndSignAll(txDraft)
  console.log(txSigned.transaction)

  console.log()
  console.log(`Funding Outpoint Info (BE, internal)`)
  const outpoint = await getFundingOutPoint(txSigned.transaction, vout)
  console.log(outpoint)

  const expectingTxid = DashTx.utils.reverseHex(outpoint.txid);
  console.log("DEBUG expecting txid", expectingTxid)

  const txidHex = await rpc.sendRawTransaction({
    hexstring: txSigned.transaction,
  })
  console.log("DEBUG send result (txidHex) (LE, for RPC)", txidHex)
  if (!txidHex) {
    throw new Error("sendRawTransaction did not return a transaction id");
  }

  let assetLockProof: DashBincode.AssetLockProof
  {
    // TODO: These are commented out to help debugging the ChainProof version
    const assetInstantEvent = startEventSource(
      ZMQ_AUTH_URL,
      "rawtxlocksig",
      createCheckDataIsProof(txSigned),
    )
    const assetChainPoll = pollAssetLockChainProof(txidHex)
    assetLockProof = await Promise.race([
      assetInstantEvent.promise,
      assetChainPoll.promise,
    ])
    console.error('assetLockProof', assetLockProof)
    assetInstantEvent.source.close()
    assetChainPoll.source.close()
  }
  if (!assetLockProof) {
    console.error('failed to acquire asset lock proof')
    process.exit(3);
  }

  let identityId = await createIdentityId(outpoint.txid, outpoint.vout)

  return {
    txidHex,
    identityId,
    assetLockProof,
  }
}

/**
 * @param wif
 * @param version
 */
async function wifToInfo(
  wif: string,
  version: VERSION_PRIVATE
): Promise<{
  wif: string,
  privateKey: Uint8Array,
  privateKeyHex: string,
  publicKey: Uint8Array,
  publicKeyHex: string,
  pubKeyHash: Uint8Array,
  pubKeyHashHex: string,
  address: string
}> {
  let privateKey = await DashKeys.wifToPrivKey(wif, { version })
  let publicKey = await KeyUtils.toPublicKey(privateKey)
  let pubKeyHash = await DashKeys.pubkeyToPkh(publicKey)
  let address = await DashKeys.pkhToAddr(pubKeyHash, {
    version,
  })

  let privateKeyHex = DashKeys.utils.bytesToHex(privateKey)
  let publicKeyHex = DashKeys.utils.bytesToHex(publicKey)
  let pubKeyHashHex = DashKeys.utils.bytesToHex(pubKeyHash)

  let info = {
    wif,
    privateKey,
    privateKeyHex,
    publicKey,
    publicKeyHex,
    pubKeyHash,
    pubKeyHashHex,
    address,
  }
  // console.log(info);
  // process.exit(1);
  return info
}

/**
 * @param txSignedHex
 * @param outputIndex
 */
async function getFundingOutPoint(
  txSignedHex: HexString,
  outputIndex: number
): Promise<{ txid: string, vout: number }> {
  let txBytes = DashTx.utils.hexToBytes(txSignedHex)
  let txidBytes = await DashTx.doubleSha256(txBytes)
  let txid = DashTx.utils.bytesToHex(txidBytes)

  return { txid, vout: outputIndex }
}

/**
 * @param fundingOutPointHex
 */
function createIdentityId(
  txidHex: HexString,
  vout: number,
): Promise<Uint8Array> {
  const fundingOutPointHex = `${txidHex}${DashTx.utils.toUint32LE(vout)}`
  console.log(`Funding Outpoint Hex`, fundingOutPointHex)

  let fundingOutPointBytes = DashTx.utils.hexToBytes(fundingOutPointHex)
  let identityHashBytes = DashTx.doubleSha256(fundingOutPointBytes)
  // let identityId = b58.encode(identityHashBytes);
  // return identityId;
  return identityHashBytes
}

function createCheckDataIsProof(
  txProofSigned: { transaction: string }
): CheckData<{ raw: string }> {
  /**
   * @param {unknown} txlocksig
   * @returns {txlocksig is {raw: string}}
   */
  function checkDataIsProof(txlocksig: unknown): txlocksig is { raw: string } {
    // @ts-expect-error
    const raw = txlocksig?.raw
    console.log("checkDataIsProof", txlocksig, raw, 'startsWith?', txProofSigned.transaction.slice(0, 16))
    if (typeof raw !== 'string') {
      console.warn(`unknown data:`, txlocksig)
      return false
    }

    return raw.startsWith(txProofSigned.transaction)
  }

  return checkDataIsProof
}

function pollAssetLockChainProof(
  txidHex: HexString
): { promise: Promise<any>, source: { close: () => void } } {
  let isActive = true
  /** @type {any} */
  let timeoutToken: any

  function setTimeoutToken(token: any) {
    timeoutToken = token
  }

  let promise: Promise<DashBincode.AssetLockProof> = new Promise(async function (resolve, reject) {
    let timeout = 1000
    for (; ;) {
      console.log(`pollAssetLockChainProof: sleeping for ${(timeout / 1000) | 0}s...`)
      await sleep(timeout, setTimeoutToken)
      timeout = Math.min(15000, timeout * 2) // exponential backoff.

      if (!isActive) {
        reject("cancelled")
        return
      }
      let txCore = await getTransactionJson(txidHex)
      if (!txCore) continue

      const txInfo = txCore
      let vout = txInfo.vout.findIndex(voutInfo =>
        voutInfo.scriptPubKey?.hex === "6a00" // TODO match the burn
      )

      let assetLockChainProof = DashBincode.ChainAssetLockProof({
        core_chain_locked_height: txInfo.height,
        out_point: {
          // The hex encoding of a transaction id is reversed for some unknown reason.
          txid: DashBincode.Txid(DashTx.utils.hexToBytes(DashTx.utils.reverseHex(txidHex))),
          vout: vout,
        },
      })

      console.log("assetLockChainProof", assetLockChainProof)

      // found the proof, but sometimes it rejects the proof because it doesn't have concensus to that height
      // yet, so wait a bit (TODO: make this a retry loop later, not here)
      await sleep(1000, t => {});

      const proof = DashBincode.AssetLockProof.Chain(assetLockChainProof)
      resolve(proof)
      return
    }
  })

  let source = {
    close: function () {
      isActive = false
      clearTimeout(timeoutToken)
    },
  }

  return {
    promise,
    source,
  }
}

type TransactionJson = {
  /** Whether specified block is in the active chain or not (only present with explicit "blockhash" argument) */
  in_active_chain?: boolean,
  /** The serialized, hex-encoded data for 'txid' */
  hex: string,
  /** The transaction id (same as provided) */
  txid: string,
  /** The transaction hash (differs from txid for witness transactions) */
  hash: string,
  /** The serialized transaction size */
  size: number,
  /** The virtual transaction size (differs from size for witness transactions) */
  vsize: number,
  /** The transaction's weight (between vsize*4-3 and vsize*4) */
  weight: number,
  /** The version */
  version: number,
  /** The lock time */
  locktime: number,
  /** The transaction inputs */
  vin: Array<{
    txid?: string,
    vout?: number,
    scriptSig?: { asm: string, hex: string },
    sequence: number,
    txinwitness?: Array<string>
  }>,
  /** The transaction outputs */
  vout: Array<{
    /** Output value */
    value: number,
    /** Output index */
    n: number,
    /** Output scriptPubKey */
    scriptPubKey: {
      asm: string,
      hex: string,
      reqSigs?: number,
      type: string,
      addresses?: Array<string>
    }
  }>,
  /** If the transaction has been included in a block on the local best block chain, this is the block height where the transaction was mined. Otherwise, this is -1. Not shown for mempool transactions. */
  height?: number,
  /** The block hash */
  blockhash?: string,
  /** The confirmations */
  confirmations?: number,
  /** The block time expressed in UNIX epoch time */
  blocktime?: number,
  /** Same as "blocktime" */
  time?: number
}

type TransactionMetadata = {
  height: number
}

type TransactionJsonMetadata = TransactionJson & TransactionMetadata

async function getTransactionJson(
  txidHex: HexString
): Promise<TransactionJsonMetadata | null> {
  const E_NO_TX = -5
  let getJson = true

  console.log('getTransactionJson: Looking for transaction...', txidHex)
  /** @type {TransactionJson | null} */
  let txInfo: TransactionJson | null = await DashTx.utils
    .rpc(RPC_AUTH_URL, "getrawtransaction", txidHex, getJson)
    .catch(
      /** @param {Error} err */
      function (err: Error) {
        //@ts-expect-error - it may have .code
        if (err.code === E_NO_TX) {
          return null
        }
        throw err
      },
    )
  // console.log('getTransactionJson: txInfo', txInfo)
  if (!txInfo?.vout || txInfo?.blockhash == undefined || txInfo?.height == undefined) {
    return null
  }

  // console.log('getTransactionJson: Getting block height...')
  // /**
  //  * @type {{
  //  *  height: number,
  //  * }} 
  //  */
  // let blockInfo = await DashTx.utils
  //   .rpc(RPC_AUTH_URL, "getblock", txInfo.blockhash, "1" /* verbosity */)
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
  return txInfo
}

// TODO: This sleep with setTimeoutToken is an obnoxious leaky abstraction. And is unref() really
// the right thing to do?
async function sleep(
  ms: number,
  setTimeoutToken: (token: NodeJS.Timeout) => void
): Promise<void> {
  return await new Promise(function (resolve) {
    let token = setTimeout(resolve, ms)
    // if (token.unref) {
    //   token.unref()
    // }
    if (setTimeoutToken) {
      setTimeoutToken(token)
    }
  })
}

type CheckData<T> = (message: unknown) => message is T

function startEventSource<T extends { raw: string }>(
  url: string,
  eventName: string,
  checkData: CheckData<T>
): { promise: Promise<DashBincode.AssetLockProof>, source: { close: () => void } } {
  const tickerHeartbeatMs = 5 * 1000
  // in case of a network hiccup lasting several seconds
  const tickerHeartbeatTimeout = 3 * tickerHeartbeatMs

  const source = createEventSource(url)

  let tickerTimeoutId: NodeJS.Timeout | undefined = undefined
  function updateTickerTimeout() {
    // clearTimeout(tickerTimeoutId)
    // tickerTimeoutId = setTimeout(() => source.close(), tickerHeartbeatTimeout)
  }
  updateTickerTimeout()

  const promise: Promise<DashBincode.AssetLockProof> = (async () => {
    // sometimes it complains that we're not a current client yet?
    await sleep(100, t => {});

    const resp = await fetch(ZMQ_AUTH_URL, {
      method: "PUT",
      headers: {
        Authorization: `Basic ${btoa(`api:null`)}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ topics: ["debug:ticker", eventName] }),
    })

    const result = await resp.text()
    console.log(`[DEBUG] status: ${result}`)

    for await (const {data: rawData, event, id} of source) {
      updateTickerTimeout()

      console.log(`DEBUG MessageEvent`, event)
      const data = JSON.parse(rawData)

      if (!checkData(data)) {
        continue
      }

      const txlocksigHex = data.raw
      {
        const len = txlocksigHex.length / 2
        console.log()
        console.log(`Tx Lock Sig Hex (${len}):`)
        console.log(txlocksigHex)
      }

      let vout = -1
      let instantLockTxHex = ""
      let instantLockSigHex = ""
      {
        let txlocksig = DashTx.parseUnknown(txlocksigHex)
        vout = 0
        //vout = txlocksig.extraPayload.outputs.findIndex(function (output) {
        //  //@ts-expect-error
        //  return output.script === "6a00";
        //});
        // console.log(txlocksig.extraPayload.outputs);
        instantLockSigHex = txlocksig.sigHashTypeHex
        let isLen = instantLockSigHex.length / 2
        let len = txlocksigHex.length / 2
        len -= isLen
        instantLockTxHex = txlocksigHex.slice(0, len * 2)
        console.log()
        console.log(`Tx Hex (${len})`)
        console.log(instantLockTxHex)
        console.log()
        console.log(`Tx Lock Sig Instant Lock Hex (${isLen})`)
        console.log(txlocksig.sigHashTypeHex)
      }

      const assetLockInstantProof = DashBincode.RawInstantLockProof({
        instant_lock: DashBincode.BinaryData(DashTx.utils.hexToBytes(instantLockSigHex)),
        transaction: DashBincode.BinaryData(DashTx.utils.hexToBytes(instantLockTxHex)), // TODO this may need the proof, not the signed tx
        output_index: vout,
      })
      const proof = DashBincode.AssetLockProof.Instant(assetLockInstantProof)

      source.close()
      return proof
    }

    // throw new Error("event source closed before found")

    console.log("event source closed before found");

    // if (eventName) {
    //   console.log(`EventSource: listening for ${eventName}`)
    //   source.addEventListener(eventName, onMessage)
    // } else {
    //   console.log(`EventSource: listening for all messages`)
    //   source.addEventListener("message", onMessage)
    // }
  })();

  return {
    promise: promise,
    source: {
      close: () => source.close(),
    },
  }
}

/**
 * THIS IS PROBABLY WRONG
 * We'd actually need to do getaddresstxids, getrawtransaction, getaddressutxos, getaddressmempool to get all of the data to pair the coins properly
 */
export const TODOgetUtxos = async function (
  rpc: TRPC,
  addresses: string[]
): Promise<any[]> {
  const [utxos, memDeltas] = await Promise.all([
    rpc.getAddressUtxos({ addresses }),
    rpc.getAddressMempool({ addresses }),
  ])

  const oldTotal = DashTx.sum(utxos)
  const newTotal = DashTx.sum(memDeltas)
  const total = newTotal + oldTotal
  if (total === 0) {
    return []
  } else if (total < 0) {
    throw new Error("sanity fail: double spend detected")
  }

  for (const delta of memDeltas) {
    if (delta.satoshis < 0) {
      throw new Error(
        "dev error: reconciling instant-send debits is not yet supported",
      )
    }

    // TODO expose decodeUnchecked(), rename 'pubKeyHash' (data) to 'hex'
    const pubKeyHashCheck = DashKeys._dash58check.decode(delta.address, {
      versions: VERSIONS_TESTNET,
    })
    const utxo = {
      address: delta.address,
      // TODO: needs better abstraction
      pubKeyHash: (pubKeyHashCheck as PubKeyHashParts).pubKeyHash!,
      txid: delta.txid,
      outputIndex: delta.index,
      satoshis: delta.satoshis,
      // TODO: needs better abstraction
      script: `76a914${(pubKeyHashCheck as PubKeyHashParts).pubKeyHash}88ac`,
      height: -1,
    }
    utxos.push(utxo)
  }

  return utxos
}

// /**
//  * @param {String} path
//  */
// async function readWif(path) {
//   let wif = await Fs.readFile(path, "utf8");
//   wif = wif.trim();

//   return wif;
// }
