import { GrpcWebFetchTransport } from "@protobuf-ts/grpcweb-transport"
import { PlatformClient } from "./generated/platform/v0/platform.client.ts"
import { CoreClient } from "./generated/core/v0/core.client.ts"
import type { RpcTransport } from "@protobuf-ts/runtime-rpc"

export class NodeConnection {
    constructor(
        public readonly transport: RpcTransport,
        public readonly core: CoreClient,
        public readonly platform: PlatformClient,
    ) { }
}

export function connectToNode(address: string) {
    const transport = new GrpcWebFetchTransport({
        baseUrl: address,
        // format: 'text',
        // interceptors: [
        //     {
        //         interceptUnary(next, method, input, options) {
        //             console.log("UnaryCall", method, input, options);
        //             return next(method, input, options);
        //         }
        //         // interceptServerStreaming(next: NextServerStreamingFn, method: MethodInfo, input: object, options: RpcOptions): ServerStreamingCall;
        //         // interceptClientStreaming(next: NextClientStreamingFn, method: MethodInfo, options: RpcOptions): ClientStreamingCall;
        //         // interceptDuplex(next: NextDuplexStreamingFn, method: MethodInfo, options: RpcOptions): DuplexStreamingCall;
        //     }
        // ]
    })
    const core = new CoreClient(transport)
    const platform = new PlatformClient(transport)

    return new NodeConnection(transport, core, platform)
}

/**
 * Parameters for getaddressbalance RPC.
 */
export interface GetAddressBalanceParams {
  addresses: string[];
}

/**
 * Result for getaddressbalance RPC.
 */
export interface GetAddressBalanceResult {
  balance: number;
  balance_immature: number;
  balance_spendable: number;
  received: number;
}

/**
 * Parameters for getaddressdeltas RPC.
 */
export interface GetAddressDeltasParams {
  addresses: string[];
  start?: number;
  end?: number;
}

/**
 * Result item for getaddressdeltas RPC.
 */
export interface AddressDelta {
  satoshis: number;
  txid: string;
  index: number;
  blockindex: number;
  height: number;
  address: string;
}

/**
 * Parameters for getaddressmempool RPC.
 */
export interface GetAddressMempoolParams {
  addresses: string[];
}

/**
 * Result item for getaddressmempool RPC.
 */
export interface AddressMempoolDelta {
  address: string;
  txid: string;
  index: number;
  satoshis: number;
  timestamp: number;
  prevtxid?: string;
  prevout?: string;
}

/**
 * Parameters for getaddresstxids RPC.
 */
export interface GetAddressTxidsParams {
  addresses: string[];
  start?: number;
  end?: number;
}

/**
 * Parameters for getaddressutxos RPC.
 */
export interface GetAddressUtxosParams {
  addresses: string[];
}

/**
 * Result item for getaddressutxos RPC.
 */
export interface AddressUtxo {
  address: string;
  txid: string;
  outputIndex: number;
  script: string;
  satoshis: number;
  height: number;
}

/**
 * Parameters for analyzepsbt RPC.
 */
export interface AnalyzePsbtParams {
  psbt: string;
}

/**
 * Result for analyzepsbt RPC.
 */
export interface AnalyzePsbtResult {
  inputs: Array<{
    has_utxo: boolean;
    is_final: boolean;
    missing?: {
      pubkeys?: string[];
      signatures?: string[];
      redeemscript?: string;
    };
    next?: string;
  }>;
  estimated_vsize?: number;
  estimated_feerate?: number;
  fee?: number;
  next: string;
  error?: string;
}

/**
 * Parameters for combinepsbt RPC.
 */
export interface CombinePsbtParams {
  txs: string[];
}

/**
 * Parameters for combinerawtransaction RPC.
 */
export interface CombineRawTransactionParams {
  txs: string[];
}

/**
 * Parameters for converttopsbt RPC.
 */
export interface ConvertToPsbtParams {
  hexstring: string;
  permitsigdata?: boolean;
}

/**
 * Parameters for createpsbt RPC.
 */
export interface CreatePsbtInput {
  txid: string;
  vout: number;
  sequence?: number;
}
export type CreatePsbtOutput = { [address: string]: number | string } | { data: string };
export interface CreatePsbtParams {
  inputs: CreatePsbtInput[];
  outputs: CreatePsbtOutput[];
  locktime?: number;
}

/**
 * Parameters for createrawtransaction RPC.
 */
export interface CreateRawTransactionInput {
  txid: string;
  vout: number;
  sequence?: number;
}
export type CreateRawTransactionOutput = { [address: string]: number | string } | { data: string };
export interface CreateRawTransactionParams {
  inputs: CreateRawTransactionInput[];
  outputs: CreateRawTransactionOutput[];
  locktime?: number;
}

/**
 * Parameters for decodepsbt RPC.
 */
export interface DecodePsbtParams {
  psbt: string;
}

/**
 * Parameters for decoderawtransaction RPC.
 */
export interface DecodeRawTransactionParams {
  hexstring: string;
}

/**
 * Parameters for decodescript RPC.
 */
export interface DecodeScriptParams {
  hexstring: string;
}

/**
 * Parameters for finalizepsbt RPC.
 */
export interface FinalizePsbtParams {
  psbt: string;
  extract?: boolean;
}

/**
 * Parameters for getassetunlockstatuses RPC.
 */
export interface GetAssetUnlockStatusesParams {
  indexes: number[];
  height?: number;
}
export interface AssetUnlockStatus {
  index: number;
  status: "chainlocked" | "mined" | "mempooled" | "unknown";
}

/**
 * Parameters for getislocks RPC.
 */
export interface GetIsLocksParams {
  txids: string[];
}
export type IsLockResult = {
  txid: string;
  inputs: { txid: string; vout: number }[];
  cycleHash: string;
  signature: string;
  hex: string;
} | "None";

/**
 * Parameters for getrawtransaction RPC.
 */
export interface GetRawTransactionParams {
  txid: string;
  verbose?: boolean;
  blockhash?: string;
}

/**
 * Parameters for getrawtransactionmulti RPC.
 */
export interface GetRawTransactionMultiParams {
  txs: { [blockhash: string]: string[] };
  verbose?: boolean;
}

/**
 * Parameters for gettxchainlocks RPC.
 */
export interface GetTxChainLocksParams {
  txids: string[];
}
export interface TxChainLockStatus {
  height: number;
  chainlock: boolean;
  mempool: boolean;
}

/**
 * Parameters for joinpsbts RPC.
 */
export interface JoinPsbtParams {
  txs: string[];
}

/**
 * Parameters for sendrawtransaction RPC.
 */
export interface SendRawTransactionParams {
  hexstring: string;
  maxfeerate?: number;
  // useInstantSend?: boolean; // Deprecated
  // bypassLimits?: boolean;
}

/**
 * Parameters for signrawtransactionwithkey RPC.
 */
export interface SignRawTransactionWithKeyInput {
  txid: string;
  vout: number;
  scriptPubKey: string;
  redeemScript?: string;
  amount: number;
}
export interface SignRawTransactionWithKeyParams {
  hexstring: string;
  privkeys: string[];
  prevtxs?: SignRawTransactionWithKeyInput[];
  sighashtype?: string;
}
export interface SignRawTransactionWithKeyResult {
  hex: string;
  complete: boolean;
}

/**
 * Parameters for testmempoolaccept RPC.
 */
export interface TestMempoolAcceptParams {
  rawtxs: string[];
  maxfeerate?: number;
}
export interface TestMempoolAcceptResult {
  txid: string;
  allowed: boolean;
  "reject-reason"?: string;
  "package-error"?: string;
  vsize: number;
  fees?: { base: number };
}

/**
 * Parameters for utxoupdatepsbt RPC.
 */
export interface UtxoUpdatePsbtParams {
  psbt: string;
  descriptors?: (string | { desc: string; range?: number | [number, number] })[];
}

export class TRPC {
    /**
     * 
     * @param baseUrl A URL with in the form http://username:pass@hostname/
     */
    constructor(
        public baseUrl: string,
    ) { }

    async rawRpc(method: string, ...params: any[]) {
        let url = new URL(this.baseUrl)
        let baseUrl = `${url.protocol}//${url.host}${url.pathname}`
        let basicAuth = btoa(`${url.username}:${url.password}`)

        let payload = JSON.stringify({ method, params })
        let resp = await fetch(baseUrl, {
            method: "POST",
            headers: {
                Authorization: `Basic ${basicAuth}`,
                "Content-Type": "application/json",
            },
            body: payload,
        })

        let data = await resp.json()
        if (data.error) {
            let err = new Error(data.error.message)
            Object.assign(err, data.error)
            throw err
        }

        return data.result
    }

    /**
     * Returns the balance for address(es).
     */
    async getAddressBalance(params: GetAddressBalanceParams): Promise<GetAddressBalanceResult> {
        return this.rawRpc("getaddressbalance", params);
    }

    /**
     * Returns all changes (deltas) for address(es).
     */
    async getAddressDeltas(params: GetAddressDeltasParams): Promise<AddressDelta[]> {
        return this.rawRpc("getaddressdeltas", params);
    }

    /**
     * Returns all mempool deltas for address(es).
     */
    async getAddressMempool(params: GetAddressMempoolParams): Promise<AddressMempoolDelta[]> {
        return this.rawRpc("getaddressmempool", params);
    }

    /**
     * Returns the txids for address(es).
     */
    async getAddressTxids(params: GetAddressTxidsParams): Promise<string[]> {
        return this.rawRpc("getaddresstxids", params);
    }

    /**
     * Returns all unspent outputs for address(es).
     */
    async getAddressUtxos(params: GetAddressUtxosParams): Promise<AddressUtxo[]> {
        return this.rawRpc("getaddressutxos", params);
    }

    /**
     * Analyze and provide information about the current status of a PSBT and its inputs.
     */
    async analyzePsbt(params: AnalyzePsbtParams): Promise<AnalyzePsbtResult> {
        return this.rawRpc("analyzepsbt", params.psbt);
    }

    /**
     * Combine multiple partially-signed PSBTs into one.
     */
    async combinePsbt(params: CombinePsbtParams): Promise<string> {
        return this.rawRpc("combinepsbt", params.txs);
    }

    /**
     * Combine multiple partially signed transactions into one transaction.
     */
    async combineRawTransaction(params: CombineRawTransactionParams): Promise<string> {
        return this.rawRpc("combinerawtransaction", params.txs);
    }

    /**
     * Convert a network serialized transaction to a PSBT.
     */
    async convertToPsbt(params: ConvertToPsbtParams): Promise<string> {
        return this.rawRpc("converttopsbt", params.hexstring, params.permitsigdata);
    }

    /**
     * Create a transaction in the Partially Signed Transaction (PST) format.
     */
    async createPsbt(params: CreatePsbtParams): Promise<string> {
        return this.rawRpc("createpsbt", params.inputs, params.outputs, params.locktime);
    }

    /**
     * Create an unsigned serialized transaction.
     */
    async createRawTransaction(params: CreateRawTransactionParams): Promise<string> {
        return this.rawRpc("createrawtransaction", params.inputs, params.outputs, params.locktime);
    }

    /**
     * Decode a base64-encoded PSBT.
     */
    async decodePsbt(params: DecodePsbtParams): Promise<any> {
        return this.rawRpc("decodepsbt", params.psbt);
    }

    /**
     * Decode a serialized transaction hex string.
     */
    async decodeRawTransaction(params: DecodeRawTransactionParams): Promise<any> {
        return this.rawRpc("decoderawtransaction", params.hexstring);
    }

    /**
     * Decode a hex-encoded P2SH redeem script.
     */
    async decodeScript(params: DecodeScriptParams): Promise<any> {
        return this.rawRpc("decodescript", params.hexstring);
    }

    /**
     * Finalize the inputs of a PSBT.
     */
    async finalizePsbt(params: FinalizePsbtParams): Promise<{ psbt?: string; hex?: string; complete: boolean }> {
        return this.rawRpc("finalizepsbt", params.psbt, params.extract);
    }

    /**
     * Returns the status of the provided Asset Unlock indexes.
     */
    async getAssetUnlockStatuses(params: GetAssetUnlockStatusesParams): Promise<AssetUnlockStatus[]> {
        return this.rawRpc("getassetunlockstatuses", params.indexes, params.height);
    }

    /**
     * Returns the raw InstantSend lock data for each provided transaction ID.
     */
    async getIsLocks(params: GetIsLocksParams): Promise<IsLockResult[]> {
        return this.rawRpc("getislocks", params.txids);
    }

    /**
     * Gets a hex-encoded serialized transaction or a JSON object describing the transaction.
     */
    async getRawTransaction(params: GetRawTransactionParams): Promise<any> {
        return this.rawRpc("getrawtransaction", params.txid, params.verbose, params.blockhash);
    }

    /**
     * Gets hex-encoded serialized transactions or a JSON object describing the transactions.
     */
    async getRawTransactionMulti(params: GetRawTransactionMultiParams): Promise<any> {
        return this.rawRpc("getrawtransactionmulti", params.txs, params.verbose);
    }

    /**
     * Returns the block height each transaction was mined at and indicates whether it is in the mempool, ChainLocked, or neither.
     */
    async getTxChainLocks(params: GetTxChainLocksParams): Promise<TxChainLockStatus[]> {
        return this.rawRpc("gettxchainlocks", params.txids);
    }

    /**
     * Joins multiple distinct PSBTs into one PSBT with inputs and outputs from all of the PSBTs.
     */
    async joinPsbt(params: JoinPsbtParams): Promise<string> {
        return this.rawRpc("joinpsbts", params.txs);
    }

    /**
     * Validates a transaction and broadcasts it to the peer-to-peer network.
     */
    async sendRawTransaction(params: SendRawTransactionParams): Promise<string | null> {
        return this.rawRpc("sendrawtransaction", params.hexstring, params.maxfeerate);
    }

    /**
     * Signs inputs for a transaction in the serialized transaction format using private keys provided in the call.
     */
    async signRawTransactionWithKey(params: SignRawTransactionWithKeyParams): Promise<SignRawTransactionWithKeyResult> {
        return this.rawRpc(
            "signrawtransactionwithkey",
            params.hexstring,
            params.privkeys,
            params.prevtxs,
            params.sighashtype
        );
    }

    /**
     * Returns the results of mempool acceptance tests for raw transaction(s).
     */
    async testMempoolAccept(params: TestMempoolAcceptParams): Promise<TestMempoolAcceptResult[]> {
        return this.rawRpc("testmempoolaccept", params.rawtxs, params.maxfeerate);
    }

    /**
     * Updates a PSBT with data from output descriptors, UTXOs, or the mempool.
     */
    async utxoUpdatePsbt(params: UtxoUpdatePsbtParams): Promise<string> {
        return this.rawRpc("utxoupdatepsbt", params.psbt, params.descriptors);
    }
}