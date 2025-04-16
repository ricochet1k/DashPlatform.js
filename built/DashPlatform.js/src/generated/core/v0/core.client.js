import { Core } from "./core.js";
import { stackIntercept } from "@protobuf-ts/runtime-rpc";
/**
 * @generated from protobuf service org.dash.platform.dapi.v0.Core
 */
export class CoreClient {
    _transport;
    typeName = Core.typeName;
    methods = Core.methods;
    options = Core.options;
    constructor(_transport) {
        this._transport = _transport;
    }
    /**
     * @generated from protobuf rpc: getBlockchainStatus(org.dash.platform.dapi.v0.GetBlockchainStatusRequest) returns (org.dash.platform.dapi.v0.GetBlockchainStatusResponse);
     */
    getBlockchainStatus(input, options) {
        const method = this.methods[0], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: getMasternodeStatus(org.dash.platform.dapi.v0.GetMasternodeStatusRequest) returns (org.dash.platform.dapi.v0.GetMasternodeStatusResponse);
     */
    getMasternodeStatus(input, options) {
        const method = this.methods[1], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: getBlock(org.dash.platform.dapi.v0.GetBlockRequest) returns (org.dash.platform.dapi.v0.GetBlockResponse);
     */
    getBlock(input, options) {
        const method = this.methods[2], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: getBestBlockHeight(org.dash.platform.dapi.v0.GetBestBlockHeightRequest) returns (org.dash.platform.dapi.v0.GetBestBlockHeightResponse);
     */
    getBestBlockHeight(input, options) {
        const method = this.methods[3], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: broadcastTransaction(org.dash.platform.dapi.v0.BroadcastTransactionRequest) returns (org.dash.platform.dapi.v0.BroadcastTransactionResponse);
     */
    broadcastTransaction(input, options) {
        const method = this.methods[4], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: getTransaction(org.dash.platform.dapi.v0.GetTransactionRequest) returns (org.dash.platform.dapi.v0.GetTransactionResponse);
     */
    getTransaction(input, options) {
        const method = this.methods[5], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: getEstimatedTransactionFee(org.dash.platform.dapi.v0.GetEstimatedTransactionFeeRequest) returns (org.dash.platform.dapi.v0.GetEstimatedTransactionFeeResponse);
     */
    getEstimatedTransactionFee(input, options) {
        const method = this.methods[6], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: subscribeToBlockHeadersWithChainLocks(org.dash.platform.dapi.v0.BlockHeadersWithChainLocksRequest) returns (stream org.dash.platform.dapi.v0.BlockHeadersWithChainLocksResponse);
     */
    subscribeToBlockHeadersWithChainLocks(input, options) {
        const method = this.methods[7], opt = this._transport.mergeOptions(options);
        return stackIntercept("serverStreaming", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: subscribeToTransactionsWithProofs(org.dash.platform.dapi.v0.TransactionsWithProofsRequest) returns (stream org.dash.platform.dapi.v0.TransactionsWithProofsResponse);
     */
    subscribeToTransactionsWithProofs(input, options) {
        const method = this.methods[8], opt = this._transport.mergeOptions(options);
        return stackIntercept("serverStreaming", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: subscribeToMasternodeList(org.dash.platform.dapi.v0.MasternodeListRequest) returns (stream org.dash.platform.dapi.v0.MasternodeListResponse);
     */
    subscribeToMasternodeList(input, options) {
        const method = this.methods[9], opt = this._transport.mergeOptions(options);
        return stackIntercept("serverStreaming", this._transport, method, opt, input);
    }
}
