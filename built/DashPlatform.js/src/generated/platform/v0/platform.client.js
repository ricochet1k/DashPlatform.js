import { Platform } from "./platform.js";
import { stackIntercept } from "@protobuf-ts/runtime-rpc";
/**
 * @generated from protobuf service org.dash.platform.dapi.v0.Platform
 */
export class PlatformClient {
    _transport;
    typeName = Platform.typeName;
    methods = Platform.methods;
    options = Platform.options;
    constructor(_transport) {
        this._transport = _transport;
    }
    /**
     * @generated from protobuf rpc: broadcastStateTransition(org.dash.platform.dapi.v0.BroadcastStateTransitionRequest) returns (org.dash.platform.dapi.v0.BroadcastStateTransitionResponse);
     */
    broadcastStateTransition(input, options) {
        const method = this.methods[0], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: getIdentity(org.dash.platform.dapi.v0.GetIdentityRequest) returns (org.dash.platform.dapi.v0.GetIdentityResponse);
     */
    getIdentity(input, options) {
        const method = this.methods[1], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: getIdentityKeys(org.dash.platform.dapi.v0.GetIdentityKeysRequest) returns (org.dash.platform.dapi.v0.GetIdentityKeysResponse);
     */
    getIdentityKeys(input, options) {
        const method = this.methods[2], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: getIdentitiesContractKeys(org.dash.platform.dapi.v0.GetIdentitiesContractKeysRequest) returns (org.dash.platform.dapi.v0.GetIdentitiesContractKeysResponse);
     */
    getIdentitiesContractKeys(input, options) {
        const method = this.methods[3], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: getIdentityNonce(org.dash.platform.dapi.v0.GetIdentityNonceRequest) returns (org.dash.platform.dapi.v0.GetIdentityNonceResponse);
     */
    getIdentityNonce(input, options) {
        const method = this.methods[4], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: getIdentityContractNonce(org.dash.platform.dapi.v0.GetIdentityContractNonceRequest) returns (org.dash.platform.dapi.v0.GetIdentityContractNonceResponse);
     */
    getIdentityContractNonce(input, options) {
        const method = this.methods[5], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: getIdentityBalance(org.dash.platform.dapi.v0.GetIdentityBalanceRequest) returns (org.dash.platform.dapi.v0.GetIdentityBalanceResponse);
     */
    getIdentityBalance(input, options) {
        const method = this.methods[6], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: getIdentitiesBalances(org.dash.platform.dapi.v0.GetIdentitiesBalancesRequest) returns (org.dash.platform.dapi.v0.GetIdentitiesBalancesResponse);
     */
    getIdentitiesBalances(input, options) {
        const method = this.methods[7], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: getIdentityBalanceAndRevision(org.dash.platform.dapi.v0.GetIdentityBalanceAndRevisionRequest) returns (org.dash.platform.dapi.v0.GetIdentityBalanceAndRevisionResponse);
     */
    getIdentityBalanceAndRevision(input, options) {
        const method = this.methods[8], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: getEvonodesProposedEpochBlocksByIds(org.dash.platform.dapi.v0.GetEvonodesProposedEpochBlocksByIdsRequest) returns (org.dash.platform.dapi.v0.GetEvonodesProposedEpochBlocksResponse);
     */
    getEvonodesProposedEpochBlocksByIds(input, options) {
        const method = this.methods[9], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: getEvonodesProposedEpochBlocksByRange(org.dash.platform.dapi.v0.GetEvonodesProposedEpochBlocksByRangeRequest) returns (org.dash.platform.dapi.v0.GetEvonodesProposedEpochBlocksResponse);
     */
    getEvonodesProposedEpochBlocksByRange(input, options) {
        const method = this.methods[10], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: getProofs(org.dash.platform.dapi.v0.GetProofsRequest) returns (org.dash.platform.dapi.v0.GetProofsResponse);
     */
    getProofs(input, options) {
        const method = this.methods[11], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: getDataContract(org.dash.platform.dapi.v0.GetDataContractRequest) returns (org.dash.platform.dapi.v0.GetDataContractResponse);
     */
    getDataContract(input, options) {
        const method = this.methods[12], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: getDataContractHistory(org.dash.platform.dapi.v0.GetDataContractHistoryRequest) returns (org.dash.platform.dapi.v0.GetDataContractHistoryResponse);
     */
    getDataContractHistory(input, options) {
        const method = this.methods[13], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: getDataContracts(org.dash.platform.dapi.v0.GetDataContractsRequest) returns (org.dash.platform.dapi.v0.GetDataContractsResponse);
     */
    getDataContracts(input, options) {
        const method = this.methods[14], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: getDocuments(org.dash.platform.dapi.v0.GetDocumentsRequest) returns (org.dash.platform.dapi.v0.GetDocumentsResponse);
     */
    getDocuments(input, options) {
        const method = this.methods[15], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: getIdentityByPublicKeyHash(org.dash.platform.dapi.v0.GetIdentityByPublicKeyHashRequest) returns (org.dash.platform.dapi.v0.GetIdentityByPublicKeyHashResponse);
     */
    getIdentityByPublicKeyHash(input, options) {
        const method = this.methods[16], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: waitForStateTransitionResult(org.dash.platform.dapi.v0.WaitForStateTransitionResultRequest) returns (org.dash.platform.dapi.v0.WaitForStateTransitionResultResponse);
     */
    waitForStateTransitionResult(input, options) {
        const method = this.methods[17], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: getConsensusParams(org.dash.platform.dapi.v0.GetConsensusParamsRequest) returns (org.dash.platform.dapi.v0.GetConsensusParamsResponse);
     */
    getConsensusParams(input, options) {
        const method = this.methods[18], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: getProtocolVersionUpgradeState(org.dash.platform.dapi.v0.GetProtocolVersionUpgradeStateRequest) returns (org.dash.platform.dapi.v0.GetProtocolVersionUpgradeStateResponse);
     */
    getProtocolVersionUpgradeState(input, options) {
        const method = this.methods[19], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: getProtocolVersionUpgradeVoteStatus(org.dash.platform.dapi.v0.GetProtocolVersionUpgradeVoteStatusRequest) returns (org.dash.platform.dapi.v0.GetProtocolVersionUpgradeVoteStatusResponse);
     */
    getProtocolVersionUpgradeVoteStatus(input, options) {
        const method = this.methods[20], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: getEpochsInfo(org.dash.platform.dapi.v0.GetEpochsInfoRequest) returns (org.dash.platform.dapi.v0.GetEpochsInfoResponse);
     */
    getEpochsInfo(input, options) {
        const method = this.methods[21], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * What votes are currently happening for a specific contested index
     *
     * @generated from protobuf rpc: getContestedResources(org.dash.platform.dapi.v0.GetContestedResourcesRequest) returns (org.dash.platform.dapi.v0.GetContestedResourcesResponse);
     */
    getContestedResources(input, options) {
        const method = this.methods[22], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * What's the state of a contested resource vote? (ie who is winning?)
     *
     * @generated from protobuf rpc: getContestedResourceVoteState(org.dash.platform.dapi.v0.GetContestedResourceVoteStateRequest) returns (org.dash.platform.dapi.v0.GetContestedResourceVoteStateResponse);
     */
    getContestedResourceVoteState(input, options) {
        const method = this.methods[23], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * Who voted for a contested resource to go to a specific identity?
     *
     * @generated from protobuf rpc: getContestedResourceVotersForIdentity(org.dash.platform.dapi.v0.GetContestedResourceVotersForIdentityRequest) returns (org.dash.platform.dapi.v0.GetContestedResourceVotersForIdentityResponse);
     */
    getContestedResourceVotersForIdentity(input, options) {
        const method = this.methods[24], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * How did an identity vote?
     *
     * @generated from protobuf rpc: getContestedResourceIdentityVotes(org.dash.platform.dapi.v0.GetContestedResourceIdentityVotesRequest) returns (org.dash.platform.dapi.v0.GetContestedResourceIdentityVotesResponse);
     */
    getContestedResourceIdentityVotes(input, options) {
        const method = this.methods[25], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * What vote polls will end soon?
     *
     * @generated from protobuf rpc: getVotePollsByEndDate(org.dash.platform.dapi.v0.GetVotePollsByEndDateRequest) returns (org.dash.platform.dapi.v0.GetVotePollsByEndDateResponse);
     */
    getVotePollsByEndDate(input, options) {
        const method = this.methods[26], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: getPrefundedSpecializedBalance(org.dash.platform.dapi.v0.GetPrefundedSpecializedBalanceRequest) returns (org.dash.platform.dapi.v0.GetPrefundedSpecializedBalanceResponse);
     */
    getPrefundedSpecializedBalance(input, options) {
        const method = this.methods[27], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: getTotalCreditsInPlatform(org.dash.platform.dapi.v0.GetTotalCreditsInPlatformRequest) returns (org.dash.platform.dapi.v0.GetTotalCreditsInPlatformResponse);
     */
    getTotalCreditsInPlatform(input, options) {
        const method = this.methods[28], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: getPathElements(org.dash.platform.dapi.v0.GetPathElementsRequest) returns (org.dash.platform.dapi.v0.GetPathElementsResponse);
     */
    getPathElements(input, options) {
        const method = this.methods[29], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: getStatus(org.dash.platform.dapi.v0.GetStatusRequest) returns (org.dash.platform.dapi.v0.GetStatusResponse);
     */
    getStatus(input, options) {
        const method = this.methods[30], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: getCurrentQuorumsInfo(org.dash.platform.dapi.v0.GetCurrentQuorumsInfoRequest) returns (org.dash.platform.dapi.v0.GetCurrentQuorumsInfoResponse);
     */
    getCurrentQuorumsInfo(input, options) {
        const method = this.methods[31], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: getIdentityTokenBalances(org.dash.platform.dapi.v0.GetIdentityTokenBalancesRequest) returns (org.dash.platform.dapi.v0.GetIdentityTokenBalancesResponse);
     */
    getIdentityTokenBalances(input, options) {
        const method = this.methods[32], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: getIdentitiesTokenBalances(org.dash.platform.dapi.v0.GetIdentitiesTokenBalancesRequest) returns (org.dash.platform.dapi.v0.GetIdentitiesTokenBalancesResponse);
     */
    getIdentitiesTokenBalances(input, options) {
        const method = this.methods[33], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: getIdentityTokenInfos(org.dash.platform.dapi.v0.GetIdentityTokenInfosRequest) returns (org.dash.platform.dapi.v0.GetIdentityTokenInfosResponse);
     */
    getIdentityTokenInfos(input, options) {
        const method = this.methods[34], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: getIdentitiesTokenInfos(org.dash.platform.dapi.v0.GetIdentitiesTokenInfosRequest) returns (org.dash.platform.dapi.v0.GetIdentitiesTokenInfosResponse);
     */
    getIdentitiesTokenInfos(input, options) {
        const method = this.methods[35], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: getTokenStatuses(org.dash.platform.dapi.v0.GetTokenStatusesRequest) returns (org.dash.platform.dapi.v0.GetTokenStatusesResponse);
     */
    getTokenStatuses(input, options) {
        const method = this.methods[36], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: getTokenPreProgrammedDistributions(org.dash.platform.dapi.v0.GetTokenPreProgrammedDistributionsRequest) returns (org.dash.platform.dapi.v0.GetTokenPreProgrammedDistributionsResponse);
     */
    getTokenPreProgrammedDistributions(input, options) {
        const method = this.methods[37], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: getTokenTotalSupply(org.dash.platform.dapi.v0.GetTokenTotalSupplyRequest) returns (org.dash.platform.dapi.v0.GetTokenTotalSupplyResponse);
     */
    getTokenTotalSupply(input, options) {
        const method = this.methods[38], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: getGroupInfo(org.dash.platform.dapi.v0.GetGroupInfoRequest) returns (org.dash.platform.dapi.v0.GetGroupInfoResponse);
     */
    getGroupInfo(input, options) {
        const method = this.methods[39], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: getGroupInfos(org.dash.platform.dapi.v0.GetGroupInfosRequest) returns (org.dash.platform.dapi.v0.GetGroupInfosResponse);
     */
    getGroupInfos(input, options) {
        const method = this.methods[40], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: getGroupActions(org.dash.platform.dapi.v0.GetGroupActionsRequest) returns (org.dash.platform.dapi.v0.GetGroupActionsResponse);
     */
    getGroupActions(input, options) {
        const method = this.methods[41], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
    /**
     * @generated from protobuf rpc: getGroupActionSigners(org.dash.platform.dapi.v0.GetGroupActionSignersRequest) returns (org.dash.platform.dapi.v0.GetGroupActionSignersResponse);
     */
    getGroupActionSigners(input, options) {
        const method = this.methods[42], opt = this._transport.mergeOptions(options);
        return stackIntercept("unary", this._transport, method, opt, input);
    }
}
