// import * as DashTx from "dashtx"
import { toHex } from "./src/hex.js";
import { connectToNode } from "./src/rpc.js";
import BloomFilter from 'bloom-filter';
import * as DashTx from "dashtx";
const NODE_ADDRESS = "https://seed-2.testnet.networks.dash.org:1443";
const node = connectToNode(NODE_ADDRESS);
const coreStatus = await node.core.getBlockchainStatus({});
console.log('core status', coreStatus.response);
const platformStatus = await node.platform.getStatus({ version: { oneofKind: "v0", v0: {} } });
console.log('platform status', platformStatus.response.version);
// const pstatus = platformStatus.response.version
let latestHeight = coreStatus.response.chain.blocksCount;
// if (pstatus.oneofKind == 'v0') {
//     latestHeight = +pstatus.v0.chain!.latestBlockHeight
// }
const numElements = 1; // number of elements we will insert into the BloomFilter???
const falsePositiveRate = 1.0; // match everything
const bloomFilter = BloomFilter.create(numElements, falsePositiveRate);
const bloomFilterSerialized = bloomFilter.toObject();
const transactionStream = node.core.subscribeToTransactionsWithProofs({
    fromBlock: {
        oneofKind: "fromBlockHeight",
        fromBlockHeight: latestHeight,
    },
    count: 0, // means new incoming transactions
    sendTransactionHashes: true,
    bloomFilter: {
        vData: bloomFilterSerialized.vData,
        nHashFuncs: bloomFilterSerialized.nHashFuncs,
        nTweak: bloomFilterSerialized.nTweak ?? 0,
        nFlags: bloomFilterSerialized.nFlags ?? 0, // don't update
    }
});
let count = 0;
// const foundTxs: Record<string, true> = {};
for await (const resp of transactionStream.responses) {
    count += 1;
    switch (resp.responses.oneofKind) {
        case "rawMerkleBlock":
            continue;
        case "rawTransactions":
            for (const tx of resp.responses.rawTransactions.transactions) {
                const txHex = toHex(tx);
                // if (foundTxs[txHex]) continue;
                // foundTxs[txHex] = true;
                console.log('tx', toHex((await DashTx.doubleSha256(tx)).reverse()));
            }
            break;
        case "instantSendLockMessages":
            console.log(count, 'resp', resp.responses.instantSendLockMessages.messages);
            throw new Error("YAY! WE GOT ONE!"); // this never happens :(
    }
}
console.log('counted', count);
console.log('transactionStream', await transactionStream.status);
