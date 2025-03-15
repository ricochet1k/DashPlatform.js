// import * as bip39 from 'bip39';
// import { BIP32Factory } from 'bip32';
// import * as ecc from '@bitcoinerlab/secp256k1';
import { sha256 } from 'js-sha256';
// import * as bip44 from 'bip44-constants';

import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import { UnaryCall } from './ts/grpc-promisify.js';
/** @import { UnaryCall } from './ts/grpc-promisify.js' */
/** @import { ProtoGrpcType as CoreProtoGrpcType } from './proto/core.ts' */
/** @import { ProtoGrpcType as PlatformProtoGrpcType } from './proto/platform.ts' */

import * as Tx from 'dashtx';
import * as KeyUtils from '../key-utils.js';

import * as Bincode from '../bincode.ts';
import * as db from '../generated_bincode.js';
import { fromHex, toHex } from '../hex.js'
// import { OP } from '../opcodes.ts'
// import { makeOP_RETURN } from '../scripts.ts'

const dashTx = Tx.create(KeyUtils);
// const bip32 = BIP32Factory(ecc)

// const mnemonic = bip39.entropyToMnemonic('00000000000000000000000000000000')
// const seed = bip39.mnemonicToSeedSync('basket actual')
// const root = bip32.fromSeed(seed)

// m / purpose' / coin_type' / account' / change / address_index
// const child = root.derivePath("m/44'/1'/0'/0/0")

// console.log('base58', child.toBase58())
// console.log('wif', child.toWIF())
// console.log('identifier', child.identifier.toString('hex'))
// console.log('publicKey', child.publicKey.toString('hex'))
// console.log('privateKey', child.privateKey.toString('hex'))
// console.log('chainCode', child.chainCode.toString('hex'))
// console.log('depth', child.depth)
// console.log('index', child.index)
// // console.log(child.parentFingerprint.toString('hex'))
// console.log('neutered', child.isNeutered())


const hash = new Uint8Array(sha256.arrayBuffer(sha256.arrayBuffer('hello')))
console.log('hash', hash)
// const signed = ecc.sign(hash, child.privateKey)
// console.log('signed', signed.toString('hex'))



console.log()
console.log()

function waitForReady(client, deadline) {
    return new Promise((resolve, reject) => {
        client.waitForReady(deadline, (err) => {
            if (err) {
                reject(err)
            } else {
                resolve()
            }
        })
    })
}

/** @type {CoreProtoGrpcType} */
const coreProto = grpc.loadPackageDefinition(protoLoader.loadSync('../../platform/packages/dapi-grpc/protos/core/v0/core.proto'));

/** @type {PlatformProtoGrpcType} */
const platformProto = grpc.loadPackageDefinition(protoLoader.loadSync('../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto'));

// const client = new grpc.Client('localhost:3000', grpc.credentials.createInsecure())
const coreClient = new coreProto.org.dash.platform.dapi.v0.Core('seed-2.testnet.networks.dash.org:1443', grpc.credentials.createSsl())
await waitForReady(coreClient, Date.now() + 1000)
console.log("Core GRPC is ready")

const platformClient = new platformProto.org.dash.platform.dapi.v0.Platform('seed-2.testnet.networks.dash.org:1443', grpc.credentials.createSsl())
await waitForReady(platformClient, Date.now() + 1000)
console.log("Platform GRPC is ready")

const coreBlockchainStatus = await UnaryCall(coreClient, coreClient.getBlockchainStatus, {}, {deadline: Date.now()+1000});
console.log("Core Blockchain status:", coreBlockchainStatus)

// const coreMasternodeStatus = await UnaryCall(coreClient, coreClient.getMasternodeStatus, {}, {deadline: Date.now()+1000});
// console.log("Core Masternode status:", coreMasternodeStatus)

const platformStatus = await UnaryCall(platformClient, platformClient.getStatus, {}, {deadline: Date.now()+1000});
console.log("Platform status:", platformStatus.v0)

let rpcAuthUrl = "https://api:null@trpc.digitalcash.dev";

let utxos = await Tx.utils.rpc(rpcAuthUrl, "getaddressutxos", {
  addresses: [addr],
});

const asset_lock = Tx.createForSig({
  version: 3, // L1_VERSION_PLATFORM
  type: 8, // ASSET_LOCK_TYPE
  inputs: utxos,
  outputs: [
    // burn output
    {satoshis: 42, pubKeyHash: pkh},
  ],
  extraPayload: toHex(Bincode.encode(db.AssetLockPayload, {
    version: 0,
    credit_outputs: [
      db.TxOut({value: 42, script_pubkey: pkh})
    ],
  }))
})

console.log('asset_lock', asset_lock)

// const asset_lock_bytes = Bincode.encode(db.Transaction, asset_lock)
// console.log('asset_lock_bytes', asset_lock_bytes)

// let response = await UnaryCall(coreClient, coreClient.broadcastTransaction, {
//     transaction: asset_lock_bytes,
// })

// console.log("Response", response);




const identity_create = db.StateTransition.IdentityCreate(
    db.IdentityCreateTransition.V0(
        db.IdentityCreateTransitionV0({
            public_keys: [],
            // asset_lock_proof: db.AssetLockProof.Instant(db.InstantAssetLockProof({
            //     instant_lock: "",
            //     transaction: asset_lock,
            // })),
            asset_lock_proof: db.AssetLockProof.Chain(db.ChainAssetLockProof({
                core_chain_locked_height: 1,
                out_point: db.OutPoint({
                    txid: db.Txid(fromHex("0000000000000000000000000000000000000000000000000000000000000000")),
                    vout: 1,
                }),
            })),
            output_index: 0,
            user_fee_increase: 0,
            identity_id: db.Identifier(db.IdentifierBytes32(fromHex("0000000000000000000000000000000000000000000000000000000000000000"))),
            signature: db.BinaryData(fromHex("0000000000000000000000000000000000000000000000000000000000000000"))
        })
    )
);

const identity_create_bytes = Bincode.encode(db.StateTransition, identity_create)
console.log('identity_create_bytes', identity_create_bytes)


const data_contract_create = db.StateTransition.DataContractCreate(db.DataContractCreateTransition.V0(db.DataContractCreateTransitionV0({
    data_contract: db.DataContractInSerializationFormat.V1(db.DataContractInSerializationFormatV1({
      
    })),
    identity_nonce: 43,
    user_fee_increase: 4,
    signature_public_key_id: 42,
    signature: db.BinaryData(fromHex("0000000000000000000000000000000000000000000000000000000000000000")),
})))

const data_contract_create_bytes = Bincode.encode(db.StateTransition, data_contract_create)
console.log('data_contract_create_bytes', data_contract_create_bytes)

