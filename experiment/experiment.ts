// import * as bip39 from 'bip39';
// import { BIP32Factory } from 'bip32';
// import * as ecc from '@bitcoinerlab/secp256k1';
import { sha256 } from "js-sha256";
// import * as bip44 from 'bip44-constants';

import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import { UnaryCall } from "./ts/grpc-promisify.js";
import { ProtoGrpcType as CoreProtoGrpcType } from "./proto/core.ts";
import { ProtoGrpcType as PlatformProtoGrpcType } from "./proto/platform.ts";

import * as Tx from "dashtx";
import * as KeyUtils from "../key-utils.js";

import * as Bincode from "../bincode.ts";
import * as db from "../1.8.1/generated_bincode.js";
import { fromHex, toHex } from "../hex.js";
import DashHd from "dashhd";
import DashPhrase from "dashphrase";
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

const hash = new Uint8Array(sha256.arrayBuffer(sha256.arrayBuffer("hello")));
console.log("hash", hash);
// const signed = ecc.sign(hash, child.privateKey)
// console.log('signed', signed.toString('hex'))

const phrase = "half suit pioneer"; //await DashPhrase.generate();
// console.log('phrase', phrase);
let seed = await DashPhrase.toSeed(phrase, "asdfasdfasdf");
// console.log('seed', seed)
let walletKey = await DashHd.fromSeed(seed);
// console.log('walletKey', walletKey)

// "Core" path
// Master / BIP44 / Dash / Account 0 / Receive / Key 0
let hdpath = `m/44'/5'/0'/0/0`;
let key = await DashHd.derivePath(walletKey, hdpath);

let wif = await DashHd.toWif(key.privateKey!);
let address = await DashHd.toAddr(key.publicKey);
console.log("wif private key", wif);
console.log("addr", address);

let identity_public_key = db.IdentityPublicKey.V0(
  db.IdentityPublicKeyV0({
    id: 0,
    purpose: db.Purpose.AUTHENTICATION(),
    security_level: db.SecurityLevel.CRITICAL(),
    contract_bounds: undefined,
    key_type: db.KeyType.ECDSA_SECP256K1(),
    read_only: true,
    data: db.BinaryData(key.publicKey),
    disabled_at: undefined,
  }),
);

console.log();
console.log();

function waitForReady(client, deadline) {
  return new Promise((resolve, reject) => {
    client.waitForReady(deadline, (err) => {
      if (err) {
        reject(err);
      } else {
        resolve();
      }
    });
  });
}

const coreProto = grpc.loadPackageDefinition(
  protoLoader.loadSync(
    "../../platform/packages/dapi-grpc/protos/core/v0/core.proto",
  ),
) as any as CoreProtoGrpcType;

const platformProto = grpc.loadPackageDefinition(
  protoLoader.loadSync(
    "../../platform/packages/dapi-grpc/protos/platform/v0/platform.proto",
  ),
) as any as PlatformProtoGrpcType;

// const client = new grpc.Client('localhost:3000', grpc.credentials.createInsecure())
const coreClient = new coreProto.org.dash.platform.dapi.v0.Core(
  "seed-2.testnet.networks.dash.org:1443",
  grpc.credentials.createSsl(),
);
await waitForReady(coreClient, Date.now() + 1000);
console.log("Core GRPC is ready");

const platformClient = new platformProto.org.dash.platform.dapi.v0.Platform(
  "seed-2.testnet.networks.dash.org:1443",
  grpc.credentials.createSsl(),
);
await waitForReady(platformClient, Date.now() + 1000);
console.log("Platform GRPC is ready");

const coreBlockchainStatus = await UnaryCall(
  coreClient,
  coreClient.getBlockchainStatus,
  {},
  { deadline: Date.now() + 1000 },
);
console.log("Core Blockchain status:", coreBlockchainStatus);

// const coreMasternodeStatus = await UnaryCall(coreClient, coreClient.getMasternodeStatus, {}, {deadline: Date.now()+1000});
// console.log("Core Masternode status:", coreMasternodeStatus)

const platformStatus = await UnaryCall(
  platformClient,
  platformClient.getStatus,
  {},
  { deadline: Date.now() + 1000 },
);
console.log("Platform status:", platformStatus.v0);

let RPC_AUTH_URL = "https://api:null@trpc.digitalcash.dev";

let utxos = await Tx.utils.rpc(RPC_AUTH_URL, "getaddressutxos", {
  addresses: [address],
});

console.log("utxos", utxos);

const asset_lock = Tx.createForSig(
  {
    version: 3, // L1_VERSION_PLATFORM
    type: 8, // ASSET_LOCK_TYPE
    inputs: utxos,
    outputs: [
      // burn output
      { satoshis: 42, pubKeyHash: pkh },
    ],
    extraPayload: toHex(
      Bincode.encode(db.AssetLockPayload, {
        version: 0,
        credit_outputs: [db.TxOut({ value: 42n, script_pubkey: pkh })],
      }),
    ),
  },
  0,
  0x01,
);

console.log("asset_lock", asset_lock);

// const asset_lock_bytes = Bincode.encode(db.Transaction, asset_lock)
// console.log('asset_lock_bytes', asset_lock_bytes)

// let response = await UnaryCall(coreClient, coreClient.broadcastTransaction, {
//     transaction: asset_lock_bytes,
// })

// console.log("Response", response);

const data_contract_create = db.StateTransition.DataContractCreate(
  db.DataContractCreateTransition.V0(
    db.DataContractCreateTransitionV0({
      data_contract: db.DataContractInSerializationFormat.V0({
        id: db.Identifier(db.IdentifierBytes32(new Uint8Array(32))),
        config: db.DataContractConfig.V0({
          can_be_deleted: false,
          readonly: false,
          keeps_history: false,
          documents_keep_history_contract_default: false,
          documents_mutable_contract_default: false,
          documents_can_be_deleted_contract_default: false,
          requires_identity_decryption_bounded_key: undefined,
          requires_identity_encryption_bounded_key: undefined,
        }),
        version: 4,
        owner_id: db.Identifier(db.IdentifierBytes32(new Uint8Array(32))),
        schema_defs: undefined,
        document_schemas: new Map(),
      }),
      identity_nonce: 43n,
      user_fee_increase: 0,
      signature_public_key_id: 0,
      signature: db.BinaryData(new Uint8Array(1 + 64)),
    }),
  ),
);

const foo: db.AssetLockPayload = db.AssetLockPayload({
  version: 1,
  credit_outputs: [],
});
const fooInstanceof = foo instanceof db.AssetLockPayload;
const x = Bincode.encode(db.AssetLockPayload, foo);

function expectError(fn: () => any) {
  let failed = false;
  try {
    fn();
  } catch (_) {
    failed = true;
  }
  if (!failed) {
    throw new Error("expected an error and got none from " + fn);
  }
}

// @ts-expect-error
const bad: db.AssetLockProof = db.AssetLockProof({} as any);

const bar = db.AssetLockProof.Instant({
  instant_lock: db.BinaryData(new Uint8Array()),
  transaction: db.BinaryData(new Uint8Array()),
  output_index: 1,
});

// @ts-expect-error
const badbar: db.AssetLockProof.Chain = bar;

const bar2: db.AssetLockProof = bar;
const barInstanceof = bar instanceof db.AssetLockProof;
const bar2Instanceof = bar instanceof db.AssetLockProof.Instant;

expectError(() => {
  // @ts-expect-error
  const bady = Bincode.encode(db.AssetLockProof, foo);
});

const y = Bincode.encode(db.AssetLockProof, bar);

console.assert(data_contract_create instanceof db.StateTransition);
console.assert(
  data_contract_create instanceof db.StateTransition.DataContractCreate,
);

const data_contract_create_bytes = Bincode.encode(
  db.StateTransition,
  data_contract_create,
);
console.log("data_contract_create_bytes", data_contract_create_bytes);
