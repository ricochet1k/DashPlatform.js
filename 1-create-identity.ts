
import * as Bincode from "./src/bincode.ts";
import * as DashBincode from "./2.0.0/generated_bincode.js"
import DashKeys from "dashkeys";

import * as KeyUtils from "./src/key-utils.js";
import { loadWallet } from "./src/cli.ts";
import { deriveAllCreateIdentityKeys } from "./src/asset_lock.ts";
import { createPlatformAssetLock } from "./src/asset_lock.ts";
import { connectToNode, TRPC } from "./src/rpc.ts"
import { NODE_ADDRESS, RPC_AUTH_URL } from "./src/constants.ts"
import { toHex } from "./src/hex.js"
import { base58 } from "./src/util/base58.ts"
import { findExistingIdentity } from "./src/identity.ts"


export async function step1CreateIdentity(walletPhrase: string, walletSalt: string, identityIndex: number) {
const rpc = new TRPC(RPC_AUTH_URL);
const nodeRpc = connectToNode(NODE_ADDRESS)

const walletKey = await loadWallet(walletPhrase, walletSalt);

const hdOpts = { version: "testnet" as const }; // TODO

const {
  regFundKey,
  changeKey,
  assetKey,
  masterKey,
  otherKey,
} = await deriveAllCreateIdentityKeys(
  hdOpts,
  walletKey,
  identityIndex,
);

// console.log("Asset WIF", assetWif, "(would be ephemeral, non-hd)");

// console.log(
//   "regFundKey",
//   await DashHd.toAddr(regFundKey.publicKey, { version: "testnet" }),
// );
// console.log(
//   "changeKey",
//   await DashHd.toAddr(changeKey.publicKey, { version: "testnet" }),
// );
// console.log(
//   "assetKey",
//   await DashHd.toAddr(assetKey.publicKey, { version: "testnet" }),
// );
// console.log(
//   "masterKey",
//   await DashHd.toAddr(masterKey.publicKey, { version: "testnet" }),
// );
// console.log(
//   "masterKey priv wif",
//   await DashHd.toWif(masterKey.privateKey!, { version: "testnet" }),
// );
// console.log(
//   "otherKey",
//   await DashHd.toAddr(otherKey.publicKey, { version: "testnet" }),
// );
// console.log();

const pkh = await DashKeys.pubkeyToPkh(masterKey.publicKey)
console.log('masterKey pkh', toHex(pkh))
const existingIdentity = await findExistingIdentity(nodeRpc, pkh)
if (existingIdentity) {
  const existingIdentityV0: DashBincode.IdentityV0 = Bincode.match(existingIdentity, {
    V0: i => i[0]
  });
  const existingIdentityId = existingIdentityV0.id[0][0];
  console.log('Identity Already Created!', base58.encode(existingIdentityId))
  process.exit(1);
}

const {
  identityId,
  txidHex,
  assetLockProof,
} = await createPlatformAssetLock(hdOpts, regFundKey, changeKey, assetKey, rpc);

console.log();
console.log(`identityId:`, base58.encode(identityId));


const identityKeys = [masterKey, otherKey];
const identityPublicKeys: DashBincode.IdentityPublicKeyInCreation[] = [
  DashBincode.IdentityPublicKeyInCreation.V0(
    DashBincode.IdentityPublicKeyInCreationV0({
      id: 0,
      key_type: DashBincode.KeyType.ECDSA_SECP256K1(),
      purpose: DashBincode.Purpose.AUTHENTICATION(),
      security_level: DashBincode.SecurityLevel.MASTER(),
      contract_bounds: undefined,
      read_only: false,
      data: DashBincode.BinaryData(masterKey.publicKey),
      signature: DashBincode.BinaryData(new Uint8Array()),
    }),
  ),
  DashBincode.IdentityPublicKeyInCreation.V0(
    DashBincode.IdentityPublicKeyInCreationV0({
      id: 1,
      key_type: DashBincode.KeyType.ECDSA_SECP256K1(),
      purpose: DashBincode.Purpose.AUTHENTICATION(),
      security_level: DashBincode.SecurityLevel.CRITICAL(),
      contract_bounds: undefined,
      read_only: false,
      data: DashBincode.BinaryData(otherKey.publicKey),
      signature: DashBincode.BinaryData(new Uint8Array()),
    }),
  ),
];

const identityCreate = DashBincode.IdentityCreateTransitionV0({
  asset_lock_proof: assetLockProof,
  public_keys: identityPublicKeys,
  identity_id: DashBincode.Identifier(
    DashBincode.IdentifierBytes32(identityId),
  ),
  user_fee_increase: 0,
  signature: DashBincode.BinaryData(new Uint8Array()),
});

const stateTransition: DashBincode.StateTransition =
  DashBincode.StateTransition.IdentityCreate(
    DashBincode.IdentityCreateTransition.V0(identityCreate),
  );
// console.log(`identityPublicKeys:`, identityPublicKeys);

const signableTransition = new Uint8Array(
  Bincode.encode(DashBincode.StateTransition, stateTransition, {
    signable: true,
  }),
);

const signableTransitionHash = await KeyUtils.doubleSha256(signableTransition);

{
  const magicSigBytes = await KeyUtils.magicSign({
    privKeyBytes: assetKey.privateKey!,
    doubleSha256Bytes: signableTransitionHash,
  });

  identityCreate.signature[0] = magicSigBytes;
}

for (let i = 0; i < identityKeys.length; i += 1) {
  const key = identityKeys[i];
  const stPub = identityCreate.public_keys[i];
  const magicSigBytes = await KeyUtils.magicSign({
    privKeyBytes: key.privateKey!,
    doubleSha256Bytes: signableTransitionHash,
  });

  Bincode.match(stPub, {
    V0: ({ 0: stPub0 }: { 0: any }) => {
      stPub0.signature[0] = magicSigBytes;
    },
  });
}

const fullSigTransition = new Uint8Array(
  Bincode.encode(DashBincode.StateTransition, stateTransition, {
    signable: false,
  }),
);
const transitionHash = await KeyUtils.sha256(fullSigTransition);

console.log("Broadcasting Identity Create Transition...")
try {
  const response = await nodeRpc.platform.broadcastStateTransition({
    stateTransition: fullSigTransition,
  })
  console.log('response', response.status, response.response);
} catch (e) {
  console.error("Error: ", decodeURIComponent((e as any).message))
}

const identity = base58.encode(identityId);
console.log();
console.log(`https://testnet.platform-explorer.com/identity/${identity}`);
console.log(`https://testnet.platform-explorer.com/transaction/${toHex(transitionHash)}`);
}

if (typeof process === 'object' && process.argv[1] === import.meta.filename) {

  import("dotenv").then(dotenv => {
    dotenv.default.config({ path: ".env" });

    let walletPhrase = process.env.DASH_WALLET_PHRASE!;
    let walletSalt = process.env.DASH_WALLET_SALT ?? "";

    const identityIndex = parseInt(process.argv[2], 10);
    if (isNaN(identityIndex)) {
      console.error("");
      console.error("USAGE");
      console.error(`   ${process.argv[0]} ${process.argv[1]} <identity-index>`);
      console.error("");
      console.error("EXAMPLE");
      console.error(`   ${process.argv[0]} ${process.argv[1]} 0`);
      console.error("");
      process.exit(1);
    }

    step1CreateIdentity(walletPhrase, walletSalt, identityIndex);
  })
}
