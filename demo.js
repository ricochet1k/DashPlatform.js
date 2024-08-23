"use strict";

let DashPhrase = require("dashphrase");
let DashHd = require("dashhd");
let DashKeys = require("dashkeys");
let DashTx = require("dashtx");
let DashPlatform = require("./dashplatform.js");

let KeyUtils = require("./key-utils.js");

// let DapiGrpc = require("@dashevo/dapi-grpc");
let Dpp = require("@dashevo/wasm-dpp");

let rpcAuthUrl = "https://api:null@trpc.digitalcash.dev";

const DIP13_ECDSA = 0;

let identityEcdsaPath = "";
{
  // m/purpose'/coin_type'/feature'/subfeature'/keytype'/identityindex'/keyindex'
  // ex: m/9'/5'/5'/0'/0'/<id>/<key>
  let purposeDip13 = 9;
  let coinDash = 5;
  let featureId = 5;
  let subfeatureKey = 0;
  let keyType = DIP13_ECDSA;
  identityEcdsaPath = `m/${purposeDip13}'/${coinDash}'/${featureId}'/${subfeatureKey}'/${keyType}'`;
}

async function main() {
  let network = "testnet";

  // let phrase = await DashPhrase.generate();
  let phrase =
    "casino reveal crop open ordinary garment spy pizza clown exercise poem enjoy";
  let salt = "";
  let seedBytes = await DashPhrase.toSeed(phrase, salt);
  let walletKey = await DashHd.fromSeed(seedBytes);

  let accountIndex = 0; // pick the desired account for paying the fee
  let addressIndex = 8; // pick an address with funds
  let accountKey = await walletKey.deriveAccount(accountIndex);
  let use = DashHd.RECEIVE;
  let xprvKey = await accountKey.deriveXKey(use);
  let addressKey = await xprvKey.deriveAddress(addressIndex);
  if (!addressKey.privateKey) {
    throw new Error("not an error, just a lint hack");
  }

  let addr = await DashHd.toAddr(addressKey.publicKey, { version: network });
  let pkhBytes = await DashKeys.addrToPkh(addr, {
    //@ts-ignore
    version: network,
  });
  let pkh = DashKeys.utils.bytesToHex(pkhBytes);
  let wif = await DashHd.toWif(addressKey.privateKey, { version: network });
  console.log();
  console.log(`Address: ${addr}`);
  // TODO is _this_ the assetLockPrivateKey??
  console.log(`WIF: ${wif}`);

  KeyUtils.set(addr, {
    address: addr,
    publicKey: addressKey.publicKey,
    privateKey: addressKey.privateKey,
    pubKeyHash: pkh,
  });

  let utxos = await DashTx.utils.rpc(rpcAuthUrl, "getaddressutxos", {
    addresses: [addr],
  });
  let total = DashTx.sum(utxos);
  console.log();
  console.log(`utxos (${total})`);
  console.log(utxos);

  // TODO which hd paths to use for which addresses?
  let creditOutputs = [{ satoshis: total - 10000, pubKeyHash: pkh }];
  let totalCredits = DashTx.sum(creditOutputs);
  let burnOutput = { satoshis: totalCredits, pubKeyHash: pkh };
  //@ts-ignore - TODO add types
  let assetLockScript = DashPlatform.Tx.packAssetLock({
    creditOutputs,
  });

  const VERSION_PLATFORM = 3;
  const TYPE_ASSET_LOCK = 8;
  let txDraft = {
    version: VERSION_PLATFORM,
    type: TYPE_ASSET_LOCK,
    inputs: utxos,
    outputs: [burnOutput],
    extraPayload: assetLockScript,
  };
  console.log();
  console.log(`txDraft:`);
  console.log(txDraft);

  let dashTx = DashTx.create(KeyUtils);
  let txSigned = await dashTx.hashAndSignAll(txDraft);
  console.log();
  console.log(`txSigned:`);
  console.log(txSigned);

  // let txid = await DashTx.utils.rpc(
  //   rpcAuthUrl,
  //   "sendrawtransaction",
  //   txSigned.transaction,
  // );

  // let assetLockProof = await YoureAWizardHarry.doMagic();

  // let idIndex = 0; // increment to first unused
  // await getKeysForIdentity(idIndex);

  // let identityId = assetLockProof.createIdentifier();
  // let identity = Dpp.identity.create(identityId, dppKeys);
  // let signedTransition = signTransition(
  //   idenity,
  //   assetLockProof,
  //   assetLockPrivateKeyBuffer,
  // );

  console.log("");
  console.log("TODO");
  console.log(`  - which is considered the "asset lock private key buffer"?`);
  console.log(`  - can we bypass Dpp.IdentityPublicKey?`);
  console.log(`  - what's all this super signing the transition about?`);
  console.log(`  - how to broadcast the transition?`);
}

async function getKeysForIdentity(idIndex) {
  let identityEcdsaKey = await DashHd.derivePath(walletKey, identityEcdsaPath);
  let identityKey = await DashHd.deriveChild(
    identityEcdsaKey,
    idIndex,
    DashHd.HARDENED,
  );

  const MASTER_KEY = 0;
  const HIGH_AUTH_KEY = 1;
  const CRITICAL_KEY = 2;
  const TRANSFER_KEY = 3;

  let keyDescs = [
    {
      id: MASTER_KEY,
      securityLevel: Dpp.IdentityPublicKey.SECURITY_LEVELS.MASTER,
    },
    {
      id: HIGH_AUTH_KEY,
      securityLevel: Dpp.IdentityPublicKey.SECURITY_LEVELS.HIGH,
    },
    {
      id: CRITICAL_KEY,
      securityLevel: Dpp.IdentityPublicKey.SECURITY_LEVELS.CRITICAL,
    },
    {
      id: TRANSFER_KEY,
      purpose: Dpp.IdentityPublicKey.PURPOSES.TRANSFER,
      securityLevel: Dpp.IdentityPublicKey.SECURITY_LEVELS.CRITICAL,
    },
  ];

  let keys = [];
  let dppKeys = [];
  for (let keyDesc of keyDescs) {
    let key = await DashHd.deriveChild(
      identityKey,
      keyDesc.id,
      DashHd.HARDENED,
    );
    keys.push(key);

    let MAGIC_NUMBER_1 = 1; // TODO why?
    let dppKey = new Dpp.IdentityPublicKey(MAGIC_NUMBER_1);
    dppKey.setId(keyDesc.id);
    dppKey.setData(key.publicKey);
    if (keyDesc.purpose) {
      dppKey.setPurpose(keyDesc.purpose);
    }
    dppKey.setSecurityLevel(keyDesc.securityLevel);
    dppKeys.push(dppKey);
  }

  return dppKeys;
}

function signTransition(identity, assetLockProof, assetLockPrivateKey) {
  // TODO is assetLockProof the same as txoutproof?

  // Create ST
  const identityCreateTransition = Dpp.identity.createIdentityCreateTransition(
    identity,
    assetLockProof,
  );

  // Create key proofs
  const [stMasterKey, stHighAuthKey, stCriticalAuthKey, stTransferKey] =
    identityCreateTransition.getPublicKeys();

  // Sign master key

  identityCreateTransition.signByPrivateKey(
    identityMasterPrivateKey.toBuffer(),
    IdentityPublicKey.TYPES.ECDSA_SECP256K1,
  );

  stMasterKey.setSignature(identityCreateTransition.getSignature());

  identityCreateTransition.setSignature(undefined);

  // Sign high auth key

  identityCreateTransition.signByPrivateKey(
    identityHighAuthPrivateKey.toBuffer(),
    IdentityPublicKey.TYPES.ECDSA_SECP256K1,
  );

  stHighAuthKey.setSignature(identityCreateTransition.getSignature());

  identityCreateTransition.setSignature(undefined);

  // Sign critical auth key

  identityCreateTransition.signByPrivateKey(
    identityCriticalAuthPrivateKey.toBuffer(),
    IdentityPublicKey.TYPES.ECDSA_SECP256K1,
  );

  stCriticalAuthKey.setSignature(identityCreateTransition.getSignature());

  identityCreateTransition.setSignature(undefined);

  // Sign transfer key

  identityCreateTransition.signByPrivateKey(
    identityTransferPrivateKey.toBuffer(),
    IdentityPublicKey.TYPES.ECDSA_SECP256K1,
  );

  stTransferKey.setSignature(identityCreateTransition.getSignature());

  identityCreateTransition.setSignature(undefined);

  // Set public keys back after updating their signatures
  identityCreateTransition.setPublicKeys([
    stMasterKey,
    stHighAuthKey,
    stCriticalAuthKey,
    stTransferKey,
  ]);

  // Sign and validate state transition

  identityCreateTransition.signByPrivateKey(
    assetLockPrivateKey,
    IdentityPublicKey.TYPES.ECDSA_SECP256K1,
  );

  // TODO(versioning): restore
  // @ts-ignore
  // const result = await Dpp.stateTransition.validateBasic(
  //   identityCreateTransition,
  //   // TODO(v0.24-backport): get rid of this once decided
  //   //  whether we need execution context in wasm bindings
  //   new StateTransitionExecutionContext(),
  // );

  // if (!result.isValid()) {
  //   const messages = result.getErrors().map((error) => error.message);
  //   throw new Error(`StateTransition is invalid - ${JSON.stringify(messages)}`);
  // }

  return identityCreateTransition;
}

main();
