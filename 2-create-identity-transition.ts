import * as DashTx from "dashtx";
import * as Bincode from "./src/bincode.ts";
import * as DashBincode from "./1.8.1/generated_bincode.js";
import * as KeyUtils from "./src/key-utils.js";
import base64 from "base64-js";
import { base58 } from "./src/util/base58.ts";
import type { HDKey } from "dashhd"
import { connectToNode } from "./src/rpc.ts"
import { NODE_ADDRESS } from "./src/constants.ts"

export interface AssetLockChainProof {
  core_chain_locked_height: number;
  out_point: {
    txid: string;
    vout: number;
  };
}

// DashBincode types (should be imported if available)
// type AssetLockProof = any; // Replace with actual type from DashBincode
// type Identifier = any; // Replace with actual type from DashBincode
// type StateTransition = any; // Replace with actual type from DashBincode
// type IdentityCreateTransitionV0 = any; // Replace with actual type from DashBincode
// type IdentityPublicKeyInCreation = any; // Replace with actual type from DashBincode

export interface EvoKey {
  id: number;
  type: any; // DashBincode.KeyType
  purpose: any; // DashBincode.Purpose
  securityLevel: any; // DashBincode.SecurityLevel
  readOnly: boolean;
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  data: string;
}

export interface STKey {
  id: number;
  type: any;
  purpose: any;
  data: string;
  securityLevel: any;
  readOnly: boolean;
}

const nodeRpc = connectToNode(NODE_ADDRESS);

/**
 * 
 * @param assetKey This is the asset key that was "locked" on the core chain
 * @param masterKey This stored as the MASTER Identity Public Key
 * @param otherKey This is another Identity Public Key at the CRITICAL security level
 * @param identityId
 * @param assetLockProof Proof that the asset was locked
 */
export async function createIdentityFromAssetLock(
  assetKey: HDKey,
  masterKey: HDKey,
  otherKey: HDKey,
  identityId: Uint8Array,
  assetLockProof: DashBincode.AssetLockProof,
): Promise<void> {
  if (!masterKey.privateKey) {
    throw new Error("'masterKey' is missing 'privateKey'");
  }
  if (!otherKey.privateKey) {
    throw new Error("'otherKey' is missing 'privateKey'");
  }
  const identityKeys = await makeKnownIdentityKeys(
    { privateKey: masterKey.privateKey, publicKey: masterKey.publicKey },
    { privateKey: otherKey.privateKey, publicKey: otherKey.publicKey },
  );
  const stKeys = makeIdentityTransitionKeys(identityKeys);

  const identityCreate = DashBincode.IdentityCreateTransitionV0({
    asset_lock_proof: assetLockProof,
    public_keys: stKeys,
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
  console.log(`stKeys:`);
  console.log(stKeys);

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
      privKeyBytes: key.privateKey,
      doubleSha256Bytes: signableTransitionHash,
    });

    Bincode.match(stPub, {
      V0: ({ 0: stPub0 }: { 0: any }) => {
        stPub0.signature[0] = magicSigBytes;
      },
    });
  }

  console.log();
  console.log(
    JSON.stringify(
      stateTransition,
      (_key, val) => {
        if (val instanceof Uint8Array || val instanceof ArrayBuffer) {
          return {
            "@Uint8Array hex": DashTx.utils.bytesToHex(new Uint8Array(val)),
          };
        }
        return val;
      },
      2,
    ),
  );

  let grpcTransition = "";
  let transitionHashHex = "";
  
  const fullSigTransition = new Uint8Array(
    Bincode.encode(DashBincode.StateTransition, stateTransition, {
      signable: false,
    }),
  );
  console.log();
  console.log(`transition (fully signed):`);
  console.log(DashTx.utils.bytesToHex(fullSigTransition));
  const transitionHash = await KeyUtils.sha256(fullSigTransition);
  transitionHashHex = DashTx.utils.bytesToHex(transitionHash);
  grpcTransition = base64.fromByteArray(fullSigTransition);



  console.log("Broadcasting Identity Create Transition...")
  try {
    const response = await nodeRpc.platform.broadcastStateTransition({
      stateTransition: fullSigTransition,
    })
    console.log('response', response);
  } catch (e) {
    console.error("Error: ", decodeURIComponent((e as any).message))
  }

  console.log();
  const identity = base58.encode(identityId);
  console.log(`https://testnet.platform-explorer.com/identity/${identity}`);
  console.log(
    `https://testnet.platform-explorer.com/transaction/${transitionHashHex}`,
  );
}

// --- Helper Functions ---

async function makeKnownIdentityKeys(
  masterKey: { privateKey: Uint8Array; publicKey: Uint8Array },
  otherKey: { privateKey: Uint8Array; publicKey: Uint8Array },
): Promise<EvoKey[]> {
  if (!masterKey.privateKey) {
    throw new Error("masterKey.privateKey missing");
  }
  if (!otherKey.privateKey) {
    throw new Error("otherKey.privateKey missing");
  }
  const keyDescs: EvoKey[] = [
    {
      id: 0,
      type: DashBincode.KeyType.ECDSA_SECP256K1(),
      purpose: DashBincode.Purpose.AUTHENTICATION(),
      securityLevel: DashBincode.SecurityLevel.MASTER(),
      readOnly: false,
      publicKey: masterKey.publicKey,
      privateKey: masterKey.privateKey,
      data: "",
    },
    {
      id: 1,
      type: DashBincode.KeyType.ECDSA_SECP256K1(),
      purpose: DashBincode.Purpose.AUTHENTICATION(),
      securityLevel: DashBincode.SecurityLevel.CRITICAL(),
      readOnly: false,
      publicKey: otherKey.publicKey,
      privateKey: otherKey.privateKey,
      data: "",
    },
  ];
  return keyDescs;
}

function makeIdentityTransitionKeys(
  identityKeys: EvoKey[],
): DashBincode.IdentityPublicKeyInCreation[] {
  const stKeys: DashBincode.IdentityPublicKeyInCreation[] = [];
  for (const key of identityKeys) {
    const stKey = DashBincode.IdentityPublicKeyInCreation.V0(
      DashBincode.IdentityPublicKeyInCreationV0({
        id: key.id,
        key_type: key.type,
        purpose: key.purpose,
        security_level: key.securityLevel,
        contract_bounds: undefined,
        read_only: key.readOnly || false,
        data: DashBincode.BinaryData(key.publicKey),
        signature: DashBincode.BinaryData(new Uint8Array()),
      }),
    );
    stKeys.push(stKey);
  }
  return stKeys;
}
