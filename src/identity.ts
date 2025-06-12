import { toHex } from "./hex.js"
import { base58 } from "./util/base58.ts"
import * as BinCode from "../src/bincode.ts"
import * as DashBincode from "../2.0.0/generated_bincode.js"
import { NodeConnection } from "./rpc.ts"

export type IdentityId = Uint8Array

/**
 * Retrieve the IdentityId of the Identity that includes the given public key hash
 */
// TODO: Pass in a plain Key instead
export async function findExistingIdentity(node: NodeConnection, publicKeyHash: Uint8Array): Promise<DashBincode.Identity | null> {
    let alreadyIdentity: Awaited<ReturnType<typeof node.platform.getIdentityByPublicKeyHash>>;
    try {
        alreadyIdentity = await node.platform.getIdentityByPublicKeyHash({
            version: {
                oneofKind: 'v0', v0: {
                    publicKeyHash,
                    prove: false,
                }
            }
        })
    } catch (e) {
        if ((e as any)?.code === 'NOT_FOUND') {
            // not created yet
            return null
        } else {
            throw e
        }
    }
    if (alreadyIdentity.response.version.oneofKind === 'v0') {
        // console.log('alreadyIdentity', alreadyIdentity.response.version.v0)
        if (alreadyIdentity.response.version.v0.result.oneofKind === 'identity') {
            const identityBytes: Uint8Array = alreadyIdentity.response.version.v0.result.identity
            // console.log('alreadyIdentity hex', toHex(identityBytes))
            const identity = BinCode.decode(DashBincode.Identity, BinCode.typedArrayToBuffer(identityBytes))
            // console.log('Identity Already Created!', identity)
            return identity
        }
    }
    throw new Error("Cannot handle getIdentityByPublicKeyHash response");
}