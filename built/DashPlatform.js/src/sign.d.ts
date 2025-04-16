import { IdentityPublicKey, StateTransition } from "../2.0.0/generated_bincode.js";
/**
 * Signs a StateTransition in-place.
 * TODO: owner_id?
 * @param st StateTransition to sign
 * @param identity Public key to sign with
 * @param private_key Cooresponding Private key
 */
export declare function signTransitionWithRawKey(st: StateTransition, pubkey: IdentityPublicKey, private_key: Uint8Array): Promise<void>;
