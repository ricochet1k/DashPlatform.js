import { fromHex, toHex } from './hex.js'
import { OP } from './opcodes.ts'


export function makeScript(...parts: (number | number[] | Uint8Array)[]) {
    let array: number[] = [];
    for (const part of parts) {
        if (typeof part === "number")
            array.push(part); // opcode
        else { // slice
            let len = part.length;
            if (len < OP.OP_PUSHDATA1) {
                array.push(len);
            } else if (len < 0x100) {
                array.push(OP.OP_PUSHDATA1, len);
            } else if (len < 0x10000) {
                array.push(OP.OP_PUSHDATA2, len & 0xff, len >> 8);
            } else if (len < 0x100000000) {
                array.push(OP.OP_PUSHDATA4, len & 0xff, (len >> 8) & 0xff, (len >> 16) & 0xff, (len >> 24) & 0xff);
            }
            array.push(...part);
        }
    }
    return new Uint8Array(array)
}

// console.log('scriptTest', toHex(makeScript(fromHex('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'))))

export function makeP2PK(pubkey: Uint8Array) {
    return makeScript(
        pubkey,
        OP.OP_CHECKSIG,
    )
}


export function makeP2SH(script_hash: Uint8Array) {
    return makeScript(
        OP.OP_HASH160,
        script_hash,
        OP.OP_EQUAL,
    )
}

export function makeP2PKH(pubkey_hash: Uint8Array) {
    return makeScript(
        OP.OP_DUP,
        OP.OP_HASH160,
        pubkey_hash,
        OP.OP_EQUALVERIFY,
        OP.OP_CHECKSIG,
    )
}

export function makeOP_RETURN(data: Uint8Array) {
    return makeScript(
        OP.OP_RETURN,
        data,
    )
}

