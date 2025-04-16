export const EncodeOnlyRawBytes = Object.assign(function EncodeOnlyRawBytes(data) {
    return data;
}, {
    // name: 'EncodeOnlyRawBytes',
    isValid(x) {
        return x instanceof Uint8Array;
    },
    encode(bc, x) {
        new Uint8Array(bc.dataview.buffer).set(x, bc._idxThenAddExtend(x.byteLength));
    },
    decode(bc) {
        throw new Error("Unable to decode an EncodeOnlyRawBytes (how many bytes to decode?)");
    }
});
export const Transaction = EncodeOnlyRawBytes;
