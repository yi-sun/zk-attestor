pragma circom 2.0.0;

include "./vocdoni-keccak/keccak.circom";
include "./vocdoni-keccak/permutations.circom";
include "./vocdoni-keccak/utils.circom";

template PadMultiBlock(nBits) {
    signal input in[nBits];

    var blockSize = 136 * 8;
    var numPadBlocks = (nBits + 2 + blockSize - 1) \ blockSize;
    var outBits = blockSize * numPadBlocks;
    signal output out[outBits];
    
    for (var i = 0; i < nBits; i++) {
        out[i] <== in[i];
    }
    out[nBits] <== 1;
    for (var i = nBits + 1; i < outBits - 1; i++) {
        out[i] <== 0;
    }
    out[outBits - 1] <== 1;
}

template Keccak256(nBitsIn) {
    signal input in[nBitsIn];
    signal output out[256];

    var blockSize = 136 * 8;
    var numPadBlocks = (nBitsIn + 2 + blockSize - 1) \ blockSize;

    component pad = PadMultiBlock(nBitsIn);
    for (var i = 0; i < nBitsIn; i++) {
        pad.in[i] <== in[i];
    }

    component abs[numPadBlocks];
    for (var idx = 0; idx < numPadBlocks; idx++) {
        abs[idx] = Absorb();
    }
    for (var i = 0; i < 25 * 64; i++) {
        abs[0].s[i] <== 0;
    }
    for (var i = 0; i < blockSize; i++) {
        abs[0].block[i] <== pad.out[i];
    }
    for (var idx = 1; idx < numPadBlocks; idx++) {
        for (var i = 0; i < 25 * 64; i++) {
            abs[idx].s[i] <== abs[idx - 1].out[i];
        }
        for (var i = 0; i < blockSize; i++) {
            abs[idx].block[i] <== pad.out[idx * blockSize + i];
        }
    }

    component squeeze = Squeeze(256);
    for (var i = 0; i < 25 * 64; i++) {
        squeeze.s[i] <== abs[numPadBlocks - 1].out[i];
    }
    for (var i = 0; i < 256; i++) {
        out[i] <== squeeze.out[i];
    }
}
