pragma circom 2.0.1;

include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/multiplexer.circom";

include "./rlp.circom";
include "./keccak2.circom";

template EthBlockHash() {
    signal input rlpPrefixBits[24];
    signal input parentHashRlpBits[256 + 8];
    signal input ommersHashRlpBits[256 + 8];
    signal input beneficiaryRlpBits[160 + 8];
    signal input stateRootRlpBits[256 + 8];
    signal input transactionsRootRlpBits[256 + 8];
    signal input receiptsRootRlpBits[256 + 8];
    signal input logsBloomRlpBits[256 * 8 + 24];
    signal input difficultyRlpBits[64];
    signal input numberRlpBits[32];
    signal input gasLimitRlpBits[40];
    signal input gasUsedRlpBits[40];
    signal input timestampRlpBits[40];
    signal input extraDataRlpBits[256 + 8];
    signal input mixHashRlpBits[256 + 8];
    signal input nonceRlpBits[64 + 8];
    signal input basefeeRlpBits[48];

    signal input numberRlpBitLen;
    signal input gasUsedRlpBitLen;
    signal input extraDataRlpBitLen;
    signal input basefeeRlpBitLen;

    signal output blockHash[256];

    component numberVal = LessEqThan(6);
    numberVal.in[0] <== numberRlpBitLen;
    numberVal.in[1] <== 32;
    numberVal.out === 1;

    component gasUsedVal = LessEqThan(6);
    gasUsedVal.in[0] <== gasUsedRlpBitLen;
    gasUsedVal.in[1] <== 40;
    gasUsedVal.out === 1;

    component extraDataVal = LessEqThan(9);
    extraDataVal.in[0] <== extraDataRlpBitLen;
    extraDataVal.in[1] <== 264;
    extraDataVal.out === 1;

    component basefeeVal = LessEqThan(6);
    basefeeVal.in[0] <== basefeeRlpBitLen;
    basefeeVal.in[1] <== 48;
    basefeeVal.out === 1;    

    component concat = VarConcat4(3648, 3680, 12,
                                  40, 80, 7,
                                  40, 304, 9,
                                  336, 384, 9);
    concat.aLen <== 3648 + numberRlpBitLen;
    concat.bLen <== 40 + gasUsedRlpBitLen;
    concat.cLen <== 40 + extraDataRlpBitLen;
    concat.dLen <== 336 + basefeeRlpBitLen;

    var curr_idx = 0;
    for (var idx = 0; idx < 24; idx++) {
        concat.a[curr_idx] <== rlpPrefixBits[idx];
        curr_idx = curr_idx + 1;
    }
    for (var idx = 0; idx < 256 + 8; idx++) {
        concat.a[curr_idx] <== parentHashRlpBits[idx];
        curr_idx = curr_idx + 1;
    }
    for (var idx = 0; idx < 256 + 8; idx++) {
        concat.a[curr_idx] <== ommersHashRlpBits[idx];
        curr_idx = curr_idx + 1;
    }
    for (var idx = 0; idx < 160 + 8; idx++) {
        concat.a[curr_idx] <== beneficiaryRlpBits[idx];
        curr_idx = curr_idx + 1;
    }
    for (var idx = 0; idx < 256 + 8; idx++) {
        concat.a[curr_idx] <== stateRootRlpBits[idx];
        curr_idx = curr_idx + 1;
    }
    for (var idx = 0; idx < 256 + 8; idx++) {
        concat.a[curr_idx] <== transactionsRootRlpBits[idx];
        curr_idx = curr_idx + 1;
    }
    for (var idx = 0; idx < 256 + 8; idx++) {
        concat.a[curr_idx] <== receiptsRootRlpBits[idx];
        curr_idx = curr_idx + 1;
    }
    for (var idx = 0; idx < 256 * 8 + 24; idx++) {
        concat.a[curr_idx] <== logsBloomRlpBits[idx];
        curr_idx = curr_idx + 1;
    }
    for (var idx = 0; idx < 64; idx++) {
        concat.a[curr_idx] <== difficultyRlpBits[idx];
        curr_idx = curr_idx + 1;
    }
    for (var idx = 0; idx < 32; idx++) {
        concat.a[curr_idx] <== numberRlpBits[idx];
        curr_idx = curr_idx + 1;
    }

    curr_idx = 0;
    for (var idx = 0; idx < 40; idx++) {
        concat.b[curr_idx] <== gasLimitRlpBits[idx];
        curr_idx = curr_idx + 1;
    }
    for (var idx = 0; idx < 40; idx++) {
        concat.b[curr_idx] <== gasUsedRlpBits[idx];
        curr_idx = curr_idx + 1;
    }

    curr_idx = 0;
    for (var idx = 0; idx < 40; idx++) {
        concat.c[curr_idx] <== timestampRlpBits[idx];
        curr_idx = curr_idx + 1;
    }
    for (var idx = 0; idx < 256 + 8; idx++) {
        concat.c[curr_idx] <== extraDataRlpBits[idx];
        curr_idx = curr_idx + 1;
    }

    curr_idx = 0;
    for (var idx = 0; idx < 256 + 8; idx++) {
        concat.d[curr_idx] <== mixHashRlpBits[idx];
        curr_idx = curr_idx + 1;
    }
    for (var idx = 0; idx < 64 + 8; idx++) {
        concat.d[curr_idx] <== nonceRlpBits[idx];
        curr_idx = curr_idx + 1;
    }
    for (var idx = 0; idx < 48; idx++) {
        concat.d[curr_idx] <== basefeeRlpBits[idx];
        curr_idx = curr_idx + 1;
    }

    component leq = LessEqThan(13);
    leq.in[0] <== concat.outLen + 2;
    // 4 * blockSize = 4352
    leq.in[1] <== 4352;

    // if leq.out == 1, use keccak4, else use keccak5
    component pad4 = Pad101(4064, 4350, 4352, 13);
    component pad5 = Pad101(4351, 4448, 5440, 13);
    for (var idx = 0; idx < 4350; idx++) {
        pad4.in[idx] <== concat.out[idx];
    }
    pad4.inLen <== concat.outLen - leq.out * concat.outLen;

    for (var idx = 0; idx < 4448; idx++) {
        pad5.in[idx] <== concat.out[idx];
    }
    pad5.inLen <== concat.outLen;
    
    var blockSize = 136 * 8;
    component keccak4 = Keccak256NoPad(4 * blockSize);
    component keccak5 = Keccak256NoPad(5 * blockSize);
    for (var idx = 0; idx < 4352; idx++) {
        keccak4.in[idx] <== pad4.out[idx];
    }
    for (var idx = 0; idx < 5440; idx++) {
        keccak5.in[idx] <== pad5.out[idx];
    }
    for (var idx = 0; idx < 256; idx++) {
        blockHash[idx] <== leq.out * (keccak4.out[idx] - keccak5.out[idx]) + keccak5.out[idx];
    }    
}

template EthBlockHashMin() {
    signal input rlpPrefixBits[24];
    signal input parentHashRlpBits[256 + 8];
    signal input ommersHashRlpBits[256 + 8];
    signal input beneficiaryRlpBits[160 + 8];
    signal input stateRootRlpBits[256 + 8];
    signal input transactionsRootRlpBits[256 + 8];
    signal input receiptsRootRlpBits[256 + 8];
    signal input logsBloomRlpBits[256 * 8 + 24];
    signal input difficultyRlpBits[64];
    signal input suffixRlpBits[32 + 40 + 40 + 40 + 256 + 8 + 256 + 8 + 64 + 8 + 48];

    signal input suffixRlpBitLen;

    signal output blockHash[256];

    component leq = LessEqThan(13);
    leq.in[0] <== 3648 + suffixRlpBitLen + 2;
    // 4 * blockSize = 4352
    leq.in[1] <== 4352;

    // if leq.out == 1, use keccak4, else use keccak5
    component pad4 = Pad101(4064, 4350, 4352, 13);
    component pad5 = Pad101(4351, 4448, 5440, 13);

    pad4.inLen <== 3648 + suffixRlpBitLen;
    pad5.inLen <== 3648 + suffixRlpBitLen;
    var curr_idx = 0;
    for (var idx = 0; idx < 24; idx++) {
        pad4.in[curr_idx] <== rlpPrefixBits[idx];
	pad5.in[curr_idx] <== rlpPrefixBits[idx];	
        curr_idx = curr_idx + 1;
    }
    for (var idx = 0; idx < 256 + 8; idx++) {
        pad4.in[curr_idx] <== parentHashRlpBits[idx];
	pad5.in[curr_idx] <== parentHashRlpBits[idx];	
        curr_idx = curr_idx + 1;
    }
    for (var idx = 0; idx < 256 + 8; idx++) {
        pad4.in[curr_idx] <== ommersHashRlpBits[idx];
        pad5.in[curr_idx] <== ommersHashRlpBits[idx];
        curr_idx = curr_idx + 1;
    }
    for (var idx = 0; idx < 160 + 8; idx++) {
        pad4.in[curr_idx] <== beneficiaryRlpBits[idx];
        pad5.in[curr_idx] <== beneficiaryRlpBits[idx];	
        curr_idx = curr_idx + 1;
    }
    for (var idx = 0; idx < 256 + 8; idx++) {
        pad4.in[curr_idx] <== stateRootRlpBits[idx];
	pad5.in[curr_idx] <== stateRootRlpBits[idx];
        curr_idx = curr_idx + 1;
    }
    for (var idx = 0; idx < 256 + 8; idx++) {
        pad4.in[curr_idx] <== transactionsRootRlpBits[idx];
        pad5.in[curr_idx] <== transactionsRootRlpBits[idx];
        curr_idx = curr_idx + 1;
    }
    for (var idx = 0; idx < 256 + 8; idx++) {
        pad4.in[curr_idx] <== receiptsRootRlpBits[idx];
        pad5.in[curr_idx] <== receiptsRootRlpBits[idx];
        curr_idx = curr_idx + 1;
    }
    for (var idx = 0; idx < 256 * 8 + 24; idx++) {
        pad4.in[curr_idx] <== logsBloomRlpBits[idx];
        pad5.in[curr_idx] <== logsBloomRlpBits[idx];
        curr_idx = curr_idx + 1;
    }
    for (var idx = 0; idx < 64; idx++) {
        pad4.in[curr_idx] <== difficultyRlpBits[idx];
        pad5.in[curr_idx] <== difficultyRlpBits[idx];
        curr_idx = curr_idx + 1;
    }
    for (var idx = 0; idx < 702; idx++) {
        pad4.in[curr_idx] <== suffixRlpBits[idx];
        pad5.in[curr_idx] <== suffixRlpBits[idx];
        curr_idx = curr_idx + 1;
    }
    for (var idx = 0; idx < 32 + 40 + 40 + 40 + 256 + 8 + 256 + 8 + 64 + 8 + 48 - 702; idx++) {
        pad5.in[curr_idx] <== suffixRlpBits[idx + 702];
        curr_idx = curr_idx + 1;
    }
    
    var blockSize = 136 * 8;
    component keccak4 = Keccak256NoPad(4 * blockSize);
    component keccak5 = Keccak256NoPad(5 * blockSize);
    for (var idx = 0; idx < 4352; idx++) {
        keccak4.in[idx] <== pad4.out[idx];
    }
    for (var idx = 0; idx < 5440; idx++) {
        keccak5.in[idx] <== pad5.out[idx];
    }
    for (var idx = 0; idx < 256; idx++) {
        blockHash[idx] <== leq.out * (keccak4.out[idx] - keccak5.out[idx]) + keccak5.out[idx];
    }    
}

template EthBlockHashHex() {
    signal input rlpPrefixHexs[6];
    signal input parentHashRlpHexs[64 + 2];
    signal input ommersHashRlpHexs[64 + 2];
    signal input beneficiaryRlpHexs[40 + 2];
    signal input stateRootRlpHexs[64 + 2];
    signal input transactionsRootRlpHexs[64 + 2];
    signal input receiptsRootRlpHexs[64 + 2];
    signal input logsBloomRlpHexs[64 * 8 + 6];
    signal input difficultyRlpHexs[16];
    signal input suffixRlpHexs[8 + 10 + 10 + 10 + 64 + 2 + 64 + 2 + 16 + 2 + 12];

    signal input suffixRlpHexLen;

    // bits
    signal output blockHash[256];

    component pad = ReorderPad101Hex(1016, 1112, 1360, 13);
    pad.inLen <== 912 + suffixRlpHexLen;
    var curr_idx = 0;
    for (var idx = 0; idx < 6; idx++) {
	pad.in[curr_idx] <== rlpPrefixHexs[idx];	
        curr_idx = curr_idx + 1;
    }
    for (var idx = 0; idx < 64 + 2; idx++) {
	pad.in[curr_idx] <== parentHashRlpHexs[idx];	
        curr_idx = curr_idx + 1;
    }
    for (var idx = 0; idx < 64 + 2; idx++) {
        pad.in[curr_idx] <== ommersHashRlpHexs[idx];
        curr_idx = curr_idx + 1;
    }
    for (var idx = 0; idx < 40 + 2; idx++) {
        pad.in[curr_idx] <== beneficiaryRlpHexs[idx];	
        curr_idx = curr_idx + 1;
    }
    for (var idx = 0; idx < 64 + 2; idx++) {
	pad.in[curr_idx] <== stateRootRlpHexs[idx];
        curr_idx = curr_idx + 1;
    }
    for (var idx = 0; idx < 64 + 2; idx++) {
        pad.in[curr_idx] <== transactionsRootRlpHexs[idx];
        curr_idx = curr_idx + 1;
    }
    for (var idx = 0; idx < 64 + 2; idx++) {
        pad.in[curr_idx] <== receiptsRootRlpHexs[idx];
        curr_idx = curr_idx + 1;
    }
    for (var idx = 0; idx < 64 * 8 + 6; idx++) {
        pad.in[curr_idx] <== logsBloomRlpHexs[idx];
        curr_idx = curr_idx + 1;
    }
    for (var idx = 0; idx < 16; idx++) {
        pad.in[curr_idx] <== difficultyRlpHexs[idx];
        curr_idx = curr_idx + 1;
    }
    for (var idx = 0; idx < 8 + 10 + 10 + 10 + 64 + 2 + 64 + 2 + 16 + 2 + 12; idx++) {
        pad.in[curr_idx] <== suffixRlpHexs[idx];
        curr_idx = curr_idx + 1;
    }

    // if leq.out == 1, use 4 rounds, else use 5 rounds
    component leq = LessEqThan(13);
    leq.in[0] <== 912 + suffixRlpHexLen + 1;
    // 4 * blockSize = 1088
    leq.in[1] <== 1088;
    
    var blockSizeHex = 136 * 2;
    component keccak = Keccak256Hex(5);
    for (var idx = 0; idx < 5 * blockSizeHex; idx++) {
        keccak.inPaddedHex[idx] <== pad.out[idx];
    }
    keccak.rounds <== 5 - leq.out;
    for (var idx = 0; idx < 256; idx++) {
        blockHash[idx] <== keccak.out[idx];
    }    
}
