pragma circom 2.0.1;

include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/multiplexer.circom";

include "./rlp.circom";
include "./keccak.circom";

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
