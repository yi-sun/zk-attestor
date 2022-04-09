pragma circom 2.0.3;

include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/multiplexer.circom";

template Pad0(inLenMin, inLenMax, outLen) {
    assert(inLenMax + 1 <= outLen);
    signal input in[inLenMax];
    signal input inLen;
    signal output out[outLen];
    
    for (var idx = 0; idx < inLenMin; idx++) {
        out[idx] <== in[idx];
    }
    for (var idx = inLenMin; idx < inLenMax; idx++) {
        out[idx] <-- (idx < inLen) * in[idx];
    }
    for (var idx = inLenMax; idx < outLen; idx++) {
        out[idx] <== 0;
    }

    component eqs[inLenMax - inLenMin];
    component eq_sum_selector = Multiplexer(1, inLenMax - inLenMin + 1);
    eq_sum_selector.inp[0][0] <== 0;
    for (var idx = inLenMin; idx < inLenMax; idx++) {
        eqs[idx - inLenMin] = IsEqual();
        eqs[idx - inLenMin].in[0] <== out[idx];
        eqs[idx - inLenMin].in[1] <== in[idx];

        eq_sum_selector.inp[idx - inLenMin + 1][0] <== eq_sum_selector.inp[idx - inLenMin][0] + eqs[idx - inLenMin].out;
    }
    eq_sum_selector.sel <== inLen - inLenMin;
    eq_sum_selector.out[0] === inLen - inLenMin;

    component zeros[inLenMax - inLenMin + 1];
    component zero_sum_selector = Multiplexer(1, inLenMax - inLenMin + 1);
    for (var idx = inLenMax; idx >= inLenMin; idx--) {
        zeros[idx - inLenMin] = IsZero();
        zeros[idx - inLenMin].in <== out[idx];

        if (idx == inLenMax) {
            zero_sum_selector.inp[idx - inLenMin][0] <== zeros[idx - inLenMin].out;
        } else {
            zero_sum_selector.inp[idx - inLenMin][0] <== zeros[idx - inLenMin].out + zero_sum_selector.inp[idx - inLenMin + 1][0];
        }
    }
    zero_sum_selector.sel <== inLen - inLenMin;
    zero_sum_selector.out[0] === inLenMax - inLen + 1;
}

template ReorderPad101Hex(inLenMin, inLenMax, outLen, outLenBits) {
    assert((2 ** outLenBits) >= outLen);
    assert(inLenMax + 1 <= outLen);
    assert(inLenMax % 2 == 0);
    signal input in[inLenMax];
    signal input inLen;
    signal output out[outLen];
    
    signal inFlip[inLenMax];
    for (var idx = 0; idx < inLenMax \ 2; idx++) {
	inFlip[2 * idx] <== in[2 * idx + 1];
	inFlip[2 * idx + 1] <== in[2 * idx];
    }

    component inLenVal = LessEqThan(outLenBits);
    inLenVal.in[0] <== inLen;
    inLenVal.in[1] <== inLenMax;
    inLenVal.out === 1;

    var minRounds = (inLenMin + 1 + 271) \ 272;
    var maxRounds = (inLenMax + 1 + 271) \ 272;

    component pad0 = Pad0(inLenMin, inLenMax, maxRounds * 272);
    for (var idx = 0; idx < inLenMax; idx++) {
	pad0.in[idx] <== inFlip[idx];
    }
    pad0.inLen <== inLen;

    component eqs[(maxRounds - minRounds + 1) * 272];
    for (var idx = (minRounds - 1) * 272; idx < maxRounds * 272; idx++) {
	eqs[idx - (minRounds - 1) * 272] = IsEqual();
	eqs[idx - (minRounds - 1) * 272].in[0] <== inLen;
	eqs[idx - (minRounds - 1) * 272].in[1] <== idx + 1;
    }

    component leqs[maxRounds - minRounds + 1];
    for (var round = minRounds; round <= maxRounds; round++) {
	leqs[round - minRounds] = LessEqThan(outLenBits);
	leqs[round - minRounds].in[0] <== inLen + 1;
	leqs[round - minRounds].in[1] <== round * 272; 
    }

    signal padHex[(maxRounds - minRounds + 1) * 272];
    for (var round = minRounds - 1; round < maxRounds; round++) {
	for (var idx = 0; idx < 271; idx++) {
	    if (idx == 0 && round == minRounds - 1) {
		padHex[(round - minRounds + 1) * 272 + idx] <== 0;
	    } else {
		padHex[(round - minRounds + 1) * 272 + idx] <== eqs[(round - minRounds + 1) * 272 + idx - 1].out;
	    }
	}
	// 1000 if padding is in this nibble + 0001 if at most this many rounds
	padHex[(round - minRounds + 1) * 272 + 271] <== eqs[(round - minRounds + 1) * 272 + 270].out + 8 * leqs[round + 1 - minRounds].out;
    }

    for (var idx = 0; idx < (minRounds - 1) * 272; idx++) {
	out[idx] <== pad0.out[idx];
    }
    for (var idx = (minRounds - 1) * 272; idx < maxRounds * 272; idx++) {
	out[idx] <== pad0.out[idx] + padHex[idx - (minRounds - 1) * 272];
    }
}

component main { public [ in, inLen ] } = ReorderPad101Hex(0, 1064, 1088, 11);
