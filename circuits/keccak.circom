pragma circom 2.0.2;

include "./vocdoni-keccak/keccak.circom";
include "./vocdoni-keccak/permutations.circom";
include "./vocdoni-keccak/utils.circom";

template Pad0(inLenMin, inLenMax, outLen, outLenBits) {
    assert((2 ** outLenBits) >= outLen);
    assert(inLenMax + 1 <= outLen);
    signal input in[inLenMax];
    signal input inLen;
    signal output out[outLen];

    component inLenVal = LessEqThan(outLenBits);
    inLenVal.in[0] <== inLen;
    inLenVal.in[1] <== inLenMax;
    inLenVal.out === 1;

    component inLess[inLenMax - inLenMin];
    for (var idx = 0; idx < inLenMax - inLenMin; idx++) {
        inLess[idx] = LessThan(outLenBits);
        inLess[idx].in[0] <== idx + inLenMin;
        inLess[idx].in[1] <== inLen;
    }

    for (var idx = 0; idx < inLenMin; idx++) {
        out[idx] <== in[idx];
    }
    for (var idx = inLenMin; idx < inLenMax; idx++) {
        out[idx] <== inLess[idx - inLenMin].out * in[idx];
    }
    for (var idx = inLenMax; idx < outLen; idx++) {
        out[idx] <== 0;
    }
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

    component pad0 = Pad0(inLenMin, inLenMax, outLen, outLenBits);
    for (var idx = 0; idx < inLenMax; idx++) {
	pad0.in[idx] <== inFlip[idx];
    }
    pad0.inLen <== inLen;

    var minRounds = (inLenMin + 1 + 271) \ 272;
    var maxRounds = (inLenMax + 1 + 271) \ 272;
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

template Keccak256UpdateHex() {
    // 272 * 4 = 1088 bits
    signal input inHex[272];
    signal input sBits[25 * 64];

    signal output out[25 * 64];

    component n2b[272];
    for (var idx = 0; idx < 272; idx++) {
	n2b[idx] = Num2Bits(4);
	n2b[idx].in <== inHex[idx];
    }

    component abs = Absorb();
    for (var idx = 0; idx < 272; idx++) {
	for (var hexIdx = 0; hexIdx < 4; hexIdx++) {
	    abs.block[idx * 4 + hexIdx] <== n2b[idx].out[hexIdx];
	}
    }
    for (var idx = 0; idx < 1600; idx++) {
	abs.s[idx] <== sBits[idx];
    }
    for (var idx = 0; idx < 1600; idx++) {
	out[idx] <== abs.out[idx];
    }    
}

template Keccak256Hex(maxRounds) {
    signal input inPaddedHex[maxRounds * 272];
    signal input rounds;

    signal output out[256];

    component roundCheck = LessEqThan(252);
    roundCheck.in[0] <== rounds;
    roundCheck.in[1] <== maxRounds;
    roundCheck.out === 1;

    component roundCheck2 = IsZero();
    roundCheck2.in <== rounds;
    roundCheck2.out === 0;

    component updates[maxRounds];
    updates[0] = Keccak256UpdateHex();
    for (var sIdx = 0; sIdx < 1600; sIdx++) {
	updates[0].sBits[sIdx] <== 0;
    }
    for (var inIdx = 0; inIdx < 272; inIdx++) {
	updates[0].inHex[inIdx] <== inPaddedHex[inIdx];
    }
    for (var idx = 1; idx < maxRounds; idx++) {
	updates[idx] = Keccak256UpdateHex();
	for (var sIdx = 0; sIdx < 1600; sIdx++) {
	    updates[idx].sBits[sIdx] <== updates[idx - 1].out[sIdx];
	}
	for (var inIdx = 0; inIdx < 272; inIdx++) {
	    updates[idx].inHex[inIdx] <== inPaddedHex[idx * 272 + inIdx];
	}
    }

    component selector = Multiplexer(1600, maxRounds);
    for (var idx = 0; idx < maxRounds; idx++) {
	for (var sIdx = 0; sIdx < 1600; sIdx++) {
	    selector.inp[idx][sIdx] <== updates[idx].out[sIdx];
	}
    }
    selector.sel <== rounds - 1;

    component squeeze = Squeeze(256);
    for (var idx = 0; idx < 1600; idx++) {
	squeeze.s[idx] <== selector.out[idx];
    }
    for (var idx = 0; idx < 256; idx++) {
	out[idx] <== squeeze.out[idx];
    }
}