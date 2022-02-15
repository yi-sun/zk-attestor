pragma circom 2.0.2;

include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/multiplexer.circom";

include "./vocdoni-keccak/keccak.circom";
include "./vocdoni-keccak/permutations.circom";
include "./vocdoni-keccak/utils.circom";

function min(a, b) {
    if (a < b) {
	return a;
    }
    return b;
}

function log_ceil(n) {
   var n_temp = n;
   for (var i = 0; i < 254; i++) {
       if (n_temp == 0) {
          return i;
       }
       n_temp = n_temp \ 2;
   }
   return 254;
}

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

    component zeros[inLenMax - inLenMin];
    component zero_sum_selector = Multiplexer(1, inLenMax - inLenMin);
    for (var idx = inLenMax - 1; idx >= inLenMin; idx--) {
        zeros[idx - inLenMin] = IsZero();
        zeros[idx - inLenMin].in <== out[idx];

        if (idx == inLenMax - 1) {
            zero_sum_selector.inp[idx - inLenMin][0] <== zeros[idx - inLenMin].out;
        } else {
            zero_sum_selector.inp[idx - inLenMin][0] <== zeros[idx - inLenMin].out + zero_sum_selector.inp[idx - inLenMin + 1][0];
        }
    }
    zero_sum_selector.sel <== inLen - inLenMin;
    zero_sum_selector.out[0] === inLenMax - inLen;
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

    component pad0 = Pad0(inLenMin, inLenMax, outLen);
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

    // out in bits
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

template KeccakOrLiteralHex(maxInLen) {
    signal input inLen;
    signal input in[maxInLen];

    signal output outLen;
    // out in hex
    signal output out[64];

    var maxRounds = (maxInLen + 272) \ 272;
    var outBits = log_ceil(maxRounds * 272);
    component pad = ReorderPad101Hex(0, maxInLen, maxRounds * 272, outBits);
    for (var idx = 0; idx < maxInLen; idx++) {
	pad.in[idx] <== in[idx];
    }
    pad.inLen <== inLen;

    signal hashRounds;
    signal roundRem;
    hashRounds <-- (inLen + 272) \ 272;
    roundRem <-- inLen % 272;
    inLen + 272 === hashRounds * 272 + roundRem;

    component roundRange = LessThan(252);
    roundRange.in[0] <== hashRounds;
    roundRange.in[1] <== 272;
    roundRange.out === 1;

    component remRange = LessThan(252);
    remRange.in[0] <== roundRem;
    remRange.in[1] <== 272;
    remRange.out === 1;

    component hash = Keccak256Hex(maxRounds);
    for (var idx = 0; idx < maxRounds * 272; idx++) {
	hash.inPaddedHex[idx] <== pad.out[idx];
    }
    hash.rounds <== hashRounds;

    component isShort = LessEqThan(252);
    isShort.in[0] <== inLen;
    isShort.in[1] <== 62;

    signal unflippedHashHex[64];
    for (var idx = 0; idx < 64; idx++) {
	unflippedHashHex[idx] <== hash.out[4 * idx] + 2 * hash.out[4 * idx + 1] + 4 * hash.out[4 * idx + 2] + 8 * hash.out[4 * idx + 3];
    }

    for (var idx = 0; idx < min(32, maxInLen \ 2); idx++) {
	out[2 * idx] <== isShort.out * (in[2 * idx] - unflippedHashHex[2 * idx + 1]) + unflippedHashHex[2 * idx + 1];
	out[2 * idx + 1] <== isShort.out * (in[2 * idx + 1] - unflippedHashHex[2 * idx]) + unflippedHashHex[2 * idx];
    }
    for (var idx = min(32, maxInLen \ 2); idx < 32; idx++) {
	out[2 * idx] <== (1 - isShort.out) * unflippedHashHex[2 * idx + 1];
	out[2 * idx + 1] <== (1 - isShort.out) * unflippedHashHex[2 * idx];
    }

    outLen <== isShort.out * (inLen - 64) + 64;
}
