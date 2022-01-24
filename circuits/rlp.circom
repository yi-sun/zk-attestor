pragma circom 2.0.1;

include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/multiplexer.circom";

template MultiplexerUnsafe(wIn, nIn) {
    signal input inp[nIn][wIn];
    signal input sel;
    signal output out[wIn];
    signal output success;
    
    component dec = Decoder(nIn);
    component ep[wIn];

    for (var k=0; k<wIn; k++) {
        ep[k] = EscalarProduct(nIn);
    }

    sel ==> dec.inp;
    for (var j=0; j<wIn; j++) {
        for (var k=0; k<nIn; k++) {
            inp[k][j] ==> ep[j].in1[k];
            dec.out[k] ==> ep[j].in2[k];
        }
        ep[j].out ==> out[j];
    }
    success <== dec.success;
}

template VarConcatTest(aMax, bMax, aMaxBits, bMaxBits) {
    signal input a[aMax];
    signal input b[bMax];

    signal input aLen;
    signal input bLen;

    signal output out[aMax + bMax];
    signal output outLen;

    component aVal = LessEqThan(aMaxBits);
    aVal.in[0] <== aLen;
    aVal.in[1] <== aMax;
    aVal.out === 1;

    component aBitsVal = Num2Bits(aMaxBits);
    aBitsVal.in <== aMax;
    
    component bVal = LessEqThan(bMaxBits);
    bVal.in[0] <== bLen;
    bVal.in[1] <== bMax;
    bVal.out === 1;

    component bBitsVal = Num2Bits(bMaxBits);
    bBitsVal.in <== bMax;

    component aleqs[aMax];
    component ableqs[aMax + bMax];
    for (var idx = 0; idx < aMax; idx++) {
        aleqs[idx] = LessEqThan(aMaxBits);
        aleqs[idx].in[0] <== idx + 1;
        aleqs[idx].in[1] <== aLen;
    }
    for (var idx = 0; idx < aMax + bMax; idx++) {
        ableqs[idx] = LessEqThan(max(aMaxBits, bMaxBits) + 1);
        ableqs[idx].in[0] <== idx + 1;
        ableqs[idx].in[1] <== aLen + bLen;
    }
    component bChoice[aMax + bMax];
    for (var idx = 0; idx < aMax + bMax; idx++) {
        bChoice[idx] = MultiplexerUnsafe(1, bMax);
        for (var j = 0; j < bMax; j++) {
            bChoice[idx].inp[j][0] <== b[j];
        }
        bChoice[idx].sel <== idx - aLen;
    }
    signal bChoiceVal[aMax + bMax];
    for (var idx = 0; idx < aMax + bMax; idx++) {
        bChoiceVal[idx] <== ableqs[idx].out * bChoice[idx].out[0];
    }

    // out[idx] = aleqs[idx] * a[idx] + (1 - aleqs[idx]) * ableqs[idx] * bChoice[idx].out[0]
    outLen <== aLen + bLen;
    for (var idx = 0; idx < aMax + bMax; idx++) {
        if (idx < aMax) {
            out[idx] <== aleqs[idx].out * (a[idx] - bChoiceVal[idx]) + bChoiceVal[idx];
        } else {
            out[idx] <== bChoiceVal[idx];
        }
    }
}

template VarConcat2(aMin, aMax, aMaxBits, bMin, bMax, bMaxBits) {
    assert((2 ** aMaxBits) >= aMax);
    assert((2 ** bMaxBits) >= bMax);
    signal input a[aMax];
    signal input b[bMax];

    signal input aLen;
    signal input bLen;

    signal output out[aMax + bMax];
    signal output outLen;

    component aVal = LessEqThan(aMaxBits);
    aVal.in[0] <== aLen;
    aVal.in[1] <== aMax;
    aVal.out === 1;

    component bVal = LessEqThan(bMaxBits);
    bVal.in[0] <== bLen;
    bVal.in[1] <== bMax;
    bVal.out === 1;

    component aleqs[aMax - aMin];
    component ableqs[aMax + bMax - aMin];
    for (var idx = 0; idx < aMax - aMin; idx++) {
        aleqs[idx] = LessEqThan(aMaxBits);
        aleqs[idx].in[0] <== aMin + idx + 1;
        aleqs[idx].in[1] <== aLen;
    }
    
    for (var idx = 0; idx < aMax + bMax - aMin; idx++) {
        ableqs[idx] = LessEqThan(max(aMaxBits, bMaxBits) + 1);
        ableqs[idx].in[0] <== aMin + idx + 1;
        ableqs[idx].in[1] <== aLen + bLen;
    }
    component bChoice[aMax + bMax - aMin];
    for (var idx = 0; idx < aMax + bMax - aMin; idx++) {
        bChoice[idx] = MultiplexerUnsafe(1, bMax);
        for (var j = 0; j < bMax; j++) {
            bChoice[idx].inp[j][0] <== b[j];
        }
        bChoice[idx].sel <== aMin + idx - aLen;
    }
    signal bChoiceVal[aMax + bMax - aMin];
    for (var idx = 0; idx < aMax + bMax - aMin; idx++) {
        bChoiceVal[idx] <== ableqs[idx].out * bChoice[idx].out[0];
    }

    // out[idx] = aleqs[idx] * a[idx] + (1 - aleqs[idx]) * ableqs[idx] * bChoice[idx].out[0]
    outLen <== aLen + bLen;
    for (var idx = 0; idx < aMin; idx++) {
        out[idx] <== a[idx];
    }
    for (var idx = aMin; idx < aMax; idx++) {
        out[idx] <== aleqs[idx - aMin].out * (a[idx] - bChoiceVal[idx - aMin]) + bChoiceVal[idx - aMin];
    }
    for (var idx = aMax; idx < aMax + bMax; idx++) {
        out[idx] <== bChoiceVal[idx - aMin];
    }
}

template VarConcat4(aMin, aMax, aMaxBits, bMin, bMax, bMaxBits, cMin, cMax, cMaxBits, dMin, dMax, dMaxBits) {
    signal input a[aMax];
    signal input b[bMax];
    signal input c[cMax];
    signal input d[dMax];

    signal input aLen;
    signal input bLen;
    signal input cLen;
    signal input dLen;

    signal output out[aMax + bMax + cMax + dMax];
    signal output outLen;

    component concat1 = VarConcat2(aMin, aMax, aMaxBits, bMin, bMax, bMaxBits);
    concat1.aLen <== aLen;
    concat1.bLen <== bLen;
    for (var idx = 0; idx < aMax; idx++) {
        concat1.a[idx] <== a[idx];
    }
    for (var idx = 0; idx < bMax; idx++) {
        concat1.b[idx] <== b[idx];
    }

    component concat2 = VarConcat2(cMin, cMax, cMaxBits, dMin, dMax, dMaxBits);
    concat2.aLen <== cLen;
    concat2.bLen <== dLen;
    for (var idx = 0; idx < cMax; idx++) {
        concat2.a[idx] <== c[idx];
    }
    for (var idx = 0; idx < dMax; idx++) {
        concat2.b[idx] <== d[idx];
    }

    component concat = VarConcat2(aMin + bMin, aMax + bMax, max(aMaxBits, bMaxBits) + 1,
                                  cMin + dMin, cMax + dMax, max(cMaxBits, dMaxBits) + 1);
    concat.aLen <== aLen + bLen;
    concat.bLen <== cLen + dLen;
    for (var idx = 0; idx < aMax + bMax; idx++) {
        concat.a[idx] <== concat1.out[idx];
    }
    for (var idx = 0; idx < cMax + dMax; idx++) {
        concat.b[idx] <== concat2.out[idx];
    }

    outLen <== aLen + bLen + cLen + dLen;
    for (var idx = 0; idx < aMax + bMax + cMax + dMax; idx++) {
        out[idx] <== concat.out[idx];
    }
}

// selects indices [start, end)
template SubArray(nIn, maxSelect, nInBits) {
    signal input in[nIn];
    signal input start;
    signal input end;

    signal output out[nIn];
    signal output outLen;

    component lt1 = LessEqThan(nInBits);
    lt1.in[0] <== start;
    lt1.in[1] <== end;
    lt1.out === 1;
    
    component lt2 = LessEqThan(nInBits);
    lt2.in[0] <== end;
    lt2.in[1] <== nIn;
    lt2.out === 1;

    component lt3 = LessEqThan(nInBits);
    lt3.in[0] <== end - start;
    lt3.in[1] <== maxSelect;
    lt3.out === 1;

    outLen <== end - start;
    component selectors[maxSelect];
    for (var idx = 0; idx < maxSelect; idx++) {
	selectors[idx] = MultiplexerUnsafe(1, nIn);
	for (var i = 0; i < nIn; i++) {
	    selectors[idx].inp[i][0] <== in[i];
	}
	selectors[idx].sel <== start + idx;
	out[idx] <== selectors[idx].out[0];
    }
}

template ArrayEq(nIn) {
    signal input a[nIn];
    signal input b[nIn];
    signal input inLen;

    signal output out;

    component leq = LessEqThan(252);
    leq.in[0] <== inLen;
    leq.in[1] <== nIn;
    leq.out === 1;

    component eq[nIn];
    component idxLeq[nIn];
    signal match[nIn];
    signal ors[nIn - 1];
    
    for (var idx = 0; idx < nIn; idx++) {
	eq[idx] = IsEqual();
	eq[idx].in[0] <== a[idx];
	eq[idx].in[1] <== b[idx];
	idxLeq[idx] = LessEqThan(252);
	idxLeq[idx].in[0] <== inLen;
	idxLeq[idx].in[1] <== idx;

	if (idx == 0) {
	    match[idx] <== eq[idx].out + idxLeq[idx].out - eq[idx].out * idxLeq[idx].out;
	} else {
	    ors[idx - 1] <== eq[idx].out + idxLeq[idx].out - eq[idx].out * idxLeq[idx].out;
	    match[idx] <== match[idx - 1] * ors[idx - 1];
	}
    }
    out <== match[nIn - 1];
}

function min(a, b) {
    if (a < b) {
	return a;
    }
    return b;
}

template KeccakOrLiteralHex(maxInLen) {
    signal input inLen;
    signal input in[maxInLen];

    signal output outLen;
    signal output out[64];

    var maxRounds = (maxInLen + 272) \ 272;
    component pad = ReorderPad101Hex(0, maxInLen, maxRounds * 272, 252);
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

    component isShort = LessThan(252);
    isShort.in[0] <== inLen;
    isShort.in[1] <== 63;

    signal unflippedHashHex[64];
    for (var idx = 0; idx < 64; idx++) {
	unflippedHashHex[idx] <== hash.out[4 * idx] + 2 * hash.out[4 * idx + 1] + 4 * hash.out[4 * idx + 2] + 8 * hash.out[4 * idx + 3];
    }

    for (var idx = 0; idx < min(32, maxInLen \ 2); idx++) {
	out[2 * idx] <== isShort.out * (in[2 * idx] - unflippedHashHex[2 * idx + 1]) + unflippedHashHex[2 * idx + 1];
	out[2 * idx + 1] <== isShort.out * (in[2 * idx + 1] - unflippedHashHex[2 * idx]) + unflippedHashHex[2 * idx];
    }
    for (var idx = min(32, maxInLen \ 2); idx < 32; idx++) {
	out[2 * idx] <== unflippedHashHex[2 * idx + 1];
	out[2 * idx + 1] <== unflippedHashHex[2 * idx];
    }
    outLen <== isShort.out * (inLen - 64) + 64;
}
