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

function max(a, b) {
    if (a > b) {
        return a;
    }
    return b;
}

function max3(a, b, c) {
    return max(a, max(b, c));
}

function max4(a, b, c, d) {
    return max(a, max(b, max(c, d)));
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

template Pad101(inLenMin, inLenMax, outLen, outLenBits) {
    assert((2 ** outLenBits) >= outLen);
    assert(inLenMax + 2 <= outLen);
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

    component eq[inLenMax + 1 - inLenMin];
    for (var idx = 0; idx < inLenMax + 1 - inLenMin; idx++) {
        eq[idx] = IsEqual();
        eq[idx].in[0] <== idx + inLenMin;
        eq[idx].in[1] <== inLen;
    }

    for (var idx = 0; idx < inLenMin; idx++) {
        out[idx] <== in[idx];
    }
    for (var idx = inLenMin; idx < inLenMax; idx++) {
        out[idx] <== inLess[idx - inLenMin].out * in[idx] + eq[idx - inLenMin].out;
    }
    out[inLenMax] <== eq[inLenMax - inLenMin].out;
    for (var idx = inLenMax + 1; idx < outLen - 1; idx++) {
        out[idx] <== 0;
    }
    out[outLen - 1] <== 1;    
}
