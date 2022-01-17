pragma circom 2.0.1;

include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/multiplexer.circom";

include "./keccak2.circom";
include "./vocdoni-keccak/keccak.circom";

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
        log(idx);
        log(out[idx]);
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
    component ableqs[aMax + bMax];
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

    component inLess[inLenMax];
    for (var idx = 0; idx < inLenMax; idx++) {
        inLess[idx] = LessThan(outLenBits);
        inLess[idx].in[0] <== idx;
        inLess[idx].in[1] <== inLen;
    }

    component eq[outLen];
    for (var idx = 0; idx < inLenMax + 1; idx++) {
        eq[idx] = IsEqual();
        eq[idx].in[0] <== idx;
        eq[idx].in[1] <== inLen;
    }

    for (var idx = 0; idx < inLenMin; idx++) {
        out[idx] <== in[idx];
    }
    // out[idx] = inLess[idx] * in[idx]
    for (var idx = inLenMin; idx < inLenMax; idx++) {
        out[idx] <== inLess[idx].out * in[idx] + eq[idx].out;
    }
    out[inLenMax] <== eq[inLenMax].out;
    for (var idx = inLenMax + 1; idx < outLen - 1; idx++) {
        out[idx] <== 0;
    }
    out[outLen - 1] <== 1;    
}

template EthBlockHash() {
    signal input rlpPrefixBits[32];
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

    component concat = VarConcat4(3656, 3688, 12,
                                  40, 80, 7,
                                  40, 304, 9,
                                  336, 384, 9);
    concat.aLen <== 3656 + numberRlpBitLen;
    concat.bLen <== 40 + gasUsedRlpBitLen;
    concat.cLen <== 40 + extraDataRlpBitLen;
    concat.dLen <== 336 + basefeeRlpBitLen;

    var curr_idx = 0;
    for (var idx = 0; idx < 32; idx++) {
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
    component pad4 = Pad101(4072, 4350, 4352, 13);
    component pad5 = Pad101(4351, 4456, 5440, 13);
    for (var idx = 0; idx < 4350; idx++) {
        pad4.in[idx] <== concat.out[idx];
    }
    pad4.inLen <== concat.outLen - leq.out * concat.outLen;

    for (var idx = 0; idx < 4456; idx++) {
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

//component main {public [a, b, c, d, aLen, bLen, cLen, dLen]} = VarConcat4(2, 5, 3,
//                                                                          2, 5, 3,
//                                                                          1, 3, 2,
//                                                                          3, 3, 2);

component main {public [rlpPrefixBits,
                        parentHashRlpBits,
                        ommersHashRlpBits,
                        beneficiaryRlpBits,
                        stateRootRlpBits,
                        transactionsRootRlpBits,
                        receiptsRootRlpBits,
                        logsBloomRlpBits,
                        difficultyRlpBits,
                        numberRlpBits,
                        gasLimitRlpBits,
                        gasUsedRlpBits,
                        timestampRlpBits,
                        extraDataRlpBits,
                        mixHashRlpBits,
                        nonceRlpBits,
                        basefeeRlpBits,
                        numberRlpBitLen,
                        gasUsedRlpBitLen,
                        extraDataRlpBitLen,
                        basefeeRlpBitLen]} = EthBlockHash();
