pragma circom 2.0.2;

include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/multiplexer.circom";

// selects indices [start, end)
template SubArray(nIn, maxSelect, nInBits) {
    signal input in[nIn];
    signal input start;
    signal input end;

    signal output out[maxSelect];
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

    component n2b = Num2Bits(nInBits);
    n2b.in <== start;

    signal shifts[nInBits][nIn];
    for (var idx = 0; idx < nInBits; idx++) {
        for (var j = 0; j < nIn; j++) {
            if (idx == 0) {
                shifts[idx][j] <== n2b.out[idx] * (in[(j + (1 << idx)) % nIn] - in[j]) + in[j];
            } else {
                shifts[idx][j] <== n2b.out[idx] * (shifts[idx - 1][(j + (1 << idx)) % nIn] - shifts[idx - 1][j]) + shifts[idx - 1][j];            
            }
        }
    }

    for (var idx = 0; idx < maxSelect; idx++) {
        out[idx] <== shifts[nInBits - 1][idx];
    }

    log(outLen);
    for (var idx = 0; idx < maxSelect; idx++) {
	log(out[idx]);
    }
}

template ArrayEq(nIn) {
    signal input a[nIn];
    signal input b[nIn];
    signal input inLen;

    signal output out;

    log(333333300002);
    log(nIn);
    log(inLen);

    for (var idx = 0; idx < nIn; idx++) {
	log(a[idx]);
    }
    for (var idx = 0; idx < nIn; idx++) {
	log(b[idx]);
    }    
    
    component leq = LessEqThan(252);
    leq.in[0] <== inLen;
    leq.in[1] <== nIn;
    leq.out === 1;

    component eq[nIn];
    signal matchSum[nIn];

    for (var idx = 0; idx < nIn; idx++) {
        eq[idx] = IsEqual();
        eq[idx].in[0] <== a[idx];
        eq[idx].in[1] <== b[idx];

        if (idx == 0) {
            matchSum[idx] <== eq[idx].out;
        } else {
            matchSum[idx] <== matchSum[idx - 1] + eq[idx].out;
        }
    }

    component matchChooser = Multiplexer(1, nIn + 1);
    matchChooser.inp[0][0] <== 0;
    for (var idx = 0; idx < nIn; idx++) {
        matchChooser.inp[idx + 1][0] <== matchSum[idx];
    }
    matchChooser.sel <== inLen;

    component matchCheck = IsEqual();
    matchCheck.in[0] <== matchChooser.out[0];
    matchCheck.in[1] <== inLen;

    out <== matchCheck.out;

    log(out);
}
