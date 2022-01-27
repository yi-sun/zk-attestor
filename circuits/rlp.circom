pragma circom 2.0.1;

include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/multiplexer.circom";

include "./keccak.circom";

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
