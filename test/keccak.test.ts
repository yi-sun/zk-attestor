import path = require("path");
import { expect, assert } from 'chai';

const { keccak256 } = require("@ethersproject/keccak256");

const circom_tester = require('circom_tester');
const wasm_tester = circom_tester.wasm;

describe("keccak256literalorhex 550 literal", function() {
    this.timeout(1000 * 1000);

    // runs circom compilation
    let circuit: any;
    before(async function () {
        circuit = await wasm_tester(path.join(__dirname, "circuits", "test_keccak_or_literal_hex.circom"));
    });

    var test_cases: Array<[bigint, bigint[], bigint, bigint[]]> = [];
    for (var len = 1n; len < 63; len++) {
        var input: bigint[] = [];
        var output: bigint[] = [];	
	for (var idx = 0n; idx < len; idx++) {
	    input.push(idx % 16n);
	    output.push(idx % 16n);	    
	}
	for (var idx = len; idx < 550; idx++) {
	    input.push(0n);
	}
	for (var idx = len; idx < 64; idx++) {
	    output.push(0n);
	}
    	test_cases.push([len, input, len, output]);
    }

    var test_literal = function (x: [bigint, bigint[], bigint, bigint[]]) {
        const inLen: bigint = x[0];
	const inp: bigint[] = x[1];
	const outLen: bigint = x[2];
	const out: bigint[] = x[3];

        it('literal length: ' + inLen, async function () {  
             let witness = await circuit.calculateWitness({"inLen": inLen, "in": inp});

	     await circuit.assertOut(witness, {outLen: outLen, out: out});
             await circuit.checkConstraints(witness);
         });
    }

    test_cases.forEach(test_literal);
});

describe("keccak256orliteralhex 550 hash", function() {
    this.timeout(1000 * 1000);

    // runs circom compilation
    let circuit: any;
    before(async function () {
        circuit = await wasm_tester(path.join(__dirname, "circuits", "test_keccak_or_literal_hex.circom"));
    });

    var test_cases: Array<[bigint, bigint[], bigint, bigint[]]> = [];
    for (var len = 64n; len < 550; len += 10n) {
        var input: bigint[] = [];
        var output: bigint[] = [];	
	for (var idx = 0n; idx < len; idx++) {
	    input.push(idx % 16n);
	}
	for (var idx = len; idx < 550; idx++) {
	    input.push(0n);
	}

	var hexString: string = "0x";
	for (var i = 0; i < len; i++) {
	    hexString = hexString + input[i].toString(16);
	}
	let hash: any = keccak256(hexString);
	for (var i = 2; i < 66; i++) {
	    output.push(BigInt(parseInt(hash.charAt(i), 16)));
	}
    	test_cases.push([len, input, 64n, output]);
    }

    var test_literal = function (x: [bigint, bigint[], bigint, bigint[]]) {
        const inLen: bigint = x[0];
	const inp: bigint[] = x[1];
	const outLen: bigint = x[2];
	const out: bigint[] = x[3];

        it('literal length: ' + inLen, async function () {  
             let witness = await circuit.calculateWitness({"inLen": inLen, "in": inp});

	     await circuit.assertOut(witness, {outLen: outLen, out: out});
             await circuit.checkConstraints(witness);
         });
    }

    test_cases.forEach(test_literal);
});
