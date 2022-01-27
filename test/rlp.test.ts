import path = require("path");
import { expect, assert } from 'chai';

const { keccak256 } = require("@ethersproject/keccak256");

const circom_tester = require('circom_tester');
const wasm_tester = circom_tester.wasm;

describe("subarray", function() {
    this.timeout(1000 * 1000);

    // runs circom compilation
    let circuit: any;
    before(async function () {
        circuit = await wasm_tester(path.join(__dirname, "circuits", "test_subarray.circom"));
    });

    var test_cases: Array<[bigint[], bigint, bigint, bigint[], bigint]> = [];
    test_cases.push([[0n, 1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n], 1n, 1n, [1n, 2n, 3n, 4n], 0n]);
    test_cases.push([[0n, 1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n], 1n, 2n, [1n, 2n, 3n, 4n], 1n]);
    test_cases.push([[0n, 1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n], 1n, 3n, [1n, 2n, 3n, 4n], 2n]);
    test_cases.push([[0n, 1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n], 1n, 4n, [1n, 2n, 3n, 4n], 3n]);
    test_cases.push([[0n, 1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n], 1n, 5n, [1n, 2n, 3n, 4n], 4n]);
    test_cases.push([[0n, 1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n], 2n, 3n, [2n, 3n, 4n, 5n], 1n]);
    test_cases.push([[0n, 1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n], 2n, 4n, [2n, 3n, 4n, 5n], 2n]);
    test_cases.push([[0n, 1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n], 2n, 5n, [2n, 3n, 4n, 5n], 3n]);	

    var test_one_case = function (x: [bigint[], bigint, bigint, bigint[], bigint]) {
        const input: bigint[] = x[0];
	const start: bigint = x[1];
	const end: bigint = x[2];
	const out: bigint[] = x[3];
        const outLen: bigint = x[4];

        it('start: ' + start + ' end: ' + end, async function () {  
             let witness = await circuit.calculateWitness({"in": input, "start": start, "end": end});

	     await circuit.assertOut(witness, {outLen: outLen, out: out});
             await circuit.checkConstraints(witness);
         });
    }

    test_cases.forEach(test_one_case);
});

describe("arrayeq", function() {
    this.timeout(1000 * 1000);

    // runs circom compilation
    let circuit: any;
    before(async function () {
        circuit = await wasm_tester(path.join(__dirname, "circuits", "test_arrayeq.circom"));
    });

    var test_cases: Array<[bigint[], bigint[], bigint, bigint]> = [];
    test_cases.push([[0n, 1n, 2n, 3n], [0n, 1n, 2n, 3n], 4n, 1n]);
    test_cases.push([[0n, 1n, 2n, 3n], [0n, 2n, 2n, 3n], 4n, 0n]);
    test_cases.push([[0n, 1n, 2n, 3n], [1n, 1n, 2n, 3n], 4n, 0n]);
    test_cases.push([[0n, 1n, 2n, 3n], [1n, 1n, 1n, 3n], 4n, 0n]);
    test_cases.push([[0n, 1n, 2n, 3n], [0n, 1n, 2n, 1n], 4n, 0n]);
    test_cases.push([[0n, 1n, 2n, 3n], [0n, 1n, 3n, 1n], 2n, 1n]);
    test_cases.push([[0n, 1n, 2n, 3n], [0n, 0n, 2n, 1n], 1n, 1n]);

    var test_one_case = function (x: [bigint[], bigint[], bigint, bigint]) {
        const a: bigint[] = x[0];
	const b: bigint[] = x[1];
	const inLen: bigint = x[2];
	const out: bigint = x[3];

        it('a: ' + a + ' b: ' + b + ' inLen: ' + inLen, async function () {  
             let witness = await circuit.calculateWitness({"a": a, "b": b, "inLen": inLen});

	     await circuit.assertOut(witness, {out: out});
             await circuit.checkConstraints(witness);
         });
    }

    test_cases.forEach(test_one_case);
});