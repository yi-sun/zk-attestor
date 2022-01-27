import path = require("path");
import { expect, assert } from 'chai';

const { keccak256 } = require("@ethersproject/keccak256");

const circom_tester = require('circom_tester');
const wasm_tester = circom_tester.wasm;

describe("leaf", function() {
    this.timeout(1000 * 1000);

    // runs circom compilation
    let circuit: any;
    before(async function () {
        circuit = await wasm_tester(path.join(__dirname, "circuits", "test_leaf.circom"));
    });

    let leaf1: any = {"keyNibbleHexLen": 60n,
    	     "keyNibbleHexs": [2n, 2n, 2n, 3n, 1n, 3n, 14n, 2n, 8n, 4n, 5n, 9n, 5n, 2n, 8n, 13n, 9n, 2n, 0n, 11n, 6n, 5n, 1n, 1n, 5n, 12n, 1n, 6n, 12n, 0n, 4n, 15n, 3n, 14n, 15n, 12n, 8n, 2n, 10n, 10n, 14n, 13n, 12n, 9n, 7n, 11n, 14n, 5n, 9n, 15n, 3n, 15n, 3n, 7n, 7n, 12n, 0n, 13n, 3n, 15n, 0n, 0n, 0n, 0n],
	      "valueHexs": [2n, 7n, 1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n],
 	      "leafRlpLengthHexLen": 0n,
              "leafPathRlpHexLen": 0n,
	      "leafPathPrefixHexLen": 2n,
 	      "leafPathHexLen": 60n,
	      "leafRlpValueLenHexLen": 2n,
	      "leafValueLenHexLen": 4n,
	      "leafRlpHexs": [14n, 4n, 9n, 15n, 2n, 0n, 2n, 2n, 2n, 3n, 1n, 3n, 14n, 2n, 8n, 4n, 5n, 9n, 5n, 2n, 8n, 13n, 9n, 2n, 0n, 11n, 6n, 5n, 1n, 1n, 5n, 12n, 1n, 6n, 12n, 0n, 4n, 15n, 3n, 14n, 15n, 12n, 8n, 2n, 10n, 10n, 14n, 13n, 12n, 9n, 7n, 11n, 14n, 5n, 9n, 15n, 3n, 15n, 3n, 7n, 7n, 12n, 0n, 13n, 3n, 15n, 8n, 3n, 8n, 2n, 2n, 7n, 1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n],};

    it('Leaf 1', async function () {  
         let witness = await circuit.calculateWitness(leaf1);
	 await circuit.assertOut(witness, {out: 2n});
         await circuit.checkConstraints(witness);
    });
});

describe("branch", function() {
    this.timeout(1000 * 1000);

    // runs circom compilation
    let circuit: any;
    before(async function () {
        circuit = await wasm_tester(path.join(__dirname, "circuits", "test_branch.circom"));
    });

    let branch1: any = {"keyNibble": 2n,
                        "nodeRefHexLen": 64n,    
    		        "nodeRefHexs": [5n, 4n, 12n, 9n, 6n, 11n, 1n, 4n, 12n, 10n, 14n, 11n, 0n, 15n, 2n, 13n, 7n, 13n, 5n, 11n, 7n, 6n, 9n, 8n, 10n, 14n, 0n, 14n, 13n, 3n, 14n, 8n, 6n, 13n, 10n, 5n, 1n, 3n, 14n, 10n, 5n, 10n, 15n, 5n, 6n, 5n, 12n, 13n, 2n, 5n, 12n, 6n, 5n, 13n, 4n, 6n, 1n, 3n, 12n, 11n, 0n, 5n, 1n, 13n],
 			"nodeRlpLengthHexLen": 2n,
		        "nodeValueLenHexLen": [64n, 0n, 64n, 0n, 0n, 0n, 0n, 64n, 0n, 64n, 0n, 0n, 0n, 64n, 0n, 0n],
           		"nodeRlpHexs": [15n, 8n, 11n, 1n, 10n, 0n, 10n, 2n, 11n, 13n, 9n, 9n, 13n, 14n, 7n, 2n, 11n, 12n, 6n, 14n, 9n, 12n, 0n, 9n, 9n, 6n, 6n, 15n, 3n, 5n, 3n, 15n, 11n, 12n, 7n, 4n, 3n, 6n, 10n, 6n, 8n, 12n, 1n, 2n, 4n, 8n, 9n, 9n, 15n, 15n, 3n, 10n, 12n, 11n, 10n, 8n, 2n, 13n, 12n, 2n, 12n, 3n, 9n, 1n, 11n, 5n, 14n, 8n, 6n, 14n, 8n, 0n, 10n, 0n, 5n, 4n, 12n, 9n, 6n, 11n, 1n, 4n, 12n, 10n, 14n, 11n, 0n, 15n, 2n, 13n, 7n, 13n, 5n, 11n, 7n, 6n, 9n, 8n, 10n, 14n, 0n, 14n, 13n, 3n, 14n, 8n, 6n, 13n, 10n, 5n, 1n, 3n, 14n, 10n, 5n, 10n, 15n, 5n, 6n, 5n, 12n, 13n, 2n, 5n, 12n, 6n, 5n, 13n, 4n, 6n, 1n, 3n, 12n, 11n, 0n, 5n, 1n, 13n, 8n, 0n, 8n, 0n, 8n, 0n, 8n, 0n, 10n, 0n, 7n, 8n, 3n, 14n, 13n, 4n, 6n, 0n, 0n, 14n, 4n, 9n, 1n, 4n, 8n, 4n, 7n, 7n, 7n, 10n, 6n, 8n, 8n, 9n, 14n, 0n, 13n, 15n, 9n, 1n, 14n, 7n, 3n, 6n, 11n, 1n, 3n, 14n, 5n, 3n, 10n, 5n, 14n, 6n, 6n, 7n, 6n, 5n, 13n, 8n, 10n, 11n, 15n, 13n, 1n, 9n, 8n, 7n, 2n, 5n, 0n, 0n, 5n, 9n, 8n, 0n, 10n, 0n, 13n, 13n, 3n, 10n, 11n, 2n, 11n, 7n, 13n, 1n, 9n, 13n, 2n, 2n, 8n, 14n, 11n, 0n, 10n, 9n, 13n, 4n, 10n, 11n, 9n, 6n, 4n, 4n, 2n, 10n, 12n, 4n, 15n, 13n, 2n, 13n, 10n, 3n, 13n, 11n, 13n, 8n, 1n, 2n, 1n, 7n, 0n, 9n, 9n, 2n, 13n, 0n, 14n, 8n, 15n, 11n, 4n, 8n, 7n, 1n, 3n, 2n, 15n, 0n, 8n, 0n, 8n, 0n, 8n, 0n, 10n, 0n, 8n, 15n, 10n, 13n, 6n, 6n, 13n, 0n, 4n, 8n, 2n, 3n, 15n, 10n, 15n, 13n, 10n, 1n, 13n, 1n, 5n, 8n, 3n, 11n, 1n, 11n, 1n, 4n, 4n, 0n, 2n, 3n, 10n, 6n, 6n, 7n, 5n, 14n, 7n, 14n, 6n, 4n, 5n, 2n, 12n, 11n, 1n, 12n, 6n, 2n, 10n, 13n, 8n, 15n, 10n, 13n, 6n, 7n, 9n, 3n, 10n, 15n, 10n, 7n, 8n, 0n, 8n, 0n, 8n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]};

    it('Branch 1', async function () {  
         let witness = await circuit.calculateWitness(branch1);
	 await circuit.assertOut(witness, {out: 2n});
         await circuit.checkConstraints(witness);
    });
});
