import path = require("path");
import { expect, assert } from 'chai';

const { keccak256 } = require("@ethersproject/keccak256");

const circom_tester = require('circom_tester');
const wasm_tester = circom_tester.wasm;

describe("keccak256 1 round", function() {
    this.timeout(1000 * 1000);

    // runs circom compilation
    let circuit: any;
    before(async function () {
        circuit = await wasm_tester(path.join(__dirname, "circuits", "test_keccak_round1.circom"));
    });

    it("block hash", async () => {
        let witness = await circuit.calculateWitness({"in": input});
        for (var idx = 0; idx < 256; idx++) {
            expect(witness[idx + 1]).to.equal(output[idx]);
        }
        await circuit.checkConstraints(witness);
    });
});
