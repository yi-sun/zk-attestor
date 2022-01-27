pragma circom 2.0.1;

include "../../circuits/keccak.circom";

component main {public [inPaddedHex, rounds]} = Keccak256Hex(1);
