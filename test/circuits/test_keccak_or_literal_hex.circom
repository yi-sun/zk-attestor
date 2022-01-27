pragma circom 2.0.1;

include "../../circuits/keccak.circom";

component main {public [inLen, in]} = KeccakOrLiteralHex(1000);
