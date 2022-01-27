pragma circom 2.0.1;

include "../../circuits/keccak.circom";

component main {public [in, inLen]} = ReorderPad101Hex(4, 6, 8, 3);
