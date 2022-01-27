pragma circom 2.0.1;

include "../../circuits/keccak.circom";

component main {public [in, inLen]} = Pad0(4, 6, 8, 3);
