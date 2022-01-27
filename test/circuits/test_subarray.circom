pragma circom 2.0.1;

include "../../circuits/rlp.circom";

component main {public [in, start, end]} = SubArray(10, 4, 4);
