pragma circom 2.0.1;

include "../../circuits/keccak2.circom";

component main {public [in]} = Keccak256NoPad(4352);
