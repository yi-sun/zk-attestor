pragma circom 2.0.2;

include "../../circuits/mpt.circom";

component main {public [
    keyNibble,
    nodeRefHexLen,
    nodeRefHexs,
    nodeRlpLengthHexLen,
    nodeValueHexLen,
    nodeRlpHexs
]} = EmptyVtBranchCheck(64);
