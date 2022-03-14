pragma circom 2.0.2;

include "../../circuits/mpt.circom";

component main {public [
    keyNibbleHexLen,
    keyNibbleHexs,
    valueHexs,
    leafRlpLengthHexLen,
    leafPathRlpLengthHexLen,
    leafPathPrefixHexLen,
    leafPathHexLen,
    leafValueRlpLengthHexLen,
    leafValueHexLen,
    leafRlpHexs
]} = LeafCheck(64, 66);
