pragma circom 2.0.2;

include "../../circuits/mpt.circom";

component main {public [
    keyNibbleHexLen,
    keyNibbleHexs,
    valueHexs,
    leafRlpLengthHexLen,
    leafPathRlpHexLen,
    leafPathPrefixHexLen,
    leafPathHexLen,
    leafRlpValueLenHexLen,
    leafValueLenHexLen,
    leafRlpHexs
]} = LeafCheck(64, 66);
