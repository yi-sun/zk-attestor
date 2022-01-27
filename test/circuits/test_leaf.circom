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
]} = LeafFixedKeyHexLen(64, 66);
