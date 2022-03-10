pragma circom 2.0.2;

include "../../circuits/mpt.circom";

component main {public [
    keyHexs,
    valueHexs,
    rootHashHexs,
    leafRlpLengthHexLen,
    leafPathRlpHexLen,
    leafPathPrefixHexLen,
    leafPathHexLen,
    leafRlpValueLenHexLen,
    leafValueLenHexLen,
    leafRlpHexs,
    nodeRlpLengthHexLen,    
    nodePathRlpHexLen,
    nodePathPrefixHexLen,
    nodePathHexLen,    
    nodeRefHexLen,
    nodeRlpHexs,
    nodeTypes,
    depth
]} = MPTInclusionFixedKeyHexLen(8, 64, 114);
