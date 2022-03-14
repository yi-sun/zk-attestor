pragma circom 2.0.2;

include "../../circuits/mpt.circom";

component main {public [
    keyHexs,
    valueHexs,
    rootHashHexs,
    leafRlpLengthHexLen,
    leafPathRlpLengthHexLen,
    leafPathPrefixHexLen,
    leafPathHexLen,
    leafValueRlpLengthHexLen,
    leafValueHexLen,
    leafRlpHexs,
    nodeRlpLengthHexLen,    
    nodePathRlpLengthHexLen,
    nodePathPrefixHexLen,
    nodePathHexLen,    
    nodeRefHexLen,
    nodeRlpHexs,
    nodeTypes,
    depth
]} = MPTInclusionFixedKeyHexLen(7, 64, 114);
