pragma circom 2.0.2;

include "../../circuits/mpt.circom";

component main {public [
    keyHexLen,
    keyHexs,
    valueHexLen,
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
]} = MPTInclusionNoBranchTermination(5, 6, 1500);
