pragma circom 2.0.2;

include "../../circuits/mpt.circom";

component main {public [
    keyHexLen,
    keyHexs,
    valueHexLen,
    valueHexs,
    rootHashHexs,
    leafRlpLengthHexLen,
    leafPathRlpHexLen,
    leafPathPrefixHexLen,
    leafPathHexLen,
    leafRlpValueLenHexLen,
    leafValueLenHexLen,
    leafRlpHexs,
    terminalBranchRlpLengthHexLen,
    terminalBranchNodeRefHexLen,
    terminalBranchVtRlpLenHexLen,
    terminalBranchVtValueHexLen,
    terminalBranchRlpHexs,
    nodeRlpLengthHexLen,    
    nodePathRlpHexLen,
    nodePathPrefixHexLen,
    nodePathHexLen,    
    nodeRefHexLen,
    nodeVtRlpLenHexLen,
    nodeVtValueHexLen,    
    nodeRlpHexs,
    nodeTypes,
    depth
]} = MPTInclusion(6, 64, 1916);
