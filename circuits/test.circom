pragma circom 2.0.1;

include "./ethblockhash.circom";
include "./mpt.circom";

//component main {public [a, b, c, d, aLen, bLen, cLen, dLen]} = VarConcat4(2, 5, 3,
//                                                                          2, 5, 3,
//                                                                          1, 3, 2,
//                                                                          3, 3, 2);

//component main {public [rlpPrefixBits,
//                        parentHashRlpBits,
//                        ommersHashRlpBits,
//                        beneficiaryRlpBits,
//                        stateRootRlpBits,
//                        transactionsRootRlpBits,
//                        receiptsRootRlpBits,
//                        logsBloomRlpBits,
//                        difficultyRlpBits,
//                        numberRlpBits,
//                        gasLimitRlpBits,
//                        gasUsedRlpBits,
//                        timestampRlpBits,
//                        extraDataRlpBits,
//                        mixHashRlpBits,
//                        nonceRlpBits,
//                        basefeeRlpBits,
//                        numberRlpBitLen,
//                        gasUsedRlpBitLen,
//                        extraDataRlpBitLen,
//                        basefeeRlpBitLen]} = EthBlockHash();

// component main {public [rlpPrefixBits,
//                        parentHashRlpBits,
//                        ommersHashRlpBits,
//                        beneficiaryRlpBits,
//                        stateRootRlpBits,
//                        transactionsRootRlpBits,
//                        receiptsRootRlpBits,
//                        logsBloomRlpBits,
//                        difficultyRlpBits,
//                        suffixRlpBits,
//                        suffixRlpBitLen]} = EthBlockHashMin();

//component main {public [
//    keyNibbleHexLen,
//    keyNibbleHexs,
//    valueHexs,
//    leafRlpLengthHexLen,
//    leafPathRlpHexLen,
//    leafPathPrefixHexLen,
//    leafPathHexLen,
//    leafRlpValueLenHexLen,
//    leafValueLenHexLen,
//    leafRlpHexs
//]} = LeafFixedKeyHexLen(64, 66);

//component main {public [
//    keyNibble,
//    nodeRefHexLen,
//    nodeRefHexs,
//    nodeRlpLengthHexLen,
//    nodeValueLenHexLen,
//    nodeRlpHexs
//]} = BranchFixedKeyHexLen(64);
			
// component main {public [rlpPrefixHexs,
//                        parentHashRlpHexs,
//                       ommersHashRlpHexs,
//                        beneficiaryRlpHexs,
//                        stateRootRlpHexs,
//                        transactionsRootRlpHexs,
//                        receiptsRootRlpHexs,
//                        logsBloomRlpHexs,
//                        difficultyRlpHexs,
//                        suffixRlpHexs,
//                        suffixRlpHexLen]} = EthBlockHashHex();


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
    nodeTypes
]} = MPTInclusionFixedKeyHexLen(7, 64, 228);
