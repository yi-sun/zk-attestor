pragma circom 2.0.1;

include "./ethblockhash.circom";

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

component main {public [rlpPrefixBits,
                        parentHashRlpBits,
                        ommersHashRlpBits,
                        beneficiaryRlpBits,
                        stateRootRlpBits,
                        transactionsRootRlpBits,
                        receiptsRootRlpBits,
                        logsBloomRlpBits,
                        difficultyRlpBits,
			suffixRlpBits,
                        suffixRlpBitLen]} = EthBlockHashMin();
