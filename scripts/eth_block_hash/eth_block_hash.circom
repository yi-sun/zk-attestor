pragma circom 2.0.2;

include "../../circuits/eth.circom";
			
component main {public [rlpPrefixHexs,
                        parentHashRlpHexs,
			ommersHashRlpHexs,
                        beneficiaryRlpHexs,
                        stateRootRlpHexs,
                        transactionsRootRlpHexs,
                        receiptsRootRlpHexs,
                        logsBloomRlpHexs,
                        difficultyRlpHexs,
                        suffixRlpHexs,
                        suffixRlpHexLen]} = EthBlockHashHex();
