pragma circom 2.0.1;

include "../../circuits/ethblockhash.circom";

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
