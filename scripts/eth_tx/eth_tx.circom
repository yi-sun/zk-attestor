pragma circom 2.0.2;

include "../../circuits/eth.circom";
			
component main {public [blockHash,
			index
		       ]} = EthTransactionProof(6, 500, 15000);
