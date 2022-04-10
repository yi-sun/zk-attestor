pragma circom 2.0.2;

include "../../circuits/eth.circom";
			
component main {public [blockHash,
			address,
		        slot
		       ]} = EthAddressStorageProof(8, 8);
