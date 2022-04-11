pragma circom 2.0.2;

include "../../circuits/eth2.circom";
			
component main {public [blockHash,
			address,
		        slot
		       ]} = EthAddressStorageProof2(8, 8);
