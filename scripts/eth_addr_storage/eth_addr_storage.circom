pragma circom 2.0.2;

include "../../circuits/eth.circom";
			
component main {public [blockHashHexs,
			addressHexs,
		        slotHexs
		       ]} = EthAddressStorageProof(8, 7);
