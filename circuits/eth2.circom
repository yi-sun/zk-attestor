pragma circom 2.0.2;

include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/multiplexer.circom";

include "./keccak.circom";
include "./rlp.circom";
include "./mpt2.circom";

template EthBlockHashHex2() {
    signal input blockRlpHexs[1112];

    signal output out;
    signal output blockHashHexs[64];

    signal output numberHexLen;
    
    signal output stateRoot[64];
    signal output transactionsRoot[64];		
    signal output receiptsRoot[64];	
    signal output number[6];

    log(5555555000012);
    for (var idx = 0; idx < 1112; idx++) {
        log(blockRlpHexs[idx]);
    }

    component rlp = RlpArrayCheck(1112, 16, 4,
    	      	    	          [64, 64, 40, 64, 64, 64, 512,  0, 0, 0, 0, 0,  0, 64, 16,  0],
				  [64, 64, 40, 64, 64, 64, 512, 14, 6, 8, 8, 8, 64, 64, 18, 10]);
    for (var idx = 0; idx < 1112; idx++) {
    	rlp.in[idx] <== blockRlpHexs[idx];
    }
    rlp.arrayRlpPrefix1HexLen <== 4;
    for (var idx = 0; idx < 6; idx++) {
        rlp.fieldRlpPrefix1HexLen[idx] <== 0;
    }
    rlp.fieldRlpPrefix1HexLen[6] <== 4;
    for (var idx = 7; idx < 16; idx++) {
        rlp.fieldRlpPrefix1HexLen[idx] <== 0;
    }

    var blockRlpHexLen = rlp.totalRlpHexLen;
    component pad = ReorderPad101Hex(1016, 1112, 1360, 13);
    pad.inLen <== blockRlpHexLen;
    for (var idx = 0; idx < 1112; idx++) {
        pad.in[idx] <== blockRlpHexs[idx];
    }

    // if leq.out == 1, use 4 rounds, else use 5 rounds
    component leq = LessEqThan(13);
    leq.in[0] <== blockRlpHexLen + 1;
    // 4 * blockSize = 1088
    leq.in[1] <== 1088;
    
    var blockSizeHex = 136 * 2;
    component keccak = Keccak256Hex(5);
    for (var idx = 0; idx < 5 * blockSizeHex; idx++) {
        keccak.inPaddedHex[idx] <== pad.out[idx];
    }
    keccak.rounds <== 5 - leq.out;

    out <== rlp.out;
    for (var idx = 0; idx < 32; idx++) {
        blockHashHexs[2 * idx] <== keccak.out[2 * idx + 1];
	blockHashHexs[2 * idx + 1] <== keccak.out[2 * idx];
    }
    for (var idx = 0; idx < 64; idx++) {
    	stateRoot[idx] <== rlp.fields[3][idx];
    	transactionsRoot[idx] <== rlp.fields[4][idx];
    	receiptsRoot[idx] <== rlp.fields[5][idx];
    }
    numberHexLen <== rlp.fieldHexLen[8];
    for (var idx = 0; idx < 6; idx++) {
        number[idx] <== rlp.fields[8][idx];
    }

    log(out);
    for (var idx = 0; idx < 64; idx++) {
        log(blockHashHexs[idx]);
    }
    log(numberHexLen);
    for (var idx = 0; idx < 64; idx++) {
        log(stateRoot[idx]);
    }
    for (var idx = 0; idx < 64; idx++) {
        log(transactionsRoot[idx]);
    }
    for (var idx = 0; idx < 64; idx++) {
        log(receiptsRoot[idx]);
    }
    for (var idx = 0; idx < 6; idx++) {
        log(number[idx]);
    }    
}

template EthBlockHashHex3() {
    signal input blockRlpHexs[1112];

    signal output out;
    signal output blockHashHexs[64];

    signal output numberHexLen;
    
    signal output stateRoot[64];
    signal output transactionsRoot[64];		
    signal output receiptsRoot[64];	
    signal output number[6];

    log(5555555000013);
    for (var idx = 0; idx < 1112; idx++) {
        log(blockRlpHexs[idx]);
    }

    component rlp = RlpArrayCheckNoPrefix(1112, 16, 4,
        	      	    	          [64, 64, 40, 64, 64, 64, 512,  0, 0, 0, 0, 0,  0, 64, 16,  0],
					  [64, 64, 40, 64, 64, 64, 512, 14, 6, 8, 8, 8, 64, 64, 18, 10]);
    for (var idx = 0; idx < 1112; idx++) {
    	rlp.in[idx] <== blockRlpHexs[idx];
    }

    var blockRlpHexLen = rlp.totalRlpHexLen;
    component pad = ReorderPad101Hex(1016, 1112, 1360, 13);
    pad.inLen <== blockRlpHexLen;
    for (var idx = 0; idx < 1112; idx++) {
        pad.in[idx] <== blockRlpHexs[idx];
    }

    // if leq.out == 1, use 4 rounds, else use 5 rounds
    component leq = LessEqThan(13);
    leq.in[0] <== blockRlpHexLen + 1;
    // 4 * blockSize = 1088
    leq.in[1] <== 1088;
    
    var blockSizeHex = 136 * 2;
    component keccak = Keccak256Hex(5);
    for (var idx = 0; idx < 5 * blockSizeHex; idx++) {
        keccak.inPaddedHex[idx] <== pad.out[idx];
    }
    keccak.rounds <== 5 - leq.out;

    out <== rlp.out;
    for (var idx = 0; idx < 32; idx++) {
        blockHashHexs[2 * idx] <== keccak.out[2 * idx + 1];
	blockHashHexs[2 * idx + 1] <== keccak.out[2 * idx];
    }
    for (var idx = 0; idx < 64; idx++) {
    	stateRoot[idx] <== rlp.fields[3][idx];
    	transactionsRoot[idx] <== rlp.fields[4][idx];
    	receiptsRoot[idx] <== rlp.fields[5][idx];
    }
    numberHexLen <== rlp.fieldHexLen[8];
    for (var idx = 0; idx < 6; idx++) {
        number[idx] <== rlp.fields[8][idx];
    }

    log(out);
    for (var idx = 0; idx < 64; idx++) {
        log(blockHashHexs[idx]);
    }
    log(numberHexLen);
    for (var idx = 0; idx < 64; idx++) {
        log(stateRoot[idx]);
    }
    for (var idx = 0; idx < 64; idx++) {
        log(transactionsRoot[idx]);
    }
    for (var idx = 0; idx < 64; idx++) {
        log(receiptsRoot[idx]);
    }
    for (var idx = 0; idx < 6; idx++) {
        log(number[idx]);
    }    
}

template EthAddressProof2(maxDepth) {
    var keyHexLen = 64;
    var maxValueHexLen = 228;
    var maxLeafRlpHexLen = 4 + (keyHexLen + 2) + 4 + maxValueHexLen;
    var maxBranchRlpHexLen = 1064;
    var maxExtensionRlpHexLen = 4 + 2 + keyHexLen + 2 + 64;

    signal input stateRootHexs[64];
    signal input addressHexs[40];
    signal input keyFragmentStarts[maxDepth];

    // addressRlpPrefix:      2
    // addressRlpLength:      2
    // nonceRlpPrefix         2
    // nonce                  <= 64
    // balanceRlpPrefix       2
    // balance                <= 24
    // storageRootRlpPrefix   2
    // storageRoot            64
    // codeHashRlpPrefix      2
    // codeHash               64
    signal input addressValueRlpHexs[228];

    // MPT inclusion entries
    signal input leafRlpHexs[maxLeafRlpHexLen];
    signal input leafPathPrefixHexLen;
    
    signal input nodeRlpHexs[maxDepth - 1][maxBranchRlpHexLen];
    signal input nodePathPrefixHexLen[maxDepth - 1];

    // index 0 = root; value 0 = branch, 1 = extension
    signal input nodeTypes[maxDepth - 1];
    signal input depth;

    signal output out;
    signal output nonceHexLen;
    signal output balanceHexLen;
    signal output nonceHexs[64];
    signal output balanceHexs[24];
    signal output storageRootHexs[64];
    signal output codeHashHexs[64];

    log(5555555000022);
    log(maxDepth);
    for (var idx = 0; idx < 64; idx++) {
        log(stateRootHexs[idx]);
    }
    for (var idx = 0; idx < 40; idx++) {
        log(addressHexs[idx]);
    }
    for (var idx = 0; idx < maxDepth; idx++) {
        log(keyFragmentStarts[idx]);
    }
    for (var idx = 0; idx < 228; idx++) {
        log(addressValueRlpHexs[idx]);
    }

    // check address info is properly formattted
    component rlp = RlpArrayCheckNoPrefix(228, 4, 2, [0, 0, 64, 64], [64, 24, 64, 64]);
    for (var idx = 0; idx < 228; idx++) {
    	rlp.in[idx] <== addressValueRlpHexs[idx];
    }

    // read out address fields
    nonceHexLen <== rlp.fieldHexLen[0];
    for (var idx = 0; idx < 64; idx++) {
    	nonceHexs[idx] <== rlp.fields[0][idx];
    }

    balanceHexLen <== rlp.fieldHexLen[1];
    for (var idx = 0; idx < 24; idx++) {
    	balanceHexs[idx] <== rlp.fields[1][idx];
    }
    
    for (var idx = 0; idx < 64; idx++) {
    	storageRootHexs[idx] <== rlp.fields[2][idx];
   	codeHashHexs[idx] <== rlp.fields[3][idx];
    }

    // check address MPT inclusion proof
    component address_hash = KeccakAndPadHex(40);
    for (var idx = 0; idx < 40; idx++) {
	address_hash.in[idx] <== addressHexs[idx];
    }
    address_hash.inLen <== 40;
    
    component mpt = MPTInclusionFixedKeyHexLen2(maxDepth, 64, 228);    
    for (var idx = 0; idx < 64; idx++) {
	mpt.keyHexs[idx] <== address_hash.out[idx];
    }
    for (var idx = 0; idx < 228; idx++) {
	mpt.valueHexs[idx] <== addressValueRlpHexs[idx];
    }
    for (var idx = 0; idx < 64; idx++) {
	mpt.rootHashHexs[idx] <== stateRootHexs[idx];
    }

    for (var idx = 0; idx < maxDepth; idx++) {
    	mpt.keyFragmentStarts[idx] <== keyFragmentStarts[idx];
    }

    mpt.leafPathPrefixHexLen <== leafPathPrefixHexLen;
    for (var idx = 0; idx < maxLeafRlpHexLen; idx++) {
	mpt.leafRlpHexs[idx] <== leafRlpHexs[idx];
    }
    for (var idx = 0; idx < maxDepth - 1; idx++) {
	mpt.nodePathPrefixHexLen[idx] <== nodePathPrefixHexLen[idx];
	for (var j = 0; j < maxBranchRlpHexLen; j++) {
	    mpt.nodeRlpHexs[idx][j] <== nodeRlpHexs[idx][j];
	}
	mpt.nodeTypes[idx] <== nodeTypes[idx];
    }
    mpt.depth <== depth;

    out <== rlp.out * mpt.out;

    log(out);
    log(nonceHexLen);
    log(balanceHexLen);
    for (var idx = 0; idx < 64; idx++) {
    	log(nonceHexs[idx]);
    }
    for (var idx = 0; idx < 24; idx++) {
    	log(balanceHexs[idx]);
    }
    for (var idx = 0; idx < 64; idx++) {
    	log(storageRootHexs[idx]);
    }
    for (var idx = 0; idx < 64; idx++) {
    	log(codeHashHexs[idx]);
    }
}

template EthStorageProof2(maxDepth) {
    var keyHexLen = 64;
    var maxValueHexLen = 66;
    var maxLeafRlpHexLen = 4 + (keyHexLen + 2) + 4 + maxValueHexLen;
    var maxBranchRlpHexLen = 1064;
    var maxExtensionRlpHexLen = 4 + 2 + keyHexLen + 2 + 64;

    signal input storageRootHexs[64];

    signal input slotHexs[64];
    signal input valueRlpHexs[66];
    signal input keyFragmentStarts[maxDepth];
    
    signal input leafRlpHexs[maxLeafRlpHexLen];
    signal input leafPathPrefixHexLen;
    
    signal input nodeRlpHexs[maxDepth - 1][maxBranchRlpHexLen];
    signal input nodePathPrefixHexLen[maxDepth - 1];
    
    signal input nodeTypes[maxDepth - 1];

    signal input depth;  
    
    signal output out;
    signal output slotValue[64];
    signal output valueHexLen;

    log(5555555000032);
    log(maxDepth);
    for (var idx = 0; idx < 64; idx++) {
    	log(storageRootHexs[idx]);
    }
    for (var idx = 0; idx < 64; idx++) {
    	log(slotHexs[idx]);
    }
    for (var idx = 0; idx < 66; idx++) {
    	log(valueRlpHexs[idx]);
    }
    for (var idx = 0; idx < maxDepth; idx++) {
    	log(keyFragmentStarts[idx]);
    }

    // key is keccak256(slot)
    component slot_hash = KeccakAndPadHex(64);
    for (var idx = 0; idx < 64; idx++) {
	slot_hash.in[idx] <== slotHexs[idx];
    }
    slot_hash.inLen <== 64;

    // check MPT inclusion proof
    component mpt = MPTInclusionFixedKeyHexLen2(maxDepth, 64, 66);
    for (var idx = 0; idx < 64; idx++) {
	mpt.keyHexs[idx] <== slot_hash.out[idx];	
    }
    for (var idx = 0; idx < 66; idx++) {
	mpt.valueHexs[idx] <== valueRlpHexs[idx];	
    }
    for (var idx = 0; idx < 64; idx++) {
	mpt.rootHashHexs[idx] <== storageRootHexs[idx];	
    }

    for (var idx = 0; idx < maxDepth; idx++) {
    	mpt.keyFragmentStarts[idx] <== keyFragmentStarts[idx];
    }

    mpt.leafPathPrefixHexLen <== leafPathPrefixHexLen;
    for (var idx = 0; idx < maxLeafRlpHexLen; idx++) {
	mpt.leafRlpHexs[idx] <== leafRlpHexs[idx];
    }
    for (var idx = 0; idx < maxDepth - 1; idx++) {
	mpt.nodePathPrefixHexLen[idx] <== nodePathPrefixHexLen[idx];
	for (var j = 0; j < maxBranchRlpHexLen; j++) {
	    mpt.nodeRlpHexs[idx][j] <== nodeRlpHexs[idx][j];
	}
	mpt.nodeTypes[idx] <== nodeTypes[idx];
    }
    mpt.depth <== depth;
        
    out <== mpt.out;
    valueHexLen <== mpt.valueHexLen - 2;
    for (var idx = 0; idx < 64; idx++) {
	slotValue[idx] <== valueRlpHexs[idx + 2];
    }

    log(out);
    for (var idx = 0; idx < 64; idx++) {
    	log(slotValue[idx]);
    }
    log(valueHexLen);
}

template EthTransactionProof2(maxDepth, maxIndex, maxTxRlpHexLen) {
    var maxLeafRlpHexLen = 4 + (6 + 2) + 4 + maxTxRlpHexLen;
    var maxBranchRlpHexLen = 1064;

    signal input blockHash[2];    // 128 bit coordinates
    signal input index;

    // block input
    signal input blockRlpHexs[1112];

    // MPT inclusion inputs
    signal input txRlpHexs[maxTxRlpHexLen];
    signal input keyFragmentStarts[maxDepth];

    signal input leafRlpHexs[maxLeafRlpHexLen];
    signal input leafPathPrefixHexLen;
    
    signal input nodeRlpHexs[maxDepth - 1][maxBranchRlpHexLen];
    signal input nodePathPrefixHexLen[maxDepth - 1];

    // index 0 = root; value 0 = branch, 1 = extension
    signal input nodeTypes[maxDepth - 1];
    signal input depth;

    signal output out;

    // decode compressed inputs
    signal blockHashHexs[64];
    component blockHashN2b[2];
    for (var idx = 0; idx < 2; idx++) {
    	blockHashN2b[idx] = Num2Bits(128);
	blockHashN2b[idx].in <== blockHash[idx];
	for (var j = 0; j < 32; j++) {
	    blockHashHexs[32 * idx + j] <== 8 * blockHashN2b[idx].out[4 * (31 - j) + 3] + 4 * blockHashN2b[idx].out[4 * (31 - j) + 2] + 2 * blockHashN2b[idx].out[4 * (31 - j) + 1] + blockHashN2b[idx].out[4 * (31 - j)];
	}
    }

    // validate index
    component index_lt = LessThan(10);
    index_lt.in[0] <== index;
    index_lt.in[1] <== maxIndex;

    // match block hash 
    component block_hash = EthBlockHashHex2();
    for (var idx = 0; idx < 1112; idx++) {
	block_hash.blockRlpHexs[idx] <== blockRlpHexs[idx];
    }

    component block_hash_check = ArrayEq(64);
    for (var idx = 0; idx < 64; idx++) {
	block_hash_check.a[idx] <== block_hash.blockHashHexs[idx];
	block_hash_check.b[idx] <== blockHashHexs[idx];
    }
    block_hash_check.inLen <== 64;

    // determine tx type
    component tx_type_1 = IsEqual();
    tx_type_1.in[0] <== txRlpHexs[0];
    tx_type_1.in[1] <== 0;	

    component tx_type_2 = IsEqual();
    tx_type_2.in[0] <== txRlpHexs[1];
    tx_type_2.in[1] <== 2;

    signal tx_type;  // 0 if type 0, 1 if type 2 (post EIP-1559)
    tx_type = tx_type_1 * tx_type_2;

    // TODO: check tx info is properly formatted
    var maxArrayPrefix1HexLen = 2 * (log_ceil(maxTxRlpHexLen) \ 8 + 1);
    component rlp0 = RlpArrayCheckNoPrefix(maxTxRlpHexLen, 9, maxArrayPrefix1HexLen,
        	      	                   [64, 64, 64, 40, 64, 0, 64, 64, 64],
					   [64, 64, 64, 40, 64, maxTxRlpHexLen - 488, 64, 64, 64]);
    for (var idx = 0; idx < maxTxRlpHexLen; idx++) {
        rlp0.in[idx] <== txRlpHexs[idx];
    }

    // assume access list is empty
    component rlp2 = RlpArrayCheckNoPrefix(maxTxRlpHexLen, 12, maxArrayPrefix1HexLen,
        	      	                   [0,  0,  0,  0,  0, 40,  0,              0, 0, 2, 64, 64],
					   [2, 16, 16, 16, 64, 40, 64, maxTxRlpHexLen, 0, 2, 64, 64]);
    for (var idx = 0; idx < maxTxRlpHexLen; idx++) {
        rlp2.in[idx] <== txRlpHexs[idx];
    }

    // TODO: read out tx fields

    // TODO: find RLP encoding of index
    signal rlpIndexHexs[6];
    signal rlpIndexHexLen;

    // validate MPT inclusion
    component mpt = MPTInclusionNoBranchTermination2(maxDepth, 6, maxTxRlpHexLen);
    for (var idx = 0; idx < 6; idx++) {
	mpt.keyHexs[idx] <== rlpIndexHexs[idx];
    }
    mpt.keyHexLen <== rlpIndexHexLen;
    for (var idx = 0; idx < maxTxRlpHexLen; idx++) {
	mpt.valueHexs[idx] <== txRlpHexs[idx];
    }
    for (var idx = 0; idx < 64; idx++) {
	mpt.rootHashHexs[idx] <== block_hash.transactionsRoot[idx];
    }

    for (var idx = 0; idx < maxDepth; idx++) {
    	mpt.keyFragmentStarts[idx] <== keyFragmentStarts[idx];
    }

    mpt.leafPathPrefixHexLen <== leafPathPrefixHexLen;
    for (var idx = 0; idx < maxLeafRlpHexLen; idx++) {
	mpt.leafRlpHexs[idx] <== leafRlpHexs[idx];
    }
    for (var idx = 0; idx < maxDepth - 1; idx++) {
	mpt.nodePathPrefixHexLen[idx] <== nodePathPrefixHexLen[idx];
	for (var j = 0; j < maxBranchRlpHexLen; j++) {
	    mpt.nodeRlpHexs[idx][j] <== nodeRlpHexs[idx][j];
	}
	mpt.nodeTypes[idx] <== nodeTypes[idx];
    }
    mpt.depth <== depth;

    component final_check = IsEqual();
    final_check.in[0] <== 5;
    final_check.in[1] <== index_lt.out + block_hash.out + block_hash_check.out + rlp0.out + tx_type * (rlp2.out - rlp0.out) + mpt.out;
    out <== final_check.out;
}

template EthAddressStorageProof2(addressMaxDepth, storageMaxDepth) {
    // 128 bits = big endian expression of hexes
    signal input blockHash[2];    // 128 bit coordinates
    signal input address;         // 160 bits
    signal input slot[2];         // 128 bit coordinates

    // block input
    signal input blockRlpHexs[1112];

    // address proof input
    var addressKeyHexLen = 64;
    var addressMaxValueHexLen = 228;
    var addressMaxLeafRlpHexLen = 4 + (addressKeyHexLen + 2) + 4 + addressMaxValueHexLen;
    var addressMaxBranchRlpHexLen = 1064;
    var addressMaxExtensionRlpHexLen = 4 + 2 + addressKeyHexLen + 2 + 64;

    signal input addressKeyFragmentStarts[addressMaxDepth];

    signal input addressValueRlpHexs[228];

    signal input addressLeafRlpHexs[addressMaxLeafRlpHexLen];
    signal input addressLeafPathPrefixHexLen;	

    signal input addressNodeRlpHexs[addressMaxDepth - 1][addressMaxBranchRlpHexLen];
    signal input addressNodePathPrefixHexLen[addressMaxDepth - 1];
    signal input addressNodeTypes[addressMaxDepth - 1];

    signal input addressDepth;
    
    // storage proof inputs
    var storageKeyHexLen = 64;
    var storageMaxValueHexLen = 66;
    var storageMaxLeafRlpHexLen = 4 + (storageKeyHexLen + 2) + 4 + storageMaxValueHexLen;
    var storageMaxBranchRlpHexLen = 1064;
    var storageMaxExtensionRlpHexLen = 4 + 2 + storageKeyHexLen + 2 + 64;

    signal input storageKeyFragmentStarts[storageMaxDepth];

    signal input slotValueRlpHexs[66];
    
    signal input storageLeafRlpHexs[storageMaxLeafRlpHexLen];
    signal input storageLeafPathPrefixHexLen;
    
    signal input storageNodeRlpHexs[storageMaxDepth - 1][storageMaxBranchRlpHexLen];
    signal input storageNodePathPrefixHexLen[storageMaxDepth - 1];
    signal input storageNodeTypes[storageMaxDepth - 1];

    signal input storageDepth;  
    
    signal output out;
    signal output blockNumber;
    signal output slotValue[2];                  // 128 bit coordinates

    log(5555555000042);
    log(addressMaxDepth);
    log(storageMaxDepth);
    log(blockHash[0]);
    log(blockHash[1]);
    log(address);
    log(slot[0]);
    log(slot[1]);

    // decode compressed inputs
    signal blockHashHexs[64];
    signal addressHexs[40];
    signal slotHexs[64];
    component blockHashN2b[2];
    for (var idx = 0; idx < 2; idx++) {
    	blockHashN2b[idx] = Num2Bits(128);
	blockHashN2b[idx].in <== blockHash[idx];
	for (var j = 0; j < 32; j++) {
	    blockHashHexs[32 * idx + j] <== 8 * blockHashN2b[idx].out[4 * (31 - j) + 3] + 4 * blockHashN2b[idx].out[4 * (31 - j) + 2] + 2 * blockHashN2b[idx].out[4 * (31 - j) + 1] + blockHashN2b[idx].out[4 * (31 - j)];
	}
    }
    component addressN2b = Num2Bits(160);
    addressN2b.in <== address;
    for (var idx = 0; idx < 40; idx++) {
    	addressHexs[idx] <== 8 * addressN2b.out[4 * (39 - idx) + 3] + 4 * addressN2b.out[4 * (39 - idx) + 2] + 2 * addressN2b.out[4 * (39 - idx) + 1] + addressN2b.out[4 * (39 - idx)];
    }	 
    component slotN2b[2];
    for (var idx = 0; idx < 2; idx++) {
    	slotN2b[idx] = Num2Bits(128);
	slotN2b[idx].in <== slot[idx];
	for (var j = 0; j < 32; j++) {
	    slotHexs[32 * idx + j] <== 8 * slotN2b[idx].out[4 * (31 - j) + 3] + 4 * slotN2b[idx].out[4 * (31 - j) + 2] + 2 * slotN2b[idx].out[4 * (31 - j) + 1] + slotN2b[idx].out[4 * (31 - j)];
	}
    }

    // match block hash 
    component block_hash = EthBlockHashHex3();
    for (var idx = 0; idx < 1112; idx++) {
	block_hash.blockRlpHexs[idx] <== blockRlpHexs[idx];
    }

    component block_hash_check = ArrayEq(64);
    for (var idx = 0; idx < 64; idx++) {
	block_hash_check.a[idx] <== block_hash.blockHashHexs[idx];
	block_hash_check.b[idx] <== blockHashHexs[idx];
    }
    block_hash_check.inLen <== 64;

    // check address proof
    component address_proof = EthAddressProof2(addressMaxDepth);
    for (var idx = 0; idx < 64; idx++) {
	address_proof.stateRootHexs[idx] <== block_hash.stateRoot[idx];
    }
    for (var idx = 0; idx < 40; idx++) {
	address_proof.addressHexs[idx] <== addressHexs[idx];
    }
    for (var idx = 0; idx < 228; idx++) {
	address_proof.addressValueRlpHexs[idx] <== addressValueRlpHexs[idx];
    }
    for (var idx = 0; idx < addressMaxDepth; idx++) {
    	address_proof.keyFragmentStarts[idx] <== addressKeyFragmentStarts[idx];
    }
    address_proof.leafPathPrefixHexLen <== addressLeafPathPrefixHexLen;
    for (var idx = 0; idx < addressMaxLeafRlpHexLen; idx++) {
	address_proof.leafRlpHexs[idx] <== addressLeafRlpHexs[idx];
    }
    for (var idx = 0; idx < addressMaxDepth - 1; idx++) {
	address_proof.nodePathPrefixHexLen[idx] <== addressNodePathPrefixHexLen[idx];
	for (var j = 0; j < addressMaxBranchRlpHexLen; j++) {
	    address_proof.nodeRlpHexs[idx][j] <== addressNodeRlpHexs[idx][j];
	}
	address_proof.nodeTypes[idx] <== addressNodeTypes[idx];
    }
    address_proof.depth <== addressDepth;

    // check storage proof
    component storage_proof = EthStorageProof2(storageMaxDepth);
    for (var idx = 0; idx < 64; idx++) {
	storage_proof.storageRootHexs[idx] <== address_proof.storageRootHexs[idx];
    }
    for (var idx = 0; idx < 64; idx++) {
	storage_proof.slotHexs[idx] <== slotHexs[idx];
    }
    for (var idx = 0; idx < 66; idx++) {
	storage_proof.valueRlpHexs[idx] <== slotValueRlpHexs[idx];
    }
    for (var idx = 0; idx < storageMaxDepth; idx++) {
    	storage_proof.keyFragmentStarts[idx] <== storageKeyFragmentStarts[idx];
    }
    storage_proof.leafPathPrefixHexLen <== storageLeafPathPrefixHexLen;
    for (var idx = 0; idx < storageMaxLeafRlpHexLen; idx++) {
	storage_proof.leafRlpHexs[idx] <== storageLeafRlpHexs[idx];
    }
    for (var idx = 0; idx < storageMaxDepth - 1; idx++) {
	storage_proof.nodePathPrefixHexLen[idx] <== storageNodePathPrefixHexLen[idx];
	for (var j = 0; j < storageMaxBranchRlpHexLen; j++) {
	    storage_proof.nodeRlpHexs[idx][j] <== storageNodeRlpHexs[idx][j];
	}
	storage_proof.nodeTypes[idx] <== storageNodeTypes[idx];
    }
    storage_proof.depth <== storageDepth;
    
    component final_check = IsEqual();
    final_check.in[0] <== 3;
    final_check.in[1] <== block_hash_check.out + address_proof.out + storage_proof.out;
    out <== final_check.out;

    component shift = ShiftRight(64, 9);
    for (var idx = 0; idx < 64; idx++) {
         shift.in[idx] <== storage_proof.slotValue[idx];
    }
    shift.shift <== 64 - storage_proof.valueHexLen;
    
    for (var idx = 0; idx < 2; idx++) {
        var temp = 0;
        for (var j = 0; j < 32; j++) {
	    temp = temp + shift.out[32 * idx + j] * (16 ** (31 - j));
	}
    	slotValue[idx] <== temp;
    }

    component blockNumberShift = ShiftRight(6, 3);
    for (var idx = 0; idx < 6; idx++) {
        blockNumberShift.in[idx] <== block_hash.number[idx];
    }
    blockNumberShift.shift <== 6 - block_hash.numberHexLen;
    var tempBlockNumber = 0;
    for (var idx = 0; idx < 6; idx++) {
        tempBlockNumber = tempBlockNumber + blockNumberShift.out[idx] * (16 ** (5 - idx));
    }
    blockNumber <== tempBlockNumber;

    log(out);
    log(block_hash_check.out);
    log(address_proof.out);
    log(storage_proof.out);

    log(slotValue[0]);
    log(slotValue[1]);
    log(blockNumber);
}
