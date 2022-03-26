pragma circom 2.0.1;

include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/multiplexer.circom";

include "./keccak.circom";
include "./rlp.circom";
include "./mpt.circom";

template EthBlockHashHex() {
    signal input rlpPrefixHexs[6];
    signal input parentHashRlpHexs[64 + 2];
    signal input ommersHashRlpHexs[64 + 2];
    signal input beneficiaryRlpHexs[40 + 2];
    signal input stateRootRlpHexs[64 + 2];
    signal input transactionsRootRlpHexs[64 + 2];
    signal input receiptsRootRlpHexs[64 + 2];
    signal input logsBloomRlpHexs[64 * 8 + 6];
    signal input difficultyRlpHexs[16];
    signal input suffixRlpHexs[8 + 10 + 10 + 10 + 64 + 2 + 64 + 2 + 16 + 2 + 12];

    signal input suffixRlpHexLen;

    signal output blockHashHexs[64];

    component pad = ReorderPad101Hex(1016, 1112, 1360, 13);
    pad.inLen <== 912 + suffixRlpHexLen;
    var curr_idx = 0;
    for (var idx = 0; idx < 6; idx++) {
	pad.in[curr_idx] <== rlpPrefixHexs[idx];	
        curr_idx = curr_idx + 1;
    }
    for (var idx = 0; idx < 64 + 2; idx++) {
	pad.in[curr_idx] <== parentHashRlpHexs[idx];	
        curr_idx = curr_idx + 1;
    }
    for (var idx = 0; idx < 64 + 2; idx++) {
        pad.in[curr_idx] <== ommersHashRlpHexs[idx];
        curr_idx = curr_idx + 1;
    }
    for (var idx = 0; idx < 40 + 2; idx++) {
        pad.in[curr_idx] <== beneficiaryRlpHexs[idx];	
        curr_idx = curr_idx + 1;
    }
    for (var idx = 0; idx < 64 + 2; idx++) {
	pad.in[curr_idx] <== stateRootRlpHexs[idx];
        curr_idx = curr_idx + 1;
    }
    for (var idx = 0; idx < 64 + 2; idx++) {
        pad.in[curr_idx] <== transactionsRootRlpHexs[idx];
        curr_idx = curr_idx + 1;
    }
    for (var idx = 0; idx < 64 + 2; idx++) {
        pad.in[curr_idx] <== receiptsRootRlpHexs[idx];
        curr_idx = curr_idx + 1;
    }
    for (var idx = 0; idx < 64 * 8 + 6; idx++) {
        pad.in[curr_idx] <== logsBloomRlpHexs[idx];
        curr_idx = curr_idx + 1;
    }
    for (var idx = 0; idx < 16; idx++) {
        pad.in[curr_idx] <== difficultyRlpHexs[idx];
        curr_idx = curr_idx + 1;
    }
    for (var idx = 0; idx < 8 + 10 + 10 + 10 + 64 + 2 + 64 + 2 + 16 + 2 + 12; idx++) {
        pad.in[curr_idx] <== suffixRlpHexs[idx];
        curr_idx = curr_idx + 1;
    }

    // if leq.out == 1, use 4 rounds, else use 5 rounds
    component leq = LessEqThan(13);
    leq.in[0] <== 912 + suffixRlpHexLen + 1;
    // 4 * blockSize = 1088
    leq.in[1] <== 1088;
    
    var blockSizeHex = 136 * 2;
    component keccak = Keccak256Hex(5);
    for (var idx = 0; idx < 5 * blockSizeHex; idx++) {
        keccak.inPaddedHex[idx] <== pad.out[idx];
    }
    keccak.rounds <== 5 - leq.out;
    
    for (var idx = 0; idx < 64; idx++) {
        blockHashHexs[idx] <== keccak.out[idx];
    }
}

template EthAddressProof(maxDepth) {
    var keyHexLen = 64;
    var maxValueHexLen = 228;
    var maxLeafRlpHexLen = 4 + (keyHexLen + 2) + 4 + maxValueHexLen;
    var maxBranchRlpHexLen = 1064;
    var maxExtensionRlpHexLen = 4 + 2 + keyHexLen + 2 + 64;

    signal input stateRootHexs[64];

    signal input addressHexs[40];

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
    signal input nonceHexLen;
    signal input balanceHexLen;
    signal input addressValueRlpHexs[228];

    // MPT inclusion entries
    signal input leafRlpLengthHexLen;    
    signal input leafPathRlpLengthHexLen;
    signal input leafPathPrefixHexLen;
    signal input leafPathHexLen;    
    signal input leafValueRlpLengthHexLen;
    signal input leafValueHexLen;
    signal input leafRlpHexs[maxLeafRlpHexLen];
    
    signal input nodeRlpLengthHexLen[maxDepth - 1];    
    signal input nodePathRlpLengthHexLen[maxDepth - 1];
    signal input nodePathPrefixHexLen[maxDepth - 1];
    signal input nodePathHexLen[maxDepth - 1];
    signal input nodeRefHexLen[maxDepth - 1][16];    
    signal input nodeRlpHexs[maxDepth - 1][maxBranchRlpHexLen];
    
    // index 0 = root; value 0 = branch, 1 = extension
    signal input nodeTypes[maxDepth - 1];
    signal input depth;

    signal output out;
    signal output nonceHexs[64];
    signal output balanceHexs[24];
    signal output storageRootHexs[64];
    signal output codeHashHexs[64];

    component nonce_selector = SubArray(228, 64, 8);
    for (var idx = 0; idx < 228; idx++) {
	nonce_selector.in[idx] <== addressValueRlpHexs[idx];
    }
    nonce_selector.start <== 6;
    nonce_selector.end <== 6 + nonceHexLen;
    for (var idx = 0; idx < 64; idx++) {
	nonceHexs[idx] <== nonce_selector.out[idx];
    }

    component balance_selector = SubArray(228, 24, 8);
    for (var idx = 0; idx < 228; idx++) {
	balance_selector.in[idx] <== addressValueRlpHexs[idx];
    }
    balance_selector.start <== 6 + nonceHexLen + 2;
    balance_selector.end <== 6 + nonceHexLen + 2 + balanceHexLen;
    for (var idx = 0; idx < 24; idx++) {
	balanceHexs[idx] <== balance_selector.out[idx];
    }

    component storageRoot_selector = SubArray(228, 64, 8);
    for (var idx = 0; idx < 228; idx++) {
	storageRoot_selector.in[idx] <== addressValueRlpHexs[idx];
    }
    storageRoot_selector.start <== 6 + nonceHexLen + 2 + balanceHexLen + 2;
    storageRoot_selector.end <== 6 + nonceHexLen + 2 + balanceHexLen + 2 + 64;
    for (var idx = 0; idx < 64; idx++) {
	storageRootHexs[idx] <== storageRoot_selector.out[idx];
    }

    component codeHash_selector = SubArray(228, 64, 8);
    for (var idx = 0; idx < 228; idx++) {
	codeHash_selector.in[idx] <== addressValueRlpHexs[idx];
    }
    codeHash_selector.start <== 6 + nonceHexLen + 2 + balanceHexLen + 2 + 64 + 2;
    codeHash_selector.end <== 6 + nonceHexLen + 2 + balanceHexLen + 2 + 64 + 2 + 64;
    for (var idx = 0; idx < 64; idx++) {
	codeHashHexs[idx] <== codeHash_selector.out[idx];
    }
    
    component address_hash = KeccakAndPadHex(40);
    for (var idx = 0; idx < 40; idx++) {
	address_hash.in[idx] <== addressHexs[idx];
    }
    address_hash.inLen <== 40;
    
    component mpt_proof = MPTInclusionFixedKeyHexLen(maxDepth, 64, 228);    
    for (var idx = 0; idx < 64; idx++) {
	mpt_proof.keyHexs[idx] <== address_hash.out[idx];
    }

    for (var idx = 0; idx < 228; idx++) {
	mpt_proof.valueHexs[idx] <== addressValueRlpHexs[idx];
    }
    for (var idx = 0; idx < 64; idx++) {
	mpt_proof.rootHashHexs[idx] <== stateRootHexs[idx];
    }

    mpt_proof.leafRlpLengthHexLen <== leafRlpLengthHexLen;
    mpt_proof.leafPathRlpLengthHexLen <== leafPathRlpLengthHexLen;
    mpt_proof.leafPathPrefixHexLen <== leafPathPrefixHexLen;
    mpt_proof.leafPathHexLen <== leafPathHexLen;
    mpt_proof.leafValueRlpLengthHexLen <== leafValueRlpLengthHexLen;
    mpt_proof.leafValueHexLen <== leafValueHexLen;
    for (var idx = 0; idx < maxLeafRlpHexLen; idx++) {
	mpt_proof.leafRlpHexs[idx] <== leafRlpHexs[idx];
    }
    for (var idx = 0; idx < maxDepth - 1; idx++) {
	mpt_proof.nodeRlpLengthHexLen[idx] <== nodeRlpLengthHexLen[idx];
	mpt_proof.nodePathRlpLengthHexLen[idx] <== nodePathRlpLengthHexLen[idx];
	mpt_proof.nodePathPrefixHexLen[idx] <== nodePathPrefixHexLen[idx];
	mpt_proof.nodePathHexLen[idx] <== nodePathHexLen[idx];
	for (var j = 0; j < 16; j++) {
	    mpt_proof.nodeRefHexLen[idx][j] <== nodeRefHexLen[idx][j];
	}
	for (var j = 0; j < maxBranchRlpHexLen; j++) {
	    mpt_proof.nodeRlpHexs[idx][j] <== nodeRlpHexs[idx][j];
	}
	mpt_proof.nodeTypes[idx] <== nodeTypes[idx];
    }
    mpt_proof.depth <== depth;

    out <== mpt_proof.out;
}

template EthStorageProof(maxDepth) {
    var keyHexLen = 64;
    var maxValueHexLen = 66;
    var maxLeafRlpHexLen = 4 + (keyHexLen + 2) + 4 + maxValueHexLen;
    var maxBranchRlpHexLen = 1064;
    var maxExtensionRlpHexLen = 4 + 2 + keyHexLen + 2 + 64;

    signal input storageRootHexs[64];

    signal input slotHexLen;
    signal input slotHexs[64];
    signal input valueRlpHexs[66];
    
    signal input leafRlpLengthHexLen;
    signal input leafPathRlpLengthHexLen;
    signal input leafPathPrefixHexLen;
    signal input leafPathHexLen;
    signal input leafValueRlpLengthHexLen;
    signal input leafValueHexLen;
    signal input leafRlpHexs[maxLeafRlpHexLen];
    
    signal input nodeRlpLengthHexLen[maxDepth - 1];    
    signal input nodePathRlpLengthHexLen[maxDepth - 1];
    signal input nodePathPrefixHexLen[maxDepth - 1];
    signal input nodePathHexLen[maxDepth - 1];    
    signal input nodeRefHexLen[maxDepth - 1][16]; 
    signal input nodeRlpHexs[maxDepth - 1][maxBranchRlpHexLen];
    signal input nodeTypes[maxDepth - 1];

    signal input depth;  
    
    signal output out;
    signal output slotValue[64];
    signal output valueHexLen;

    valueHexLen <== leafValueHexLen - 2;
    component slotValue_selector = SubArray(66, 64, 7);
    for (var idx = 0; idx < 66; idx++) {
	slotValue_selector.in[idx] <== valueRlpHexs[idx];
    }
    slotValue_selector.start <== 2;
    slotValue_selector.end <== 2 + valueHexLen;
    for (var idx = 0; idx < 64; idx++) {
	slotValue[idx] <== slotValue_selector.out[idx];
    }

    component slot_hash = KeccakAndPadHex(64);
    for (var idx = 0; idx < 64; idx++) {
	slot_hash.in[idx] <== slotHexs[idx];
    }
    slot_hash.inLen <== slotHexLen;
    
    component mpt_proof = MPTInclusionFixedKeyHexLen(maxDepth, 64, 66);

    for (var idx = 0; idx < 64; idx++) {
	mpt_proof.keyHexs[idx] <== slot_hash.out[idx];	
    }
    for (var idx = 0; idx < 66; idx++) {
	mpt_proof.valueHexs[idx] <== valueRlpHexs[idx];	
    }
    for (var idx = 0; idx < 64; idx++) {
	mpt_proof.rootHashHexs[idx] <== storageRootHexs[idx];	
    }

    mpt_proof.leafRlpLengthHexLen <== leafRlpLengthHexLen;
    mpt_proof.leafPathRlpLengthHexLen <== leafPathRlpLengthHexLen;
    mpt_proof.leafPathPrefixHexLen <== leafPathPrefixHexLen;
    mpt_proof.leafPathHexLen <== leafPathHexLen;
    mpt_proof.leafValueRlpLengthHexLen <== leafValueRlpLengthHexLen;
    mpt_proof.leafValueHexLen <== leafValueHexLen;
    for (var idx = 0; idx < maxLeafRlpHexLen; idx++) {
	mpt_proof.leafRlpHexs[idx] <== leafRlpHexs[idx];
    }
    for (var idx = 0; idx < maxDepth - 1; idx++) {
	mpt_proof.nodeRlpLengthHexLen[idx] <== nodeRlpLengthHexLen[idx];
	mpt_proof.nodePathRlpLengthHexLen[idx] <== nodePathRlpLengthHexLen[idx];
	mpt_proof.nodePathPrefixHexLen[idx] <== nodePathPrefixHexLen[idx];
	mpt_proof.nodePathHexLen[idx] <== nodePathHexLen[idx];
	for (var j = 0; j < 16; j++) {
	    mpt_proof.nodeRefHexLen[idx][j] <== nodeRefHexLen[idx][j];
	}
	for (var j = 0; j < maxBranchRlpHexLen; j++) {
	    mpt_proof.nodeRlpHexs[idx][j] <== nodeRlpHexs[idx][j];
	}
	mpt_proof.nodeTypes[idx] <== nodeTypes[idx];
    }
    mpt_proof.depth <== depth;
        
    out <== mpt_proof.out;    
}

template EthTransactionProof(maxDepth) {

}

template EthAddressStorageProof(addressMaxDepth, storageMaxDepth) {
    // block hash inputs
    signal input blockHashHexs[64];

    signal input rlpPrefixHexs[6];
    signal input parentHashRlpHexs[64 + 2];
    signal input ommersHashRlpHexs[64 + 2];
    signal input beneficiaryRlpHexs[40 + 2];
    signal input stateRootRlpHexs[64 + 2];
    signal input transactionsRootRlpHexs[64 + 2];
    signal input receiptsRootRlpHexs[64 + 2];
    signal input logsBloomRlpHexs[64 * 8 + 6];
    signal input difficultyRlpHexs[16];
    
    signal input suffixRlpHexLen;
    signal input suffixRlpHexs[8 + 10 + 10 + 10 + 64 + 2 + 64 + 2 + 16 + 2 + 12];

    // address proof input
    var addressKeyHexLen = 64;
    var addressMaxValueHexLen = 228;
    var addressMaxLeafRlpHexLen = 4 + (addressKeyHexLen + 2) + 4 + addressMaxValueHexLen;
    var addressMaxBranchRlpHexLen = 1064;
    var addressMaxExtensionRlpHexLen = 4 + 2 + addressKeyHexLen + 2 + 64;

    signal input addressHexs[40];
    signal input nonceHexLen;
    signal input balanceHexLen;
    signal input addressValueRlpHexs[228];

    signal input addressLeafRlpLengthHexLen;    
    signal input addressLeafPathRlpLengthHexLen;
    signal input addressLeafPathPrefixHexLen;
    signal input addressLeafPathHexLen;    
    signal input addressLeafValueRlpLengthHexLen;
    signal input addressLeafValueHexLen;
    signal input addressLeafRlpHexs[addressMaxLeafRlpHexLen];

    signal input addressNodeRlpLengthHexLen[addressMaxDepth - 1];    
    signal input addressNodePathRlpLengthHexLen[addressMaxDepth - 1];
    signal input addressNodePathPrefixHexLen[addressMaxDepth - 1];
    signal input addressNodePathHexLen[addressMaxDepth - 1];    
    signal input addressNodeRefHexLen[addressMaxDepth - 1][16];    
    signal input addressNodeRlpHexs[addressMaxDepth - 1][addressMaxBranchRlpHexLen];
    signal input addressNodeTypes[addressMaxDepth - 1];

    signal input addressDepth;
    
    // storage proof inputs
    var storageKeyHexLen = 64;
    var storageMaxValueHexLen = 66;
    var storageMaxLeafRlpHexLen = 4 + (storageKeyHexLen + 2) + 4 + storageMaxValueHexLen;
    var storageMaxBranchRlpHexLen = 1064;
    var storageMaxExtensionRlpHexLen = 4 + 2 + storageKeyHexLen + 2 + 64;

    signal input slotHexLen;
    signal input slotHexs[64];
    signal input slotValueRlpHexs[66];
    
    signal input storageLeafRlpLengthHexLen;
    signal input storageLeafPathRlpLengthHexLen;
    signal input storageLeafPathPrefixHexLen;
    signal input storageLeafPathHexLen;
    signal input storageLeafValueRlpLengthHexLen;
    signal input storageLeafValueHexLen;
    signal input storageLeafRlpHexs[storageMaxLeafRlpHexLen];
    
    signal input storageNodeRlpLengthHexLen[storageMaxDepth - 1];    
    signal input storageNodePathRlpLengthHexLen[storageMaxDepth - 1];
    signal input storageNodePathPrefixHexLen[storageMaxDepth - 1];
    signal input storageNodePathHexLen[storageMaxDepth - 1];    
    signal input storageNodeRefHexLen[storageMaxDepth - 1][16]; 
    signal input storageNodeRlpHexs[storageMaxDepth - 1][storageMaxBranchRlpHexLen];
    signal input storageNodeTypes[storageMaxDepth - 1];

    signal input storageDepth;  
    
    signal output out;
    signal output slotValue[64];
    signal output slotValueHexLen;
    
    component block_hash_proof = EthBlockHashHex();
    for (var idx = 0; idx < 6; idx++) {
	block_hash_proof.rlpPrefixHexs[idx] <== rlpPrefixHexs[idx];
    }
    for (var idx = 0; idx < 64 + 2; idx++) {
	block_hash_proof.parentHashRlpHexs[idx] <== parentHashRlpHexs[idx];
	block_hash_proof.ommersHashRlpHexs[idx] <== ommersHashRlpHexs[idx];
	block_hash_proof.stateRootRlpHexs[idx] <== stateRootRlpHexs[idx];
	block_hash_proof.transactionsRootRlpHexs[idx] <== transactionsRootRlpHexs[idx];
	block_hash_proof.receiptsRootRlpHexs[idx] <== receiptsRootRlpHexs[idx];
    }
    for (var idx = 0; idx < 40 + 2; idx++) {
	block_hash_proof.beneficiaryRlpHexs[idx] <== beneficiaryRlpHexs[idx];
    }
    for (var idx = 0; idx < 64 * 8 + 6; idx++) {
	block_hash_proof.logsBloomRlpHexs[idx] <== logsBloomRlpHexs[idx];
    }
    for (var idx = 0; idx < 16; idx++) {
	block_hash_proof.difficultyRlpHexs[idx] <== difficultyRlpHexs[idx];
    }
    for (var idx = 0; idx < 8 + 10 + 10 + 10 + 64 + 2 + 64 + 2 + 16 + 2 + 12; idx++) {
	block_hash_proof.suffixRlpHexs[idx] <== suffixRlpHexs[idx];
    }
    block_hash_proof.suffixRlpHexLen <== suffixRlpHexLen;
    
    component block_hash_check = ArrayEq(64);
    for (var idx = 0; idx < 64; idx++) {
	block_hash_check.a[idx] <== block_hash_proof.blockHashHexs[idx];
	block_hash_check.b[idx] <== blockHashHexs[idx];
    }
    block_hash_check.inLen <== 64;

    component address_proof = EthAddressProof(addressMaxDepth);
    for (var idx = 0; idx < 64; idx++) {
	address_proof.stateRootHexs[idx] <== stateRootRlpHexs[idx + 2];
    }
    for (var idx = 0; idx < 40; idx++) {
	address_proof.addressHexs[idx] <== addressHexs[idx];
    }
    address_proof.nonceHexLen <== nonceHexLen;
    address_proof.balanceHexLen <== balanceHexLen;
    for (var idx = 0; idx < 228; idx++) {
	address_proof.addressValueRlpHexs[idx] <== addressValueRlpHexs[idx];
    }
    address_proof.leafRlpLengthHexLen <== addressLeafRlpLengthHexLen;
    address_proof.leafPathRlpLengthHexLen <== addressLeafPathRlpLengthHexLen;
    address_proof.leafPathPrefixHexLen <== addressLeafPathPrefixHexLen;
    address_proof.leafPathHexLen <== addressLeafPathHexLen;
    address_proof.leafValueRlpLengthHexLen <== addressLeafValueRlpLengthHexLen;
    address_proof.leafValueHexLen <== addressLeafValueHexLen;
    for (var idx = 0; idx < addressMaxLeafRlpHexLen; idx++) {
	address_proof.leafRlpHexs[idx] <== addressLeafRlpHexs[idx];
    }
    for (var idx = 0; idx < addressMaxDepth - 1; idx++) {
	address_proof.nodeRlpLengthHexLen[idx] <== addressNodeRlpLengthHexLen[idx];
	address_proof.nodePathRlpLengthHexLen[idx] <== addressNodePathRlpLengthHexLen[idx];
	address_proof.nodePathPrefixHexLen[idx] <== addressNodePathPrefixHexLen[idx];
	address_proof.nodePathHexLen[idx] <== addressNodePathHexLen[idx];
	for (var j = 0; j < 16; j++) {
	    address_proof.nodeRefHexLen[idx][j] <== addressNodeRefHexLen[idx][j];
	}
	for (var j = 0; j < addressMaxBranchRlpHexLen; j++) {
	    address_proof.nodeRlpHexs[idx][j] <== addressNodeRlpHexs[idx][j];
	}
	address_proof.nodeTypes[idx] <== addressNodeTypes[idx];
    }
    address_proof.depth <== addressDepth;

    component storage_proof = EthStorageProof(storageMaxDepth);
    for (var idx = 0; idx < 64; idx++) {
	storage_proof.storageRootHexs[idx] <== address_proof.storageRootHexs[idx];
    }
    storage_proof.slotHexLen <== slotHexLen;
    for (var idx = 0; idx < 64; idx++) {
	storage_proof.slotHexs[idx] <== slotHexs[idx];
    }
    for (var idx = 0; idx < 66; idx++) {
	storage_proof.valueRlpHexs[idx] <== slotValueRlpHexs[idx];
    }
    storage_proof.leafRlpLengthHexLen <== storageLeafRlpLengthHexLen;
    storage_proof.leafPathRlpLengthHexLen <== storageLeafPathRlpLengthHexLen;
    storage_proof.leafPathPrefixHexLen <== storageLeafPathPrefixHexLen;
    storage_proof.leafPathHexLen <== storageLeafPathHexLen;
    storage_proof.leafValueRlpLengthHexLen <== storageLeafValueRlpLengthHexLen;
    storage_proof.leafValueHexLen <== storageLeafValueHexLen;
    for (var idx = 0; idx < storageMaxLeafRlpHexLen; idx++) {
	storage_proof.leafRlpHexs[idx] <== storageLeafRlpHexs[idx];
    }
    for (var idx = 0; idx < storageMaxDepth - 1; idx++) {
	storage_proof.nodeRlpLengthHexLen[idx] <== storageNodeRlpLengthHexLen[idx];
	storage_proof.nodePathRlpLengthHexLen[idx] <== storageNodePathRlpLengthHexLen[idx];
	storage_proof.nodePathPrefixHexLen[idx] <== storageNodePathPrefixHexLen[idx];
	storage_proof.nodePathHexLen[idx] <== storageNodePathHexLen[idx];
	for (var j = 0; j < 16; j++) {
	    storage_proof.nodeRefHexLen[idx][j] <== storageNodeRefHexLen[idx][j];
	}
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

    slotValueHexLen <== storage_proof.valueHexLen;
    for (var idx = 0; idx < 64; idx++) {
	slotValue[idx] <== storage_proof.slotValue[idx];
    }
}
