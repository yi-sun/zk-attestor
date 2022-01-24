pragma circom 2.0.2;

include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/multiplexer.circom";

include "./keccak2.circom";
include "./rlp.circom";

function max(a, b) {
    if (a > b) {
	return a;
    }
    return b;
}

template LeafFixedKeyHexLen(keyHexLen, maxValueHexLen) {
    var maxLeafRlpHexLen = 4 + 66 + 4 + maxValueHexLen;

    signal input keyNibbleHexLen;
    signal input keyNibbleHexs[keyHexLen];
    signal input valueHexs[maxValueHexLen];

    // leaf = rlp_prefix           [2]
    //        rlp_length           [0, 2 * ceil(log_8(1 + ceil(log_8(keyHexLen + 2)) + 4 + keyHexLen + 2 + 2 * ceil(log_8(maxValueHexLen)) + maxValueHexLen))]
    //        rlp_path_rlp_prefix  [2]
    //        rlp_path_rlp_length  [0, 2 * ceil(log_8(keyHexLen + 2))]
    //        path_prefix          [1, 2]
    //        path                 [0, keyHexLen]
    //        rlp_value_prefix     [2]
    //        rlp_value_len        [0, 2 * ceil(log_8(maxValueHexLen))]
    //        value                [0, maxValueHexLen]
    signal input leafRlpLengthHexLen;
    signal input leafPathRlpHexLen;
    signal input leafPathPrefixHexLen;
    signal input leafPathHexLen;
    signal input leafRlpValueLenHexLen;
    signal input leafValueLenHexLen;
    signal input leafRlpHexs[maxLeafRlpHexLen];

    signal output out;

    // * check input hexes are hexes
    component hexCheck[maxLeafRlpHexLen];
    for (var idx = 0; idx < maxLeafRlpHexLen; idx++) {
	hexCheck[idx] = Num2Bits(4);
	hexCheck[idx].in <== leafRlpHexs[idx];
    }
    
    // * [ignore] check validity of RLP encoding    
    // * [ignore] check validity of path prefix
    
    // * check path matches keyNibbles
    component leaf_to_path = SubArray(maxLeafRlpHexLen, keyHexLen, 252);
    for (var idx = 0; idx < maxLeafRlpHexLen; idx++) {
	leaf_to_path.in[idx] <== leafRlpHexs[idx];
    }
    leaf_to_path.start <== 2 + leafRlpLengthHexLen + 2 + leafPathRlpHexLen + leafPathPrefixHexLen;
    leaf_to_path.end <== 2 + leafRlpLengthHexLen + 2 + leafPathRlpHexLen + leafPathPrefixHexLen + leafPathHexLen;

    component key_path_match = ArrayEq(keyHexLen);
    for (var idx = 0; idx < keyHexLen; idx++) {
	key_path_match.a[idx] <== leaf_to_path.out[idx];
	key_path_match.b[idx] <== keyNibbleHexs[idx];
    }
    key_path_match.inLen <== leaf_to_path.outLen;

    component key_path_len_match = IsEqual();
    key_path_len_match.in[0] <== keyNibbleHexLen;
    key_path_len_match.in[1] <== leaf_to_path.outLen;

    signal key_path;
    key_path <== key_path_len_match.out * key_path_match.out;
    
    // * check value matches valueBits
    component leaf_to_value = SubArray(maxLeafRlpHexLen, maxValueHexLen, 252);
    for (var idx = 0; idx < maxLeafRlpHexLen; idx++) {
	leaf_to_value.in[idx] <== leafRlpHexs[idx];
    }
    leaf_to_value.start <== 2 + leafRlpLengthHexLen + 2 + leafPathRlpHexLen + leafPathPrefixHexLen + leafPathHexLen + 2 + leafRlpValueLenHexLen;
    leaf_to_value.end <== 2 + leafRlpLengthHexLen + 2 + leafPathRlpHexLen + leafPathPrefixHexLen + leafPathHexLen + 2 + leafRlpValueLenHexLen + leafValueLenHexLen;

    component leaf_value_match = ArrayEq(maxValueHexLen);
    for (var idx = 0; idx < maxValueHexLen; idx++) {
	leaf_value_match.a[idx] <== leaf_to_value.out[idx];
	leaf_value_match.b[idx] <== valueHexs[idx];
    }
    leaf_value_match.inLen <== leafValueLenHexLen;

    out <== key_path + leaf_value_match.out;
}

template ExtensionFixedKeyHexLen(keyHexLen, maxNodeRefLen) {
    var maxExtensionRlpHexLen = 4 + 134;

    signal input keyNibbleHexLen;
    signal input keyNibbleHexs[keyHexLen];

    signal input nodeRefHexLen;
    signal input nodeRefHexs[maxNodeRefLen];

    // extension = rlp_prefix           [2]
    //             rlp_length           [0, 2 * ceil((...))]
    //             rlp_path_rlp_prefix  [2]
    //             rlp_path_rlp_length  [0, 2 * ceil(log_8(keyHexLen + 2))]
    //             path_prefix          [1, 2]
    //             path                 [0, keyHexLen]
    //             rlp_node_ref_prefix  [2]
    //             node_ref             [0, 64]
    signal input nodeRlpLengthHexLen;
    signal input nodePathRlpHexLen;
    signal input nodePathPrefixHexLen;
    signal input nodePathHexLen;
    signal input nodeRefExtHexLen;
    signal input nodeRlpHexs[maxExtensionRlpHexLen];

    signal output out;

    // check input hexs are hexs
    component hexChecks[maxExtensionRlpHexLen];
    for (var idx = 0; idx < maxExtensionRlpHexLen; idx++) {
	hexChecks[idx] = Num2Bits(4);
	hexChecks[idx].in <== nodeRlpHexs[idx];
    }
    
    // * [ignore] check validity of RLP encoding     
    // * [ignore] check validity of path prefix      
    // * check path contains nibbles of key
    component extension_to_path = SubArray(maxExtensionRlpHexLen, keyHexLen, 252);
    for (var idx = 0; idx < maxExtensionRlpHexLen; idx++) {
	extension_to_path.in[idx] <== nodeRlpHexs[idx];
    }
    extension_to_path.start <== 2 + nodeRlpLengthHexLen + 2 + nodePathRlpHexLen + nodePathPrefixHexLen;
    extension_to_path.end <== 2 + nodeRlpLengthHexLen + 2 + nodePathRlpHexLen + nodePathPrefixHexLen + nodePathHexLen;

    component key_path_match = ArrayEq(keyHexLen);
    for (var idx = 0; idx < keyHexLen; idx++) {
	key_path_match.a[idx] <== extension_to_path.out[idx];
	key_path_match.b[idx] <== keyNibbleHexs[idx];
    }
    key_path_match.inLen <== keyNibbleHexLen;
    
    component key_path_len_match = IsEqual();
    key_path_len_match.in[0] <== keyNibbleHexLen;
    key_path_len_match.in[1] <== nodePathHexLen;
    
    signal key_path;
    key_path <== key_path_len_match.out * key_path_match.out;
    
    // * check node_ref matches child
    component extension_to_node_ref = SubArray(maxExtensionRlpHexLen, maxNodeRefLen, 252);
    for (var idx = 0; idx < maxExtensionRlpHexLen; idx++) {
	extension_to_node_ref.in[idx] <== nodeRlpHexs[idx];
    }
    extension_to_node_ref.start <== 2 + nodeRlpLengthHexLen + 2 + nodePathRlpHexLen + nodePathPrefixHexLen + nodePathHexLen + 2;
    extension_to_node_ref.end <== 2 + nodeRlpLengthHexLen + 2 + nodePathRlpHexLen + nodePathPrefixHexLen + nodePathHexLen + 2 + nodeRefExtHexLen;
    
    component node_ref_match = ArrayEq(maxNodeRefLen);
    for (var idx = 0; idx < maxNodeRefLen; idx++) {
	node_ref_match.a[idx] <== extension_to_node_ref.out[idx];
	node_ref_match.b[idx] <== nodeRefHexs[idx];
    }
    node_ref_match.inLen <== maxNodeRefLen;

    component node_ref_len_match = IsEqual();
    node_ref_len_match.in[0] <== nodeRefHexLen;
    node_ref_len_match.in[1] <== nodeRefExtHexLen;

    signal node_ref;
    node_ref <== node_ref_match.out * node_ref_len_match.out;
    
    out <== key_path + node_ref;
}

template BranchFixedKeyHexLen(maxNodeRefLen) {
    var maxBranchRlpHexLen = 1064;

    signal input keyNibble;

    signal input nodeRefHexLen;
    signal input nodeRefHexs[maxNodeRefLen];

    // branch = rlp_prefix              [2]
    //          rlp_length              [0, 8]
    //          v0_rlp_prefix           [2]
    //          v0                      [0, 64]
    //          ...
    //          v15_rlp_prefix          [2]
    //          v15                     [0, 64]
    //          vt_rlp_prefix           [2]
    signal input nodeRlpLengthHexLen;
    // v0, ..., v15 _or_ node_ref
    signal input nodeValueLenHexLen[16];
    signal input nodeRlpHexs[maxBranchRlpHexLen];

    signal output out;

    log(keyNibble);
    log(nodeRefHexLen);
    for(var idx = 0; idx < 5; idx++) {
	log(nodeRefHexs[idx]);
    }
    log(nodeRlpLengthHexLen);
    for (var idx = 0; idx < 16; idx++) {
	log(nodeValueLenHexLen[idx]);
    }
    for (var idx = 0; idx < 5; idx++) {
	log(nodeRlpHexs[idx]);
    }
    log(22222222222222222222222);

    // check input hexs are hexs
    component hexChecks[maxBranchRlpHexLen];
    for (var idx = 0; idx < maxBranchRlpHexLen; idx++) {
	hexChecks[idx] = Num2Bits(4);
	hexChecks[idx].in <== nodeRlpHexs[idx];
    }
    
    // * [ignore] check validity of RLP encoding
    // * [ignore] check validity of inputs
    
    // * check node_ref at index of nibble matches child
    signal nodeRefStartHexIdx[16];
    nodeRefStartHexIdx[0] <== 2 + nodeRlpLengthHexLen + 2;
    for (var idx = 1; idx < 16; idx++) {
	nodeRefStartHexIdx[idx] <== nodeRefStartHexIdx[idx - 1] + nodeValueLenHexLen[idx - 1] + 2;
    }

    component nodeStartSelector = Multiplexer(1, 16);
    component nodeRefLenSelector = Multiplexer(1, 16);
    for (var idx = 0; idx < 16; idx++) {
	nodeStartSelector.inp[idx][0] <== nodeRefStartHexIdx[idx];
	nodeRefLenSelector.inp[idx][0] <== nodeValueLenHexLen[idx];
    }
    nodeStartSelector.sel <== keyNibble;
    nodeRefLenSelector.sel <== keyNibble;

    // find the node_ref at the index of nibble
    component branch_to_node_ref = SubArray(maxBranchRlpHexLen, maxNodeRefLen, 252);
    for (var idx = 0; idx < maxBranchRlpHexLen; idx++) {
	branch_to_node_ref.in[idx] <== nodeRlpHexs[idx];
    }
    branch_to_node_ref.start <== nodeStartSelector.out[0];
    branch_to_node_ref.end <== nodeStartSelector.out[0] + nodeRefLenSelector.out[0];

    for (var idx = 0; idx < 5; idx++) {
	log(branch_to_node_ref.out[idx]);
    }
    for (var idx = 0; idx < 5; idx++) {
	log(nodeRefHexs[idx]);
    }
    log(33333333333333333333333);
    
    component node_ref_match = ArrayEq(maxNodeRefLen);
    for (var idx = 0; idx < maxNodeRefLen; idx++) {
	node_ref_match.a[idx] <== branch_to_node_ref.out[idx];
	node_ref_match.b[idx] <== nodeRefHexs[idx];
    }
    node_ref_match.inLen <== nodeRefHexLen;

    component node_ref_len_match = IsEqual();
    node_ref_len_match.in[0] <== nodeRefHexLen;
    node_ref_len_match.in[1] <== nodeRefLenSelector.out[0];

    log(node_ref_match.out);
    log(node_ref_len_match.out);
    
    out <== node_ref_match.out + node_ref_len_match.out;     
}

// Proves inclusion of (key, value) in a MPT
// Assumes all keys have a fixed bit length, so that branches have length 16 only
// and all paths terminate in a leaf
// pathNodes is an array of hashes of nodes in a path from (key, value) to root
template MPTInclusionFixedKeyHexLen(depth, keyHexLen, maxValueHexLen) {
    var maxLeafRlpHexLen = 4 + 66 + 4 + maxValueHexLen;
    var maxBranchRlpHexLen = 1064;
    var maxExtensionRlpHexLen = 4 + 134;

    signal input keyHexs[keyHexLen];
    signal input valueHexs[maxValueHexLen];
    signal input rootHashHexs[64];
    
    // leaf = rlp_prefix           [2]
    //        rlp_length           [0, 2 * ceil(log_8(1 + ceil(log_8(keyHexLen + 2)) + 4 + keyHexLen + 2 +  2 * ceil(log_8(maxValueHexLen)) + maxValueHexLen))]
    //        rlp_path_rlp_prefix  [2]
    //        rlp_path_rlp_length  [0, 2 * ceil(log_8(keyHexLen + 2))]
    //        path_prefix          [1, 2]
    //        path                 [0, keyHexLen]
    //        rlp_value_prefix     [2]
    //        rlp_value_len        [0, 2 * ceil(log_8(maxValueHexLen))]
    //        value                [0, maxValueHexLen]
    signal input leafRlpLengthHexLen;
    signal input leafPathRlpHexLen;
    signal input leafPathPrefixHexLen;
    signal input leafPathHexLen;
    signal input leafRlpValueLenHexLen;
    signal input leafValueLenHexLen;
    signal input leafRlpHexs[maxLeafRlpHexLen];
    
    // extension = rlp_prefix           [2]
    //             rlp_length           [0, 2 * ceil((...))]
    //             rlp_path_rlp_prefix  [2]
    //             rlp_path_rlp_length  [0, 2 * ceil(log_8(keyHexLen + 2))]
    //             path_prefix          [1, 2]
    //             path                 [0, keyHexLen]
    //             rlp_node_ref_prefix  [2]
    //             node_ref             [0, 64]
    // branch = rlp_prefix              [2]
    //          rlp_length              [0, 8]
    //          v0_rlp_prefix           [2]
    //          v0                      [0, 64]
    //          ...
    //          v15_rlp_prefix          [2]
    //          v15                     [0, 64]
    //          vt_prefix               [2]
    signal input nodeRlpLengthHexLen[depth - 1];    
    signal input nodePathRlpHexLen[depth - 1];
    signal input nodePathPrefixHexLen[depth - 1];
    signal input nodePathHexLen[depth - 1];    
    signal input nodeRefHexLen[depth - 1][16]; 
    signal input nodeRlpHexs[depth - 1][maxBranchRlpHexLen];
    
    // index 0 = root
    // 0 = branch, 1 = extension
    signal input nodeTypes[depth - 1];

    signal output out;

    // TODO: validate RLP + prefix len in leaf, branch, ext

    // hash of leaf
    component leafHash = KeccakOrLiteralHex(maxLeafRlpHexLen);
    for (var idx = 0; idx < maxLeafRlpHexLen; idx++) {
	leafHash.in[idx] <== leafRlpHexs[idx];
    }
    leafHash.inLen <== 2 + leafRlpLengthHexLen + 2 + leafPathRlpHexLen + leafPathPrefixHexLen + leafPathHexLen + 2 + leafRlpValueLenHexLen + leafValueLenHexLen;
    for (var idx = 0; idx < 64; idx++) {
	log(leafHash.out[idx]);
    }
    log(1111111111111111111);
    
    // hashes of nodes along path
    var maxNodeRlpHexLen = 1064;
    var maxRounds = (maxNodeRlpHexLen + 272) \ 272;
    component nodeHashes[depth - 1];
    for (var layer = 0; layer < depth - 1; layer++) {
	nodeHashes[layer] = KeccakOrLiteralHex(maxNodeRlpHexLen);
	for (var idx = 0; idx < maxNodeRlpHexLen; idx++) {
	    nodeHashes[layer].in[idx] <== nodeRlpHexs[layer][idx];
	}
	nodeHashes[layer].inLen <== nodeTypes[layer] * (2 + nodeRlpLengthHexLen[layer] + 2 + nodePathRlpHexLen[layer] + nodePathPrefixHexLen[layer] + nodePathHexLen[layer] + 2 + nodeRefHexLen[layer][0] - (2 + nodeRlpLengthHexLen[layer] + 2 * 17 + nodeRefHexLen[layer][0] + nodeRefHexLen[layer][1] + nodeRefHexLen[layer][2] + nodeRefHexLen[layer][3] + nodeRefHexLen[layer][4] + nodeRefHexLen[layer][5] + nodeRefHexLen[layer][6] + nodeRefHexLen[layer][7] + nodeRefHexLen[layer][8] + nodeRefHexLen[layer][9] + nodeRefHexLen[layer][10] + nodeRefHexLen[layer][11] + nodeRefHexLen[layer][12] + nodeRefHexLen[layer][13] + nodeRefHexLen[layer][14] + nodeRefHexLen[layer][15])) + (2 + nodeRlpLengthHexLen[layer] + 2 * 17 + nodeRefHexLen[layer][0] + nodeRefHexLen[layer][1] + nodeRefHexLen[layer][2] + nodeRefHexLen[layer][3] + nodeRefHexLen[layer][4] + nodeRefHexLen[layer][5] + nodeRefHexLen[layer][6] + nodeRefHexLen[layer][7] + nodeRefHexLen[layer][8] + nodeRefHexLen[layer][9] + nodeRefHexLen[layer][10] + nodeRefHexLen[layer][11] + nodeRefHexLen[layer][12] + nodeRefHexLen[layer][13] + nodeRefHexLen[layer][14] + nodeRefHexLen[layer][15]);
    }

    // check rootHash
    component rootHashCheck = ArrayEq(64);
    for (var idx = 0; idx < 64; idx++) {
	rootHashCheck.a[idx] <== rootHashHexs[idx];
	rootHashCheck.b[idx] <== nodeHashes[0].out[idx];
    }
    rootHashCheck.inLen <== 64;

    // compute key fragments
    // if branch: nibble is of size 1
    // if ext: nibble is of size nodePathHexLen[layer]
    signal start[depth];
    start[0] <== 0;
    for (var layer = 0; layer < depth - 1; layer++) {
	// nodeTypes[layer] = 1 if ext, 0 if branch
	start[layer + 1] <== start[layer] + 1 + nodeTypes[layer] * (nodePathHexLen[layer] - 1);
    }

    // constrain Leaf: rlp([prefix (20 or 3) | path, value])    
    component leaf = LeafFixedKeyHexLen(keyHexLen, maxValueHexLen);

    component leafSelector = SubArray(keyHexLen, keyHexLen, 252);
    for (var idx = 0; idx < keyHexLen; idx++) {
	leafSelector.in[idx] <== keyHexs[idx];
    }
    leafSelector.start <== start[depth - 1];
    leafSelector.end <== keyHexLen;
    
    leaf.keyNibbleHexLen <== leafSelector.outLen;
    for (var idx = 0; idx < keyHexLen; idx++) {
	leaf.keyNibbleHexs[idx] <== leafSelector.out[idx];
    }
    for (var idx = 0; idx < maxValueHexLen; idx++) {
	leaf.valueHexs[idx] <== valueHexs[idx];
    }
    leaf.leafRlpLengthHexLen <== leafRlpLengthHexLen;
    leaf.leafPathRlpHexLen <== leafPathRlpHexLen;
    leaf.leafPathPrefixHexLen <== leafPathPrefixHexLen;
    leaf.leafPathHexLen <== leafPathHexLen;
    leaf.leafRlpValueLenHexLen <== leafRlpValueLenHexLen;
    leaf.leafValueLenHexLen <== leafValueLenHexLen;
    for (var idx = 0; idx < maxLeafRlpHexLen; idx++) {
	leaf.leafRlpHexs[idx] <== leafRlpHexs[idx];
    }

    // constrain Extension: rlp([prefix (00 or 1) | path, node_ref])    
    component exts[depth - 1];
    component extKeySelectors[depth - 1];
    for (var layer = 0; layer < depth - 1; layer++) {
	exts[layer] = ExtensionFixedKeyHexLen(keyHexLen, 64);
	
	extKeySelectors[layer] = SubArray(keyHexLen, keyHexLen, 252);
	for (var idx = 0; idx < keyHexLen; idx++) {
	    extKeySelectors[layer].in[idx] <== keyHexs[idx];
	}
	extKeySelectors[layer].start <== start[layer];
	extKeySelectors[layer].end <== start[layer + 1];
	
	exts[layer].keyNibbleHexLen <== nodePathHexLen[layer];
	for (var idx = 0; idx < keyHexLen; idx++) {
	    exts[layer].keyNibbleHexs[idx] <== extKeySelectors[layer].out[idx];
	}
	
	if (layer == depth - 2) {
	    exts[layer].nodeRefHexLen <== leafHash.outLen;
	    for (var idx = 0; idx < 64; idx++) {
		exts[layer].nodeRefHexs[idx] <== leafHash.out[idx];
	    }
	} else {
	    exts[layer].nodeRefHexLen <== nodeHashes[layer + 1].outLen;
	    for (var idx = 0; idx < 64; idx++) {
		exts[layer].nodeRefHexs[idx] <== nodeHashes[layer + 1].out[idx];
	    }
	}

	exts[layer].nodeRlpLengthHexLen <== nodeRlpLengthHexLen[layer];
	exts[layer].nodePathRlpHexLen <== nodePathRlpHexLen[layer];
	exts[layer].nodePathPrefixHexLen <== nodePathPrefixHexLen[layer];
	exts[layer].nodePathHexLen <== nodePathHexLen[layer];
	exts[layer].nodeRefExtHexLen <== nodeRefHexLen[layer][0];
	for (var idx = 0; idx < maxExtensionRlpHexLen; idx++) {
	    exts[layer].nodeRlpHexs[idx] <== nodeRlpHexs[layer][idx];
	}
    }

    // constrain Branch: rlp([node_ref, ..., node_ref, b''])
    component branches[depth - 1];
    component nibbleSelector[depth - 1];
    for (var layer = 0; layer < depth - 1; layer++) {
	branches[layer] = BranchFixedKeyHexLen(64);

	nibbleSelector[layer] = Multiplexer(1, keyHexLen);
	for (var idx = 0; idx < 64; idx++) {
	    nibbleSelector[layer].inp[idx][0] <== keyHexs[idx];
	}
	nibbleSelector[layer].sel <== start[layer];
	
	branches[layer].keyNibble <== nibbleSelector[layer].out[0];

	if (layer == depth - 2) {
	    branches[layer].nodeRefHexLen <== leafHash.outLen;
	    for (var idx = 0; idx < 64; idx++) {
		branches[layer].nodeRefHexs[idx] <== leafHash.out[idx];
	    }
	} else {
	    branches[layer].nodeRefHexLen <== nodeHashes[layer + 1].outLen;
	    for (var idx = 0; idx < 64; idx++) {
		branches[layer].nodeRefHexs[idx] <== nodeHashes[layer + 1].out[idx];
	    }
	}
	
	branches[layer].nodeRlpLengthHexLen <== nodeRlpLengthHexLen[layer];
	// v0, ..., v15 _or_ node_ref
	for (var idx = 0; idx < 16; idx++) {
	    branches[layer].nodeValueLenHexLen[idx] <== nodeRefHexLen[layer][idx];
	}
	for (var idx = 0; idx < maxBranchRlpHexLen; idx++) {
	    branches[layer].nodeRlpHexs[idx] <== nodeRlpHexs[layer][idx];
	}
    }

    signal checksPassed[depth];
    checksPassed[0] <== rootHashCheck.out + leaf.out;
    for (var layer = 0; layer < depth - 1; layer++) {
	checksPassed[layer + 1] <== checksPassed[layer] + branches[layer].out + nodeTypes[layer] * (exts[layer].out - branches[layer].out);
    }
    
    component numChecks = IsEqual();
    numChecks.in[0] <== checksPassed[depth - 1];
    numChecks.in[1] <== 2 * depth + 1;
    out <== numChecks.out;
}
