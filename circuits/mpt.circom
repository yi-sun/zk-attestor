pragma circom 2.0.2;

include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/multiplexer.circom";

include "./keccak.circom";
include "./rlp.circom";

function max(a, b) {
    if (a > b) {
	return a;
    }
    return b;
}

template LeafCheck(maxKeyHexLen, maxValueHexLen) {
    var maxLeafRlpHexLen = 4 + (maxKeyHexLen + 2) + 4 + maxValueHexLen;

    // FIXME: Differentiate between cases where keyLen is 0 and where the prefix+nibble is '1b'
    signal input keyNibbleHexLen;
    signal input keyNibbleHexs[maxKeyHexLen];
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

    log(111111100001);
    log(maxKeyHexLen);
    log(maxValueHexLen);

    log(keyNibbleHexLen);
    log(leafRlpLengthHexLen);
    log(leafPathRlpHexLen);
    log(leafPathPrefixHexLen);
    log(leafPathHexLen);
    log(leafRlpValueLenHexLen);
    log(leafValueLenHexLen);

    for (var idx = 0; idx < maxKeyHexLen; idx++) {
	log(keyNibbleHexs[idx]);
    }
    for (var idx = 0; idx < maxValueHexLen; idx++) {
	log(valueHexs[idx]);
    }
    for (var idx = 0; idx < maxLeafRlpHexLen; idx++) {
	log(leafRlpHexs[idx]);
    }

    // * check input hexes are hexes
    component hexCheck[maxLeafRlpHexLen];
    for (var idx = 0; idx < maxLeafRlpHexLen; idx++) {
	hexCheck[idx] = Num2Bits(4);
	hexCheck[idx].in <== leafRlpHexs[idx];
    }
    
    // * [ignore] check validity of RLP encoding    
    // * [ignore] check validity of path prefix
    
    // * check path matches keyNibbles
    component leaf_to_path = SubArray(maxLeafRlpHexLen, maxKeyHexLen, 252);
    for (var idx = 0; idx < maxLeafRlpHexLen; idx++) {
	leaf_to_path.in[idx] <== leafRlpHexs[idx];
    }
    leaf_to_path.start <== 2 + leafRlpLengthHexLen + 2 + leafPathRlpHexLen + leafPathPrefixHexLen;
    leaf_to_path.end <== 2 + leafRlpLengthHexLen + 2 + leafPathRlpHexLen + leafPathPrefixHexLen + leafPathHexLen;

    component key_path_match = ArrayEq(maxKeyHexLen);
    for (var idx = 0; idx < maxKeyHexLen; idx++) {
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
    
    log(out);
    log(key_path_len_match.out);
    log(key_path_match.out);
    log(leaf_value_match.out);
}

template ExtensionCheck(maxKeyHexLen, maxNodeRefHexLen) {
    var maxExtensionRlpHexLen = 4 + 2 + maxKeyHexLen + 2 + maxNodeRefHexLen;

    signal input keyNibbleHexLen;
    signal input keyNibbleHexs[maxKeyHexLen];

    signal input nodeRefHexLen;
    signal input nodeRefHexs[maxNodeRefHexLen];

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

    log(111111100002);
    log(maxKeyHexLen);
    log(maxNodeRefHexLen);

    log(keyNibbleHexLen);
    log(nodeRefHexLen);
    log(nodeRlpLengthHexLen);
    log(nodePathRlpHexLen);
    log(nodePathPrefixHexLen);
    log(nodePathHexLen);
    log(nodeRefExtHexLen);

    for (var idx = 0; idx < maxKeyHexLen; idx++) {
	log(keyNibbleHexs[idx]);
    }
    for (var idx = 0; idx < maxNodeRefHexLen; idx++) {
	log(nodeRefHexs[idx]);
    }
    for (var idx = 0; idx < maxExtensionRlpHexLen; idx++) {
	log(nodeRlpHexs[idx]);
    }
    
    // check input hexs are hexs
    component hexChecks[maxExtensionRlpHexLen];
    for (var idx = 0; idx < maxExtensionRlpHexLen; idx++) {
	hexChecks[idx] = Num2Bits(4);
	hexChecks[idx].in <== nodeRlpHexs[idx];
    }
    
    // * [ignore] check validity of RLP encoding     
    // * [ignore] check validity of path prefix      
    // * check path contains nibbles of key
    component extension_to_path = SubArray(maxExtensionRlpHexLen, maxKeyHexLen, 252);
    for (var idx = 0; idx < maxExtensionRlpHexLen; idx++) {
	extension_to_path.in[idx] <== nodeRlpHexs[idx];
    }
    extension_to_path.start <== 2 + nodeRlpLengthHexLen + 2 + nodePathRlpHexLen + nodePathPrefixHexLen;
    extension_to_path.end <== 2 + nodeRlpLengthHexLen + 2 + nodePathRlpHexLen + nodePathPrefixHexLen + nodePathHexLen;
    
    component key_path_match = ArrayEq(maxKeyHexLen);
    for (var idx = 0; idx < maxKeyHexLen; idx++) {
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
    component extension_to_node_ref = SubArray(maxExtensionRlpHexLen, maxNodeRefHexLen, 252);
    for (var idx = 0; idx < maxExtensionRlpHexLen; idx++) {
	extension_to_node_ref.in[idx] <== nodeRlpHexs[idx];
    }
    extension_to_node_ref.start <== 2 + nodeRlpLengthHexLen + 2 + nodePathRlpHexLen + nodePathPrefixHexLen + nodePathHexLen + 2;
    extension_to_node_ref.end <== 2 + nodeRlpLengthHexLen + 2 + nodePathRlpHexLen + nodePathPrefixHexLen + nodePathHexLen + 2 + nodeRefExtHexLen;
    
    component node_ref_match = ArrayEq(maxNodeRefHexLen);
    for (var idx = 0; idx < maxNodeRefHexLen; idx++) {
	node_ref_match.a[idx] <== extension_to_node_ref.out[idx];
	node_ref_match.b[idx] <== nodeRefHexs[idx];
    }
    node_ref_match.inLen <== nodeRefHexLen;
    
    component node_ref_len_match = IsEqual();
    node_ref_len_match.in[0] <== nodeRefHexLen;
    node_ref_len_match.in[1] <== nodeRefExtHexLen;

    signal node_ref;
    node_ref <== node_ref_match.out * node_ref_len_match.out;
    
    out <== key_path + node_ref;
    log(out);
    log(key_path_len_match.out);
    log(key_path_match.out);	
    log(node_ref_match.out);
    log(node_ref_len_match.out);	
}

template BranchFixedKeyHexLen(maxNodeRefHexLen) {
    var maxBranchRlpHexLen = 1064;

    signal input keyNibble;

    signal input nodeRefHexLen;
    signal input nodeRefHexs[maxNodeRefHexLen];

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

    log(111111100003);
    log(maxNodeRefHexLen);
    log(keyNibble);
    log(nodeRefHexLen);
    log(nodeRlpLengthHexLen);
    log(maxBranchRlpHexLen);
    for (var idx = 0; idx < maxNodeRefHexLen; idx++) {
	log(nodeRefHexs[idx]);
    }
    for (var idx = 0; idx < 16; idx++) {
	log(nodeValueLenHexLen[idx]);
    }
    for (var idx = 0; idx < maxBranchRlpHexLen; idx++) {
	log(nodeRlpHexs[idx]);
    }
    
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
    component branch_to_node_ref = SubArray(maxBranchRlpHexLen, maxNodeRefHexLen, 252);
    for (var idx = 0; idx < maxBranchRlpHexLen; idx++) {
	branch_to_node_ref.in[idx] <== nodeRlpHexs[idx];
    }
    branch_to_node_ref.start <== nodeStartSelector.out[0];
    branch_to_node_ref.end <== nodeStartSelector.out[0] + nodeRefLenSelector.out[0];

    component node_ref_match = ArrayEq(maxNodeRefHexLen);
    for (var idx = 0; idx < maxNodeRefHexLen; idx++) {
	node_ref_match.a[idx] <== branch_to_node_ref.out[idx];
	node_ref_match.b[idx] <== nodeRefHexs[idx];
    }
    node_ref_match.inLen <== nodeRefHexLen;

    component node_ref_len_match = IsEqual();
    node_ref_len_match.in[0] <== nodeRefHexLen;
    node_ref_len_match.in[1] <== nodeRefLenSelector.out[0];

    out <== node_ref_match.out + node_ref_len_match.out;

    log(out);
    log(node_ref_match.out);
    log(node_ref_len_match.out);
}

template EmptyTerminalBranchCheck(maxNodeRefHexLen, maxValueHexLen) {
    var maxBranchRlpHexLen = 1064;
    
    signal input keyNibble;

    signal input nodeRefHexLen;
    signal input nodeRefHexs[maxNodeRefHexLen];

    // branch = rlp_prefix              [2]
    //          rlp_length              [0, 8]
    //          v0_rlp_prefix           [2]
    //          v0                      [0, 64]
    //          ...
    //          v15_rlp_prefix          [2]
    //          v15                     [0, 64]
    //          vt_rlp_prefix           [2]
    //          vt_rlp_len              [0]
    //          vt                      [0]
    signal input nodeRlpLengthHexLen;
    // v0, ..., v15: literal _or_ node_ref
    signal input nodeValueLenHexLen[16];    
    signal input nodeRlpHexs[maxBranchRlpHexLen];
    
    signal output out;
 
    log(111111100004);
    log(maxNodeRefHexLen);
    log(maxValueHexLen);
    
    log(keyNibble);
    log(nodeRefHexLen);
    log(nodeRlpLengthHexLen);

    log(maxBranchRlpHexLen);
    for (var idx = 0; idx < maxNodeRefHexLen; idx++) {
	log(nodeRefHexs[idx]);
    }
    for (var idx = 0; idx < 16; idx++) {
	log(nodeValueLenHexLen[idx]);
    }
    for (var idx = 0; idx < maxBranchRlpHexLen; idx++) {
	log(nodeRlpHexs[idx]);
    }
   
    // check input hexs are hexs
    component keyNibbleCheck = Num2Bits(4);
    keyNibbleCheck.in <== keyNibble;

    component hexChecks[maxBranchRlpHexLen];
    for (var idx = 0; idx < maxBranchRlpHexLen; idx++) {
	hexChecks[idx] = Num2Bits(4);
	hexChecks[idx].in <== nodeRlpHexs[idx];
    }
    
    // * [ignore] check validity of RLP encoding
    // * [ignore] check validity of inputs

    // find starting point of node_refs and values
    signal nodeRefStartHexIdx[16];
    nodeRefStartHexIdx[0] <== 2 + nodeRlpLengthHexLen + 2;
    for (var idx = 1; idx < 16; idx++) {
	nodeRefStartHexIdx[idx] <== nodeRefStartHexIdx[idx - 1] + nodeValueLenHexLen[idx - 1] + 2;
    }

    // check node_ref at index of nibble / value matches child / value
    component nodeStartSelector = Multiplexer(1, 16);
    component nodeRefLenSelector = Multiplexer(1, 16);
    for (var idx = 0; idx < 16; idx++) {
	nodeStartSelector.inp[idx][0] <== nodeRefStartHexIdx[idx];
	nodeRefLenSelector.inp[idx][0] <== nodeValueLenHexLen[idx];
    }
    nodeStartSelector.sel <== keyNibble;
    nodeRefLenSelector.sel <== keyNibble;

    // find the node_ref at the index of nibble / value
    component branch_to_node_ref = SubArray(maxBranchRlpHexLen, maxNodeRefHexLen, 252);
    for (var idx = 0; idx < maxBranchRlpHexLen; idx++) {
	branch_to_node_ref.in[idx] <== nodeRlpHexs[idx];
    }
    branch_to_node_ref.start <== nodeStartSelector.out[0];
    branch_to_node_ref.end <== nodeStartSelector.out[0] + nodeRefLenSelector.out[0];
    
    component node_ref_match = ArrayEq(maxNodeRefHexLen);
    for (var idx = 0; idx < maxNodeRefHexLen; idx++) {
	node_ref_match.a[idx] <== branch_to_node_ref.out[idx];
	node_ref_match.b[idx] <== nodeRefHexs[idx];
    }
    node_ref_match.inLen <== nodeRefHexLen;

    component node_ref_len_match = IsEqual();
    node_ref_len_match.in[0] <== nodeRefHexLen;
    node_ref_len_match.in[1] <== nodeRefLenSelector.out[0];

    out <== node_ref_match.out + node_ref_len_match.out;

    log(out);
    log(node_ref_match.out);
    log(node_ref_len_match.out);
}

template NonTerminalBranchCheck(maxNodeRefHexLen, maxValueHexLen) {
    var maxBranchRlpHexLen = 1064 + 2 + maxValueHexLen;
    
    signal input keyNibble;

    signal input nodeRefHexLen;
    signal input nodeRefHexs[maxNodeRefHexLen];

    // branch = rlp_prefix              [2]
    //          rlp_length              [0, 8]
    //          v0_rlp_prefix           [2]
    //          v0                      [0, 64]
    //          ...
    //          v15_rlp_prefix          [2]
    //          v15                     [0, 64]
    //          vt_rlp_prefix           [2]
    //          vt_rlp_len              [0, 2 * ceil(log_8(maxValueHexLen / 2))]
    //          vt                      [0, maxValueHexLen]    
    signal input nodeRlpLengthHexLen;
    // v0, ..., v15: literal _or_ node_ref
    signal input nodeValueLenHexLen[16];
    // vt: NULL or rlp(value)
    signal input nodeVtRlpLenHexLen;
    signal input nodeVtValueHexLen;
    
    signal input nodeRlpHexs[maxBranchRlpHexLen];
    
    signal output out;

    log(111111100005);
    log(maxNodeRefHexLen);
    log(maxValueHexLen);
    
    log(keyNibble);
    log(nodeRefHexLen);
    log(nodeRlpLengthHexLen);
    log(nodeVtRlpLenHexLen);
    log(nodeVtValueHexLen);
    
    log(maxBranchRlpHexLen);
    for (var idx = 0; idx < maxNodeRefHexLen; idx++) {
	log(nodeRefHexs[idx]);
    }
    for (var idx = 0; idx < 16; idx++) {
	log(nodeValueLenHexLen[idx]);
    }
    for (var idx = 0; idx < maxBranchRlpHexLen; idx++) {
	log(nodeRlpHexs[idx]);
    }
    
    // check input hexs are hexs
    component keyNibbleCheck = Num2Bits(4);
    keyNibbleCheck.in <== keyNibble;

    component hexChecks[maxBranchRlpHexLen];
    for (var idx = 0; idx < maxBranchRlpHexLen; idx++) {
	hexChecks[idx] = Num2Bits(4);
	hexChecks[idx].in <== nodeRlpHexs[idx];
    }
    
    // * [ignore] check validity of RLP encoding
    // * [ignore] check validity of inputs

    // find starting point of node_refs and values
    signal nodeRefStartHexIdx[16];
    nodeRefStartHexIdx[0] <== 2 + nodeRlpLengthHexLen + 2;
    for (var idx = 1; idx < 16; idx++) {
	nodeRefStartHexIdx[idx] <== nodeRefStartHexIdx[idx - 1] + nodeValueLenHexLen[idx - 1] + 2;
    }

    // check node_ref at index of nibble / value matches child / value
    component nodeStartSelector = Multiplexer(1, 16);
    component nodeRefLenSelector = Multiplexer(1, 16);
    for (var idx = 0; idx < 16; idx++) {
	nodeStartSelector.inp[idx][0] <== nodeRefStartHexIdx[idx];
	nodeRefLenSelector.inp[idx][0] <== nodeValueLenHexLen[idx];
    }
    nodeStartSelector.sel <== keyNibble;
    nodeRefLenSelector.sel <== keyNibble;

    // find the node_ref at the index of nibble / value
    component branch_to_node_ref = SubArray(maxBranchRlpHexLen, maxNodeRefHexLen, 252);
    for (var idx = 0; idx < maxBranchRlpHexLen; idx++) {
	branch_to_node_ref.in[idx] <== nodeRlpHexs[idx];
    }
    branch_to_node_ref.start <== nodeStartSelector.out[0];
    branch_to_node_ref.end <== nodeStartSelector.out[0] + nodeRefLenSelector.out[0];
    
    component node_ref_match = ArrayEq(maxNodeRefHexLen);
    for (var idx = 0; idx < maxNodeRefHexLen; idx++) {
	node_ref_match.a[idx] <== branch_to_node_ref.out[idx];
	node_ref_match.b[idx] <== nodeRefHexs[idx];
    }
    node_ref_match.inLen <== nodeRefHexLen;

    component node_ref_len_match = IsEqual();
    node_ref_len_match.in[0] <== nodeRefHexLen;
    node_ref_len_match.in[1] <== nodeRefLenSelector.out[0];

    out <== node_ref_match.out + node_ref_len_match.out;

    log(out);
    log(node_ref_match.out);
    log(node_ref_len_match.out);
}

template TerminalBranchCheck(maxNodeRefHexLen, maxValueHexLen) {
    var maxBranchRlpHexLen = 1064 + 2 + maxValueHexLen;

    signal input valueHexLen;
    signal input valueHexs[maxValueHexLen];
    
    // branch = rlp_prefix              [2]
    //          rlp_length              [0, 8]
    //          v0_rlp_prefix           [2]
    //          v0                      [0, 64]
    //          ...
    //          v15_rlp_prefix          [2]
    //          v15                     [0, 64]
    //          vt_rlp_prefix           [2]
    //          vt_rlp_len              [0, 2 * ceil(log_8(maxValueHexLen / 2))]
    //          vt                      [0, maxValueHexLen]    
    signal input nodeRlpLengthHexLen;
    // v0, ..., v15: literal _or_ node_ref
    signal input nodeValueLenHexLen[16];
    // vt: NULL or rlp(value)
    signal input nodeVtRlpLenHexLen;
    signal input nodeVtValueHexLen;
    
    signal input nodeRlpHexs[maxBranchRlpHexLen];
    
    signal output out;

    log(111111100006);
    log(maxNodeRefHexLen);
    log(maxValueHexLen);
    
    log(valueHexLen);
    log(nodeRlpLengthHexLen);
    log(nodeVtRlpLenHexLen);
    log(nodeVtValueHexLen);
    
    log(maxBranchRlpHexLen);    
    for (var idx = 0; idx < maxValueHexLen; idx++) {
	log(valueHexs[idx]);
    }
    for (var idx = 0; idx < 16; idx++) {
	log(nodeValueLenHexLen[idx]);
    }
    for (var idx = 0; idx < maxBranchRlpHexLen; idx++) {
	log(nodeRlpHexs[idx]);
    }
    
    // check input hexs are hexs
    component hexChecks[maxBranchRlpHexLen];
    for (var idx = 0; idx < maxBranchRlpHexLen; idx++) {
	hexChecks[idx] = Num2Bits(4);
	hexChecks[idx].in <== nodeRlpHexs[idx];
    }

    component valueHexChecks[maxValueHexLen];
    for (var idx = 0; idx < maxValueHexLen; idx++) {
	valueHexChecks[idx] = Num2Bits(4);
	valueHexChecks[idx].in <== valueHexs[idx];
    }	
    
    // * [ignore] check validity of RLP encoding
    // * [ignore] check validity of inputs

    // find starting point of value
    signal valueStartHexIdx;
    valueStartHexIdx <== 2 + nodeRlpLengthHexLen + 2 + 2 * 16 + nodeValueLenHexLen[0] + nodeValueLenHexLen[1] + nodeValueLenHexLen[2] + nodeValueLenHexLen[3] + nodeValueLenHexLen[4] + nodeValueLenHexLen[5] + nodeValueLenHexLen[6] + nodeValueLenHexLen[7] + nodeValueLenHexLen[8] + nodeValueLenHexLen[9] + nodeValueLenHexLen[10] + nodeValueLenHexLen[11] + nodeValueLenHexLen[12] + nodeValueLenHexLen[13] + nodeValueLenHexLen[14] + nodeValueLenHexLen[15] + nodeVtRlpLenHexLen;

    // check vt matches value
    component branch_to_value = SubArray(maxBranchRlpHexLen, maxValueHexLen, 252);
    for (var idx = 0; idx < maxBranchRlpHexLen; idx++) {
	branch_to_value.in[idx] <== nodeRlpHexs[idx];
    }
    branch_to_value.start <== valueStartHexIdx;
    branch_to_value.end <== valueStartHexIdx + nodeVtValueHexLen;
    
    component value_match = ArrayEq(maxValueHexLen);
    for (var idx = 0; idx < maxValueHexLen; idx++) {
	value_match.a[idx] <== branch_to_value.out[idx];
	value_match.b[idx] <== valueHexs[idx];
    }
    value_match.inLen <== valueHexLen;

    component value_len_match = IsEqual();
    value_len_match.in[0] <== valueHexLen;
    value_len_match.in[1] <== nodeVtValueHexLen;

    out <== value_match.out + value_len_match.out;

    log(out);
    log(value_match.out);
    log(value_len_match.out);
}

// Proves inclusion of (key, value) in a MPT
// Assumes all keys have a fixed bit length, so that branches have length 16 only
// and all paths terminate in a leaf
template MPTInclusionFixedKeyHexLen(maxDepth, keyHexLen, maxValueHexLen) {
    var maxLeafRlpHexLen = 4 + (keyHexLen + 2) + 4 + maxValueHexLen;
    var maxBranchRlpHexLen = 1064;
    var maxExtensionRlpHexLen = 4 + 2 + keyHexLen + 2 + 64;
    
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
    signal input nodeRlpLengthHexLen[maxDepth - 1];    
    signal input nodePathRlpHexLen[maxDepth - 1];
    signal input nodePathPrefixHexLen[maxDepth - 1];
    signal input nodePathHexLen[maxDepth - 1];    
    signal input nodeRefHexLen[maxDepth - 1][16]; 
    signal input nodeRlpHexs[maxDepth - 1][maxBranchRlpHexLen];
    
    // index 0 = root
    // 0 = branch, 1 = extension
    signal input nodeTypes[maxDepth - 1];
    signal input depth;
    
    signal output out;

    log(111111100007);
    log(maxDepth);
    log(keyHexLen);
    log(maxValueHexLen);

    component depthCheck = LessEqThan(10);
    depthCheck.in[0] <== depth;
    depthCheck.in[1] <== maxDepth;
    depthCheck.out === 1;
    
    // TODO: validate RLP + prefix len in leaf, branch, ext

    // hash of leaf
    component leafHash = KeccakOrLiteralHex(maxLeafRlpHexLen);
    for (var idx = 0; idx < maxLeafRlpHexLen; idx++) {
	leafHash.in[idx] <== leafRlpHexs[idx];
    }
    leafHash.inLen <== 2 + leafRlpLengthHexLen + 2 + leafPathRlpHexLen + leafPathPrefixHexLen + leafPathHexLen + 2 + leafRlpValueLenHexLen + leafValueLenHexLen;
    
    // hashes of nodes along path
    var maxNodeRlpHexLen = 1064;
    var maxRounds = (maxNodeRlpHexLen + 272) \ 272;
    component nodeHashes[maxDepth - 1];
    for (var layer = 0; layer < maxDepth - 1; layer++) {
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
    // if ext: nibble is of size nodePathHexLen[layer] unless nodePathHexLen[layer] == 0, in which case it is of size 1 (prefix len 1, path len 1)
    component isLiteralPath[maxDepth - 1];
    for (var layer = 0; layer < maxDepth - 1; layer++) {
    	isLiteralPath[layer] = IsZero();
	isLiteralPath[layer].in <== nodePathHexLen[layer];
    }

    signal start[maxDepth];
    start[0] <== 0;
    for (var layer = 0; layer < maxDepth - 1; layer++) {
	// nodeTypes[layer] = 1 if ext, 0 if branch
	// if extension and nodePathHexLen[layer] == 0, then the RLP of the prefix + path is a
	// 2-hex literal (1 prefix, 1 path), so we should advance the start by 1 hexes
	start[layer + 1] <== start[layer] + 1 - nodeTypes[layer] + nodeTypes[layer] * (nodePathHexLen[layer] + isLiteralPath[layer].out);
    }

    // constrain Leaf: rlp([prefix (20 or 3) | path, value])    
    component leaf = LeafCheck(keyHexLen, maxValueHexLen);

    component leafStartSelector = Multiplexer(1, maxDepth);
    for (var idx = 0; idx < maxDepth; idx++) {
	leafStartSelector.inp[idx][0] <== start[idx];
    }
    leafStartSelector.sel <== depth - 1;
	
    component leafSelector = SubArray(keyHexLen, keyHexLen, 252);
    for (var idx = 0; idx < keyHexLen; idx++) {
	leafSelector.in[idx] <== keyHexs[idx];
    }
    leafSelector.start <== leafStartSelector.out[0];
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
    
    // masks for depth selector
    component depthEq[maxDepth];
    for (var layer = 0; layer < maxDepth; layer++) {
	depthEq[layer] = IsEqual();
	depthEq[layer].in[0] <== depth;
	depthEq[layer].in[1] <== layer + 1;
    }

    // constrain Extension: rlp([prefix (00 or 1) | path, node_ref])    
    component exts[maxDepth - 1];
    component extKeySelectors[maxDepth - 1];
    for (var layer = 0; layer < maxDepth - 1; layer++) {
	exts[layer] = ExtensionCheck(keyHexLen, 64);
	
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

	// if layer + 1 > depth, we do not care what values are filled in
	if (layer == maxDepth - 2) {
	    exts[layer].nodeRefHexLen <== depthEq[layer + 1].out * leafHash.outLen;
	    for (var idx = 0; idx < 64; idx++) {
		exts[layer].nodeRefHexs[idx] <== depthEq[layer + 1].out * leafHash.out[idx];
	    }
	} else {
	    exts[layer].nodeRefHexLen <== depthEq[layer + 1].out * (leafHash.outLen - nodeHashes[layer + 1].outLen) + nodeHashes[layer + 1].outLen;
	    for (var idx = 0; idx < 64; idx++) {
		exts[layer].nodeRefHexs[idx] <== depthEq[layer + 1].out * (leafHash.out[idx] - nodeHashes[layer + 1].out[idx]) + nodeHashes[layer + 1].out[idx];
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
    component branches[maxDepth - 1];
    component nibbleSelector[maxDepth - 1];
    for (var layer = 0; layer < maxDepth - 1; layer++) {
	branches[layer] = BranchFixedKeyHexLen(64);

	nibbleSelector[layer] = Multiplexer(1, keyHexLen);
	for (var idx = 0; idx < keyHexLen; idx++) {
	    nibbleSelector[layer].inp[idx][0] <== keyHexs[idx];
	}
	nibbleSelector[layer].sel <== start[layer];
	
	branches[layer].keyNibble <== nibbleSelector[layer].out[0];

	// if layer + 1 > depth, we do not care what values are filled in
	if (layer == maxDepth - 2) {
	    branches[layer].nodeRefHexLen <== depthEq[layer + 1].out * leafHash.outLen;
	    for (var idx = 0; idx < 64; idx++) {
		branches[layer].nodeRefHexs[idx] <== depthEq[layer + 1].out * leafHash.out[idx];
	    }
	} else {
	    branches[layer].nodeRefHexLen <== depthEq[layer + 1].out * (leafHash.outLen - nodeHashes[layer + 1].outLen) + nodeHashes[layer + 1].outLen;
	    for (var idx = 0; idx < 64; idx++) {
		branches[layer].nodeRefHexs[idx] <== depthEq[layer + 1].out * (leafHash.out[idx] - nodeHashes[layer + 1].out[idx]) + nodeHashes[layer + 1].out[idx];
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

    component checksPassed = Multiplexer(1, maxDepth);
    checksPassed.inp[0][0] <== rootHashCheck.out + leaf.out;
    for (var layer = 0; layer < maxDepth - 1; layer++) {
	checksPassed.inp[layer + 1][0] <== checksPassed.inp[layer][0] + branches[layer].out + nodeTypes[layer] * (exts[layer].out - branches[layer].out);
    }
    checksPassed.sel <== depth - 1;

    component numChecks = IsEqual();
    numChecks.in[0] <== checksPassed.out[0];
    numChecks.in[1] <== 2 * depth + 1;
    out <== numChecks.out;

    log(out);
    for (var idx = 0; idx < maxDepth; idx++) {
	log(checksPassed.inp[idx][0]);
    }
}

// Proves inclusion of (key, value) in a MPT
// Allows variable length keys, so paths may terminate in either a leaf or branch
template MPTInclusion(maxDepth, maxKeyHexLen, maxValueHexLen) {
    var maxLeafRlpHexLen = 4 + (maxKeyHexLen + 2) + 4 + maxValueHexLen;
    var maxBranchRlpHexLen = 1064 + 2 + maxValueHexLen;
    var maxNodeRefHexLen = 64;
    var maxExtensionRlpHexLen = 4 + 2 + maxKeyHexLen + 2 + maxNodeRefHexLen;

    signal input keyHexLen;
    signal input keyHexs[maxKeyHexLen];

    signal input valueHexLen;
    signal input valueHexs[maxValueHexLen];
    signal input rootHashHexs[64];
    
    // leaf = rlp_prefix           [2]
    //        rlp_length           [0, 2 * ceil(log_8(1 + ceil(log_8(maxKeyHexLen + 2)) + 4 + maxKeyHexLen + 2 +  2 * ceil(log_8(maxValueHexLen)) + maxValueHexLen))]
    //        rlp_path_rlp_prefix  [2]
    //        rlp_path_rlp_length  [0, 2 * ceil(log_8(maxKeyHexLen + 2))]
    //        path_prefix          [1, 2]
    //        path                 [0, maxKeyHexLen]
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

    // terminal branch info
    signal input terminalBranchRlpLengthHexLen;    
    signal input terminalBranchNodeRefHexLen[16];
    signal input terminalBranchVtRlpLenHexLen;
    signal input terminalBranchVtValueHexLen;
    
    signal input terminalBranchRlpHexs[maxBranchRlpHexLen];
        
    // extension = rlp_prefix           [2]
    //             rlp_length           [0, 2 * ceil((...))]
    //             rlp_path_rlp_prefix  [2]
    //             rlp_path_rlp_length  [0, 2 * ceil(log_8(maxKeyHexLen + 2))]
    //             path_prefix          [1, 2]
    //             path                 [0, maxKeyHexLen]
    //             rlp_node_ref_prefix  [2]
    //             node_ref             [0, 64]
    // branch = rlp_prefix              [2]
    //          rlp_length              [0, 8]
    //          v0_rlp_prefix           [2]
    //          v0                      [0, 64]
    //          ...
    //          v15_rlp_prefix          [2]
    //          v15                     [0, 64]
    //          vt_rlp_prefix           [2]
    //          vt_rlp_len              [0, 2 * ceil(log_8(maxValueHexLen / 2))]
    //          vt                      [0, maxValueHexLen]
    signal input nodeRlpLengthHexLen[maxDepth - 1];    
    signal input nodePathRlpHexLen[maxDepth - 1];
    signal input nodePathPrefixHexLen[maxDepth - 1];
    signal input nodePathHexLen[maxDepth - 1];    
    signal input nodeRefHexLen[maxDepth - 1][16];
    signal input nodeVtRlpLenHexLen[maxDepth - 1];
    signal input nodeVtValueHexLen[maxDepth - 1];
    
    signal input nodeRlpHexs[maxDepth - 1][maxBranchRlpHexLen];
    
    // index 0 = root
    // 0 = branch, 1 = extension
    signal input nodeTypes[maxDepth - 1];
    signal input isTerminalBranch;
    signal input depth;
    
    signal output out;

    log(111111100008);
    log(maxDepth);
    log(maxKeyHexLen);
    log(maxValueHexLen);
    
    component depthCheck = LessEqThan(10);
    depthCheck.in[0] <== depth;
    depthCheck.in[1] <== maxDepth;
    depthCheck.out === 1;
    
    // TODO: validate RLP + prefix len in leaf, branch, ext

    // compute key fragments
    // if branch: nibble is of size 1
    // if ext: nibble is of size nodePathHexLen[layer]
    signal start[maxDepth];
    start[0] <== 0;
    for (var layer = 0; layer < maxDepth - 1; layer++) {
	// nodeTypes[layer] = 1 if ext, 0 if branch
	start[layer + 1] <== start[layer] + 1 + nodeTypes[layer] * (nodePathHexLen[layer] - 1);
    }

    // hash of leaf or terminal branch
    var maxTerminalRlpHexLen = max(maxLeafRlpHexLen, maxBranchRlpHexLen);
    component terminalHash = KeccakOrLiteralHex(maxTerminalRlpHexLen);
    if (maxLeafRlpHexLen > maxBranchRlpHexLen) {
	for (var idx = 0; idx < maxBranchRlpHexLen; idx++) {
	    terminalHash.in[idx] <== isTerminalBranch * (terminalBranchRlpHexs[idx] - leafRlpHexs[idx]) + leafRlpHexs[idx];
	}
	for (var idx = maxBranchRlpHexLen; idx < maxLeafRlpHexLen; idx++) {
	    terminalHash.in[idx] <== leafRlpHexs[idx];
	}
    } else {
	for (var idx = 0; idx < maxLeafRlpHexLen; idx++) {
	    terminalHash.in[idx] <== isTerminalBranch * (terminalBranchRlpHexs[idx] - leafRlpHexs[idx]) + leafRlpHexs[idx];
	}
	for (var idx = maxLeafRlpHexLen; idx < maxBranchRlpHexLen; idx++) {
	    terminalHash.in[idx] <== terminalBranchRlpHexs[idx];
	}
    }
    terminalHash.inLen <== isTerminalBranch * ((2 + terminalBranchRlpLengthHexLen + 2 * 17 + terminalBranchNodeRefHexLen[0] + terminalBranchNodeRefHexLen[1] + terminalBranchNodeRefHexLen[2] + terminalBranchNodeRefHexLen[3] + terminalBranchNodeRefHexLen[4] + terminalBranchNodeRefHexLen[5] + terminalBranchNodeRefHexLen[6] + terminalBranchNodeRefHexLen[7] + terminalBranchNodeRefHexLen[8] + terminalBranchNodeRefHexLen[9] + terminalBranchNodeRefHexLen[10] + terminalBranchNodeRefHexLen[11] + terminalBranchNodeRefHexLen[12] + terminalBranchNodeRefHexLen[13] + terminalBranchNodeRefHexLen[14] + terminalBranchNodeRefHexLen[15] + terminalBranchVtRlpLenHexLen + terminalBranchVtValueHexLen) - (2 + leafRlpLengthHexLen + 2 + leafPathRlpHexLen + leafPathPrefixHexLen + leafPathHexLen + 2 + leafRlpValueLenHexLen + leafValueLenHexLen)) + (2 + leafRlpLengthHexLen + 2 + leafPathRlpHexLen + leafPathPrefixHexLen + leafPathHexLen + 2 + leafRlpValueLenHexLen + leafValueLenHexLen);

    // hashes of nodes along path
    var maxNodeRlpHexLen = maxBranchRlpHexLen;
    var maxRounds = (maxNodeRlpHexLen + 272) \ 272;
    component nodeHashes[maxDepth - 1];
    for (var layer = 0; layer < maxDepth - 1; layer++) {
	nodeHashes[layer] = KeccakOrLiteralHex(maxNodeRlpHexLen);
	for (var idx = 0; idx < maxNodeRlpHexLen; idx++) {
	    nodeHashes[layer].in[idx] <== nodeRlpHexs[layer][idx];
	}
	nodeHashes[layer].inLen <== nodeTypes[layer] * (2 + nodeRlpLengthHexLen[layer] + 2 + nodePathRlpHexLen[layer] + nodePathPrefixHexLen[layer] + nodePathHexLen[layer] + 2 + nodeRefHexLen[layer][0] - (2 + nodeRlpLengthHexLen[layer] + 2 * 17 + nodeRefHexLen[layer][0] + nodeRefHexLen[layer][1] + nodeRefHexLen[layer][2] + nodeRefHexLen[layer][3] + nodeRefHexLen[layer][4] + nodeRefHexLen[layer][5] + nodeRefHexLen[layer][6] + nodeRefHexLen[layer][7] + nodeRefHexLen[layer][8] + nodeRefHexLen[layer][9] + nodeRefHexLen[layer][10] + nodeRefHexLen[layer][11] + nodeRefHexLen[layer][12] + nodeRefHexLen[layer][13] + nodeRefHexLen[layer][14] + nodeRefHexLen[layer][15] + nodeVtRlpLenHexLen[layer] + nodeVtValueHexLen[layer])) + (2 + nodeRlpLengthHexLen[layer] + 2 * 17 + nodeRefHexLen[layer][0] + nodeRefHexLen[layer][1] + nodeRefHexLen[layer][2] + nodeRefHexLen[layer][3] + nodeRefHexLen[layer][4] + nodeRefHexLen[layer][5] + nodeRefHexLen[layer][6] + nodeRefHexLen[layer][7] + nodeRefHexLen[layer][8] + nodeRefHexLen[layer][9] + nodeRefHexLen[layer][10] + nodeRefHexLen[layer][11] + nodeRefHexLen[layer][12] + nodeRefHexLen[layer][13] + nodeRefHexLen[layer][14] + nodeRefHexLen[layer][15] + nodeVtRlpLenHexLen[layer] + nodeVtValueHexLen[layer]);
    }

    // check rootHash
    // TODO: What if the whole MPT is a single leaf?
    component rootHashCheck = ArrayEq(64);
    for (var idx = 0; idx < 64; idx++) {
	rootHashCheck.a[idx] <== rootHashHexs[idx];
	rootHashCheck.b[idx] <== nodeHashes[0].out[idx];
    }
    rootHashCheck.inLen <== 64;

    // constrain Leaf: rlp([prefix (20 or 3) | path, value])    
    component leaf = LeafCheck(maxKeyHexLen, maxValueHexLen);

    component leafStartSelector = Multiplexer(1, maxDepth);
    for (var idx = 0; idx < maxDepth; idx++) {
	leafStartSelector.inp[idx][0] <== start[idx];
    }
    leafStartSelector.sel <== depth - 1;

    component leafSelector = SubArray(maxKeyHexLen, maxKeyHexLen, 252);
    for (var idx = 0; idx < maxKeyHexLen; idx++) {
	leafSelector.in[idx] <== keyHexs[idx];
    }
    leafSelector.start <== leafStartSelector.out[0];
    leafSelector.end <== keyHexLen;

    leaf.keyNibbleHexLen <== leafSelector.outLen;
    for (var idx = 0; idx < maxKeyHexLen; idx++) {
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

    // check TerminalBranch
    component terminalBranch = TerminalBranchCheck(maxNodeRefHexLen, maxValueHexLen);
    terminalBranch.valueHexLen <== valueHexLen;
    for (var idx = 0; idx < maxValueHexLen; idx++) {
	terminalBranch.valueHexs[idx] <== valueHexs[idx];
    }
    terminalBranch.nodeRlpLengthHexLen <== terminalBranchRlpLengthHexLen;
    for (var idx = 0; idx < 16; idx++) {
	terminalBranch.nodeValueLenHexLen[idx] <== terminalBranchNodeRefHexLen[idx];
    }
    terminalBranch.nodeVtRlpLenHexLen <== terminalBranchVtRlpLenHexLen;
    terminalBranch.nodeVtValueHexLen <== terminalBranchVtValueHexLen;
    for (var idx = 0; idx < maxBranchRlpHexLen; idx++) {
	terminalBranch.nodeRlpHexs[idx] <== terminalBranchRlpHexs[idx];
    }
    
    // masks for depth selector
    component depthEq[maxDepth];
    for (var layer = 0; layer < maxDepth; layer++) {
	depthEq[layer] = IsEqual();
	depthEq[layer].in[0] <== depth;
	depthEq[layer].in[1] <== layer + 1;
    }

    // constrain Extension: rlp([prefix (00 or 1) | path, node_ref])    
    component exts[maxDepth - 1];
    component extKeySelectors[maxDepth - 1];
    for (var layer = 0; layer < maxDepth - 1; layer++) {
	exts[layer] = ExtensionCheck(maxKeyHexLen, 64);
	
	extKeySelectors[layer] = SubArray(maxKeyHexLen, maxKeyHexLen, 252);
	for (var idx = 0; idx < maxKeyHexLen; idx++) {
	    extKeySelectors[layer].in[idx] <== keyHexs[idx];
	}
	extKeySelectors[layer].start <== start[layer];
	extKeySelectors[layer].end <== start[layer + 1];
	
	exts[layer].keyNibbleHexLen <== nodePathHexLen[layer];
	for (var idx = 0; idx < maxKeyHexLen; idx++) {
	    exts[layer].keyNibbleHexs[idx] <== extKeySelectors[layer].out[idx];
	}

	// if layer + 1 > depth, we do not care what values are filled in
	if (layer == maxDepth - 2) {
	    exts[layer].nodeRefHexLen <== depthEq[layer + 1].out * terminalHash.outLen;
	    for (var idx = 0; idx < 64; idx++) {
		exts[layer].nodeRefHexs[idx] <== depthEq[layer + 1].out * terminalHash.out[idx];
	    }
	} else {
	    exts[layer].nodeRefHexLen <== depthEq[layer + 1].out * (terminalHash.outLen - nodeHashes[layer + 1].outLen) + nodeHashes[layer + 1].outLen;
	    for (var idx = 0; idx < 64; idx++) {
		exts[layer].nodeRefHexs[idx] <== depthEq[layer + 1].out * (terminalHash.out[idx] - nodeHashes[layer + 1].out[idx]) + nodeHashes[layer + 1].out[idx];
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
    component branches[maxDepth - 1];
    component nibbleSelector[maxDepth - 1];
    for (var layer = 0; layer < maxDepth - 1; layer++) {
	branches[layer] = NonTerminalBranchCheck(64, maxValueHexLen);

	nibbleSelector[layer] = Multiplexer(1, maxKeyHexLen);
	for (var idx = 0; idx < maxKeyHexLen; idx++) {
	    nibbleSelector[layer].inp[idx][0] <== keyHexs[idx];
	}
	nibbleSelector[layer].sel <== start[layer];
	
	branches[layer].keyNibble <== nibbleSelector[layer].out[0];

	// if layer + 1 > depth, we do not care what values are filled in
	if (layer == maxDepth - 2) {
	    branches[layer].nodeRefHexLen <== depthEq[layer + 1].out * terminalHash.outLen;
	    for (var idx = 0; idx < 64; idx++) {
		branches[layer].nodeRefHexs[idx] <== depthEq[layer + 1].out * terminalHash.out[idx];
	    }
	} else {
	    branches[layer].nodeRefHexLen <== depthEq[layer + 1].out * (terminalHash.outLen - nodeHashes[layer + 1].outLen) + nodeHashes[layer + 1].outLen;
	    for (var idx = 0; idx < 64; idx++) {
		branches[layer].nodeRefHexs[idx] <== depthEq[layer + 1].out * (terminalHash.out[idx] - nodeHashes[layer + 1].out[idx]) + nodeHashes[layer + 1].out[idx];
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
	branches[layer].nodeVtRlpLenHexLen <== nodeVtRlpLenHexLen[layer];
	branches[layer].nodeVtValueHexLen <== nodeVtValueHexLen[layer];
    }

    component checksPassed = Multiplexer(1, maxDepth);
    checksPassed.inp[0][0] <== rootHashCheck.out + leaf.out + isTerminalBranch * (terminalBranch.out - leaf.out);
    for (var layer = 0; layer < maxDepth - 1; layer++) {
	checksPassed.inp[layer + 1][0] <== checksPassed.inp[layer][0] + branches[layer].out + nodeTypes[layer] * (exts[layer].out - branches[layer].out);
    }
    checksPassed.sel <== depth - 1;

    component numChecks = IsEqual();
    numChecks.in[0] <== checksPassed.out[0];
    numChecks.in[1] <== 2 * depth + 1;
    out <== numChecks.out;

    log(out);
    for (var idx = 0; idx < maxDepth; idx++) {
	log(checksPassed.inp[idx][0]);
    }
}

// Proves inclusion of (key, value) in a MPT
// Allows variable length keys
// Does not allow branch terminating paths
template MPTInclusionNoBranchTermination(maxDepth, maxKeyHexLen, maxValueHexLen) {
    var maxLeafRlpHexLen = 4 + (maxKeyHexLen + 2) + 4 + maxValueHexLen;
    var maxBranchRlpHexLen = 1064;
    var maxNodeRefHexLen = 64;
    var maxExtensionRlpHexLen = 4 + 2 + maxKeyHexLen + 2 + maxNodeRefHexLen;

    signal input keyHexLen;
    signal input keyHexs[maxKeyHexLen];

    signal input valueHexLen;
    signal input valueHexs[maxValueHexLen];
    signal input rootHashHexs[64];
    
    // leaf = rlp_prefix           [2]
    //        rlp_length           [0, 2 * ceil(log_8(1 + ceil(log_8(maxKeyHexLen + 2)) + 4 + maxKeyHexLen + 2 +  2 * ceil(log_8(maxValueHexLen)) + maxValueHexLen))]
    //        rlp_path_rlp_prefix  [2]
    //        rlp_path_rlp_length  [0, 2 * ceil(log_8(maxKeyHexLen + 2))]
    //        path_prefix          [1, 2]
    //        path                 [0, maxKeyHexLen]
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
    //             rlp_path_rlp_length  [0, 2 * ceil(log_8(maxKeyHexLen + 2))]
    //             path_prefix          [1, 2]
    //             path                 [0, maxKeyHexLen]
    //             rlp_node_ref_prefix  [2]
    //             node_ref             [0, 64]
    // branch = rlp_prefix              [2]
    //          rlp_length              [0, 8]
    //          v0_rlp_prefix           [2]
    //          v0                      [0, 64]
    //          ...
    //          v15_rlp_prefix          [2]
    //          v15                     [0, 64]
    //          vt_rlp_prefix           [2]
    //          vt_rlp_len              [0]
    //          vt                      [0]
    signal input nodeRlpLengthHexLen[maxDepth - 1];    
    signal input nodePathRlpHexLen[maxDepth - 1];
    signal input nodePathPrefixHexLen[maxDepth - 1];
    signal input nodePathHexLen[maxDepth - 1];    
    signal input nodeRefHexLen[maxDepth - 1][16];
    
    signal input nodeRlpHexs[maxDepth - 1][maxBranchRlpHexLen];
    
    // index 0 = root
    // 0 = branch, 1 = extension
    signal input nodeTypes[maxDepth - 1];
    signal input depth;
    
    signal output out;

    log(111111100009);
    log(maxDepth);
    log(maxKeyHexLen);
    log(maxValueHexLen);
    
    component depthCheck = LessEqThan(10);
    depthCheck.in[0] <== depth;
    depthCheck.in[1] <== maxDepth;
    depthCheck.out === 1;
    
    // TODO: validate RLP + prefix len in leaf, branch, ext

    // compute key fragments
    // if branch: nibble is of size 1
    // if ext: nibble is of size nodePathHexLen[layer]
    signal start[maxDepth];
    start[0] <== 0;
    for (var layer = 0; layer < maxDepth - 1; layer++) {
	// nodeTypes[layer] = 1 if ext, 0 if branch
	start[layer + 1] <== start[layer] + 1 + nodeTypes[layer] * (nodePathHexLen[layer] - 1);
    }

    // hash of terminal leaf
    component terminalHash = KeccakOrLiteralHex(maxLeafRlpHexLen);
    for (var idx = 0; idx < maxLeafRlpHexLen; idx++) {
	terminalHash.in[idx] <== leafRlpHexs[idx];
    }
    terminalHash.inLen <== 2 + leafRlpLengthHexLen + 2 + leafPathRlpHexLen + leafPathPrefixHexLen + leafPathHexLen + 2 + leafRlpValueLenHexLen + leafValueLenHexLen;

    // hashes of nodes along path
    var maxNodeRlpHexLen = maxBranchRlpHexLen;
    var maxRounds = (maxNodeRlpHexLen + 272) \ 272;
    component nodeHashes[maxDepth - 1];
    for (var layer = 0; layer < maxDepth - 1; layer++) {
	nodeHashes[layer] = KeccakOrLiteralHex(maxNodeRlpHexLen);
	for (var idx = 0; idx < maxNodeRlpHexLen; idx++) {
	    nodeHashes[layer].in[idx] <== nodeRlpHexs[layer][idx];
	}
	nodeHashes[layer].inLen <== nodeTypes[layer] * (2 + nodeRlpLengthHexLen[layer] + 2 + nodePathRlpHexLen[layer] + nodePathPrefixHexLen[layer] + nodePathHexLen[layer] + 2 + nodeRefHexLen[layer][0] - (2 + nodeRlpLengthHexLen[layer] + 2 * 17 + nodeRefHexLen[layer][0] + nodeRefHexLen[layer][1] + nodeRefHexLen[layer][2] + nodeRefHexLen[layer][3] + nodeRefHexLen[layer][4] + nodeRefHexLen[layer][5] + nodeRefHexLen[layer][6] + nodeRefHexLen[layer][7] + nodeRefHexLen[layer][8] + nodeRefHexLen[layer][9] + nodeRefHexLen[layer][10] + nodeRefHexLen[layer][11] + nodeRefHexLen[layer][12] + nodeRefHexLen[layer][13] + nodeRefHexLen[layer][14] + nodeRefHexLen[layer][15])) + (2 + nodeRlpLengthHexLen[layer] + 2 * 17 + nodeRefHexLen[layer][0] + nodeRefHexLen[layer][1] + nodeRefHexLen[layer][2] + nodeRefHexLen[layer][3] + nodeRefHexLen[layer][4] + nodeRefHexLen[layer][5] + nodeRefHexLen[layer][6] + nodeRefHexLen[layer][7] + nodeRefHexLen[layer][8] + nodeRefHexLen[layer][9] + nodeRefHexLen[layer][10] + nodeRefHexLen[layer][11] + nodeRefHexLen[layer][12] + nodeRefHexLen[layer][13] + nodeRefHexLen[layer][14] + nodeRefHexLen[layer][15]);
    }

    // check rootHash
    // TODO: What if the whole MPT is a single leaf?
    component rootHashCheck = ArrayEq(64);
    for (var idx = 0; idx < 64; idx++) {
	rootHashCheck.a[idx] <== rootHashHexs[idx];
	rootHashCheck.b[idx] <== nodeHashes[0].out[idx];
    }
    rootHashCheck.inLen <== 64;

    // constrain Leaf: rlp([prefix (20 or 3) | path, value])    
    component leaf = LeafCheck(maxKeyHexLen, maxValueHexLen);

    component leafStartSelector = Multiplexer(1, maxDepth);
    for (var idx = 0; idx < maxDepth; idx++) {
	leafStartSelector.inp[idx][0] <== start[idx];
    }
    leafStartSelector.sel <== depth - 1;

    component leafSelector = SubArray(maxKeyHexLen, maxKeyHexLen, 252);
    for (var idx = 0; idx < maxKeyHexLen; idx++) {
	leafSelector.in[idx] <== keyHexs[idx];
    }
    leafSelector.start <== leafStartSelector.out[0];
    leafSelector.end <== keyHexLen;

    leaf.keyNibbleHexLen <== leafSelector.outLen;
    for (var idx = 0; idx < maxKeyHexLen; idx++) {
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
    
    // masks for depth selector
    component depthEq[maxDepth];
    for (var layer = 0; layer < maxDepth; layer++) {
	depthEq[layer] = IsEqual();
	depthEq[layer].in[0] <== depth;
	depthEq[layer].in[1] <== layer + 1;
    }

    // constrain Extension: rlp([prefix (00 or 1) | path, node_ref])    
    component exts[maxDepth - 1];
    component extKeySelectors[maxDepth - 1];
    for (var layer = 0; layer < maxDepth - 1; layer++) {
	exts[layer] = ExtensionCheck(maxKeyHexLen, 64);
	
	extKeySelectors[layer] = SubArray(maxKeyHexLen, maxKeyHexLen, 252);
	for (var idx = 0; idx < maxKeyHexLen; idx++) {
	    extKeySelectors[layer].in[idx] <== keyHexs[idx];
	}
	extKeySelectors[layer].start <== start[layer];
	extKeySelectors[layer].end <== start[layer + 1];
	
	exts[layer].keyNibbleHexLen <== nodePathHexLen[layer];
	for (var idx = 0; idx < maxKeyHexLen; idx++) {
	    exts[layer].keyNibbleHexs[idx] <== extKeySelectors[layer].out[idx];
	}

	// if layer + 1 > depth, we do not care what values are filled in
	if (layer == maxDepth - 2) {
	    exts[layer].nodeRefHexLen <== depthEq[layer + 1].out * terminalHash.outLen;
	    for (var idx = 0; idx < 64; idx++) {
		exts[layer].nodeRefHexs[idx] <== depthEq[layer + 1].out * terminalHash.out[idx];
	    }
	} else {
	    exts[layer].nodeRefHexLen <== depthEq[layer + 1].out * (terminalHash.outLen - nodeHashes[layer + 1].outLen) + nodeHashes[layer + 1].outLen;
	    for (var idx = 0; idx < 64; idx++) {
		exts[layer].nodeRefHexs[idx] <== depthEq[layer + 1].out * (terminalHash.out[idx] - nodeHashes[layer + 1].out[idx]) + nodeHashes[layer + 1].out[idx];
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
    component branches[maxDepth - 1];
    component nibbleSelector[maxDepth - 1];
    for (var layer = 0; layer < maxDepth - 1; layer++) {
	branches[layer] = EmptyTerminalBranchCheck(64, maxValueHexLen);

	nibbleSelector[layer] = Multiplexer(1, maxKeyHexLen);
	for (var idx = 0; idx < maxKeyHexLen; idx++) {
	    nibbleSelector[layer].inp[idx][0] <== keyHexs[idx];
	}
	nibbleSelector[layer].sel <== start[layer];
	
	branches[layer].keyNibble <== nibbleSelector[layer].out[0];

	// if layer + 1 > depth, we do not care what values are filled in
	if (layer == maxDepth - 2) {
	    branches[layer].nodeRefHexLen <== depthEq[layer + 1].out * terminalHash.outLen;
	    for (var idx = 0; idx < 64; idx++) {
		branches[layer].nodeRefHexs[idx] <== depthEq[layer + 1].out * terminalHash.out[idx];
	    }
	} else {
	    branches[layer].nodeRefHexLen <== depthEq[layer + 1].out * (terminalHash.outLen - nodeHashes[layer + 1].outLen) + nodeHashes[layer + 1].outLen;
	    for (var idx = 0; idx < 64; idx++) {
		branches[layer].nodeRefHexs[idx] <== depthEq[layer + 1].out * (terminalHash.out[idx] - nodeHashes[layer + 1].out[idx]) + nodeHashes[layer + 1].out[idx];
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

    component checksPassed = Multiplexer(1, maxDepth);
    checksPassed.inp[0][0] <== rootHashCheck.out + leaf.out;
    for (var layer = 0; layer < maxDepth - 1; layer++) {
	checksPassed.inp[layer + 1][0] <== checksPassed.inp[layer][0] + branches[layer].out + nodeTypes[layer] * (exts[layer].out - branches[layer].out);
    }
    checksPassed.sel <== depth - 1;

    component numChecks = IsEqual();
    numChecks.in[0] <== checksPassed.out[0];
    numChecks.in[1] <== 2 * depth + 1;
    out <== numChecks.out;

    log(out);
    for (var idx = 0; idx < maxDepth; idx++) {
	log(checksPassed.inp[idx][0]);
    }
}

