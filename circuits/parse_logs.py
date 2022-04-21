import argparse
import json
import pprint

TAG_TO_NAME = {
    111111100001: 'LeafCheck',
    111111100002: 'ExtensionCheck',
    111111100003: 'BranchFixedKeyHexLen',
    111111100004: 'EmptyVtBranchCheck',
    111111100005: 'NonTerminalBranchCheck',
    111111100006: 'TerminalBranchCheck',
    111111100007: 'MPTInclusionFixedKeyHexLen',
    111111100008: 'MPTInclusion',
    111111100009: 'MPTInclusionNoBranchTermination',
    222222200001: 'Pad0',
    222222200002: 'ReorderPad101Hex',
    222222200003: 'Keccak256UpdateHex',
    222222200004: 'Keccak256Hex',
    222222200005: 'KeccakOrLiteralHex',
    222222200006: 'KeccakAndPadHex',
    333333300001: 'SubArray',
    333333300002: 'ArrayEq',
    333333300003: 'ShiftLeft',
    333333300004: 'RlpArrayPrefix',
    333333300005: 'RlpFieldPrefix',
    333333300006: 'RlpArrayCheck',
    444444400001: 'Multiplexer',
    555555500001: 'EthBlockHashHex',
    555555500002: 'EthAddressProof',
    555555500003: 'EthStorageProof',
    555555500004: 'EthAddressStorageProof',
}

def parse_next(lines, idx):
    logs = []
    while idx < len(lines):
        if int(lines[idx][:-1]) not in TAG_TO_NAME:
            break
        tag = int(lines[idx][:-1])
        name = TAG_TO_NAME[int(lines[idx][:-1])]
        log, idx = parse_one(lines, idx)
        logs.append(log)
#        print(pprint.pformat(log, width=100, compact=True, depth=1))
    return logs, idx

def parse_one(lines, idx):
    tag = int(lines[idx][:-1])
    
    log = {}
    if tag not in TAG_TO_NAME:
        return {"name": None}, idx
    else:
        log["_name"] = TAG_TO_NAME[tag]
        idx = idx + 1

    if tag == 333333300001:
        log["nIn"] = int(lines[idx][:-1])
        log["maxSelect"] = int(lines[idx + 1][:-1])
        log["nInBits"] = int(lines[idx + 2][:-1])
        log["start"] = int(lines[idx + 3][:-1])
        log["end"] = int(lines[idx + 4][:-1])
        idx = idx + 5

        log["in"] = []
        for idx2 in range(log["nIn"]):
            log["in"].append(int(lines[idx][:-1]))
            idx = idx + 1

        log["inner_logs"], idx = parse_next(lines, idx)
            
        log["outLen"] = int(lines[idx][:-1])
        idx = idx + 1
        log["out"] = []
        for idx2 in range(log["maxSelect"]):
            log["out"].append(int(lines[idx][:-1]))
            idx = idx + 1
    elif tag == 333333300002:
        log["nIn"] = int(lines[idx][:-1])
        log["inLen"] = int(lines[idx + 1][:-1])
        idx = idx + 2

        log["a"] = []
        log["b"] = []
        for idx2 in range(log["nIn"]):
            log["a"].append(int(lines[idx][:-1]))
            idx = idx + 1
        for idx2 in range(log["nIn"]):
            log["b"].append(int(lines[idx][:-1]))
            idx = idx + 1

        log["inner_logs"], idx = parse_next(lines, idx)
        
        log["out"] = int(lines[idx][:-1])
        idx = idx + 1
    elif tag == 333333300003:
        log["nIn"] = int(lines[idx][:-1])
        log["minShift"] = int(lines[idx + 1][:-1])
        log["maxShift"] = int(lines[idx + 2][:-1])
        log["shift"] = int(lines[idx + 3][:-1])
        log["shiftBits"] = int(lines[idx + 4][:-1])
        idx = idx + 5

        log["in"] = []
        for idx2 in range(log["nIn"]):
            log["in"].append(int(lines[idx][:-1]))
            idx = idx + 1

        log["inner_logs"], idx = parse_next(lines, idx)
        
        log["out"] = []
        for idx2 in range(log["nIn"]):
            log["out"].append(int(lines[idx][:-1]))
            idx = idx + 1      
    elif tag == 333333300004:
        log["in"] = []
        log["in"].append(int(lines[idx][:-1]))
        log["in"].append(int(lines[idx + 1][:-1]))
        idx = idx + 2

        log["inner_logs"], idx = parse_next(lines, idx)

        log["isBig"] = int(lines[idx][:-1])
        log["prefixOrTotalHexLen"] = int(lines[idx + 1][:-1])
        log["isValid"] = int(lines[idx + 2][:-1])
        idx = idx + 3
    elif tag == 333333300005:
        log["in"] = []
        log["in"].append(int(lines[idx][:-1]))
        log["in"].append(int(lines[idx + 1][:-1]))
        idx = idx + 2

        log["inner_logs"], idx = parse_next(lines, idx)

        log["isBig"] = int(lines[idx][:-1])
        log["isLiteral"] = int(lines[idx + 1][:-1])
        log["prefixOrTotalHexLen"] = int(lines[idx + 2][:-1])
        log["isValid"] = int(lines[idx + 3][:-1])
        log["isEmptyList"] = int(lines[idx + 4][:-1])
        idx = idx + 5
    elif tag == 333333300006:
        log["maxHexLen"] = int(lines[idx][:-1])
        log["nFields"] = int(lines[idx + 1][:-1])
        log["arrayPrefixMaxHexLen"] = int(lines[idx + 2][:-1])
        idx = idx + 3
        
        log["fieldMinHexLen"] = []
        log["fieldMaxHexLen"] = []
        for idx2 in range(log["nFields"]):
            log["fieldMinHexLen"].append(int(lines[idx][:-1]))
            idx = idx + 1
        for idx2 in range(log["nFields"]):
            log["fieldMaxHexLen"].append(int(lines[idx][:-1]))
            idx = idx + 1

        log["in"] = []
        for idx2 in range(log["maxHexLen"]):
            log["in"].append(int(lines[idx][:-1]))
            idx = idx + 1

        log["inner_logs"], idx = parse_next(lines, idx)

        log["out"] = int(lines[idx][:-1])
        log["totalRlpHexLen"] = int(lines[idx + 1][:-1])
        idx = idx + 2

        log["fieldHexLen"] = []
        for idx2 in range(log["nFields"]):
            log["fieldHexLen"].append(int(lines[idx][:-1]))
            idx = idx + 1
        log["fields"] = []
        for idx2 in range(log["nFields"]):
            log["fields"].append([])
            for idx3 in range(log["maxHexLen"]):
                log["fields"][-1].append(int(lines[idx][:-1]))
                idx = idx + 1
    elif tag == 222222200001:
        log["inLenMin"] = int(lines[idx][:-1])
        log["inLenMax"] = int(lines[idx + 1][:-1])
        log["outLen"] = int(lines[idx + 2][:-1])
        log["inLen"] = int(lines[idx + 3][:-1])
        idx = idx + 4

        log["in"] = []
        for idx2 in range(log["inLenMax"]):
            log["in"].append(int(lines[idx][:-1]))
            idx = idx + 1

        log["inner_logs"], idx = parse_next(lines, idx)

        log["out"] = []
        for idx2 in range(log["outLen"]):
            log["out"].append(int(lines[idx][:-1]))
            idx = idx + 1
    elif tag == 222222200002:
        log["inLenMin"] = int(lines[idx][:-1])
        log["inLenMax"] = int(lines[idx + 1][:-1])
        log["outLen"] = int(lines[idx + 2][:-1])
        log["outLenBits"] = int(lines[idx + 3][:-1])
        log["inLen"] = int(lines[idx + 4][:-1])
        idx = idx + 5

        log["in"] = []
        for idx2 in range(log["inLenMax"]):
            log["in"].append(int(lines[idx][:-1]))
            idx = idx + 1
            
        log["inner_logs"], idx = parse_next(lines, idx)
        
        log["out"] = []            
        for idx2 in range(log["outLen"]):
            log["out"].append(int(lines[idx][:-1]))
            idx = idx + 1
    elif tag == 222222200003:
        log["inHex"] = []
        log["sBits"] = []
        for idx2 in range(272):
            log["inHex"].append(int(lines[idx][:-1]))
            idx = idx + 1
        for idx2 in range(25 * 64):
            log["sBits"].append(int(lines[idx][:-1]))
            idx = idx + 1

        log["inner_logs"], idx = parse_next(lines, idx)
        
        log["out"] = []
        for idx2 in range(25 * 64):
            log["out"].append(int(lines[idx][:-1]))
            idx = idx + 1
    elif tag == 222222200004:
        log["maxRounds"] = int(lines[idx][:-1])
        log["rounds"] = int(lines[idx + 1][:-1])
        idx = idx + 2

        log["inPaddedHex"] = []
        for idx2 in range(log["maxRounds"] * 272):
            log["inPaddedHex"].append(int(lines[idx][:-1]))
            idx = idx + 1

        log["inner_logs"], idx = parse_next(lines, idx)

        log["out"] = []
        for idx2 in range(64):
            log["out"].append(int(lines[idx][:-1]))
            idx = idx + 1
    elif tag == 222222200005:
        log["maxInLen"] = int(lines[idx][:-1])
        log["inLen"] = int(lines[idx + 1][:-1])
        idx = idx + 2

        log["in"] = []
        for idx2 in range(log["maxInLen"]):
            log["in"].append(int(lines[idx][:-1]))
            idx = idx + 1

        log["inner_logs"], idx = parse_next(lines, idx)

        log["outLen"] = int(lines[idx][:-1])
        idx = idx + 1
        log["out"] = []
        for idx2 in range(64):
            log["out"].append(int(lines[idx][:-1]))
            idx = idx + 1
    elif tag == 222222200006:
        log["maxInLen"] = int(lines[idx][:-1])
        log["inLen"] = int(lines[idx + 1][:-1])
        idx = idx + 2

        log["in"] = []
        for idx2 in range(log["maxInLen"]):
            log["in"].append(int(lines[idx][:-1]))
            idx = idx + 1

        log["inner_logs"], idx = parse_next(lines, idx)

        log["out"] = []
        for idx2 in range(64):
            log["out"].append(int(lines[idx][:-1]))
            idx = idx + 1
    elif tag == 111111100003:
        log["maxNodeRefHexLen"] = int(lines[idx][:-1])

        log["keyNibble"] = int(lines[idx + 1][:-1])
        log["nodeRefHexLen"] = int(lines[idx + 2][:-1])
        log["nodeRlpLengthHexLen"] = int(lines[idx + 3][:-1])
        log["maxBranchRlpHexLen"] = int(lines[idx + 4][:-1])
        idx = idx + 5

        log["nodeRefHexs"] = []
        log["nodeValueLenHexLenHexs"] = []
        log["nodeRlpHexs"] = []
        for idx2 in range(log["maxNodeRefHexLen"]):
            log["nodeRefHexs"].append(int(lines[idx][:-1]))
            idx = idx + 1
        for idx2 in range(16):
            log["nodeValueLenHexLenHexs"].append(int(lines[idx][:-1]))
            idx = idx + 1
        for idx2 in range(log["maxBranchRlpHexLen"]):
            log["nodeRlpHexs"].append(int(lines[idx][:-1]))
            idx = idx + 1

        log["inner_logs"], idx = parse_next(lines, idx)
            
        log["out"] = int(lines[idx][:-1])
        log["node_ref_match.out"] = int(lines[idx + 1][:-1])
        log["node_ref_len_match.out"] = int(lines[idx + 2][:-1])
        idx = idx + 3
    elif tag == 111111100005:
        log["maxNodeRefHexLen"] = int(lines[idx][:-1])
        log["maxValueHexLen"] = int(lines[idx + 1][:-1])

        log["keyNibble"] = int(lines[idx + 2][:-1])
        log["nodeRefHexLen"] = int(lines[idx + 3][:-1])
        log["nodeRlpLengthHexLen"] = int(lines[idx + 4][:-1])
        log["nodeVtRlpLenHexLen"] = int(lines[idx + 5][:-1])
        log["nodeVtValueHexLen"] = int(lines[idx + 6][:-1])

        log["maxBranchRlpHexLen"] = int(lines[idx + 7][:-1])
        idx = idx + 8

        log["nodeRefHexs"] = []
        log["nodeValueLenHexLenHexs"] = []
        log["nodeRlpHexs"] = []
        for idx2 in range(log["maxNodeRefHexLen"]):
            log["nodeRefHexs"].append(int(lines[idx][:-1]))
            idx = idx + 1
        for idx2 in range(16):
            log["nodeValueLenHexLenHexs"].append(int(lines[idx][:-1]))
            idx = idx + 1
        for idx2 in range(log["maxBranchRlpHexLen"]):
            log["nodeRlpHexs"].append(int(lines[idx][:-1]))
            idx = idx + 1

        log["inner_logs"], idx = parse_next(lines, idx)
            
        log["out"] = int(lines[idx][:-1])
        log["node_ref_match.out"] = int(lines[idx + 1][:-1])
        log["node_ref_len_match.out"] = int(lines[idx + 2][:-1])
        idx = idx + 3
    elif tag == 111111100006:
        log["maxNodeRefHexLen"] = int(lines[idx][:-1])
        log["maxValueHexLen"] = int(lines[idx + 1][:-1])

        log["valueHexLen"] = int(lines[idx + 2][:-1])
        log["nodeRlpLengthHexLen"] = int(lines[idx + 3][:-1])
        log["nodeVtRlpLenHexLen"] = int(lines[idx + 4][:-1])
        log["nodeVtValueHexLen"] = int(lines[idx + 5][:-1])
        log["maxBranchRlpHexLen"] = int(lines[idx + 6][:-1])
        idx = idx + 7

        log["valueHexs"] = []
        log["nodeValueLenHexLenHexs"] = []
        log["nodeRlpHexs"] = []
        for idx2 in range(log["maxValueHexLen"]):
            log["valueHexs"].append(int(lines[idx][:-1]))
            idx = idx + 1
        for idx2 in range(16):
            log["nodeValueLenHexLenHexs"].append(int(lines[idx][:-1]))
            idx = idx + 1
        for idx2 in range(log["maxBranchRlpHexLen"]):
            log["nodeRlpHexs"].append(int(lines[idx][:-1]))
            idx = idx + 1

        log["inner_logs"], idx = parse_next(lines, idx)
            
        log["out"] = int(lines[idx][:-1])
        log["value_match.out"] = int(lines[idx + 1][:-1])
        log["value_len_match.out"] = int(lines[idx + 2][:-1])
        idx = idx + 3
    elif tag == 111111100008:
        log["maxDepth"] = int(lines[idx][:-1])
        log["maxKeyHexLen"] = int(lines[idx + 1][:-1])
        log["maxValueHexLen"] = int(lines[idx + 2][:-1])
        idx = idx + 3

        log["inner_logs"], idx = parse_next(lines, idx)
        
        log["out"] = int(lines[idx][:-1])
        idx = idx + 1
        log["checksPassed"] = []
        for idx2 in range(log["maxDepth"]):
            log["checksPassed"].append(int(lines[idx][:-1]))
            idx = idx + 1
    elif tag == 444444400001:
        log["wIn"] = int(lines[idx][:-1])
        log["nIn"] = int(lines[idx + 1][:-1])
        log["sel"] = int(lines[idx + 2][:-1])
        idx = idx + 3

        log["inp"] = []
        for i in range(log["nIn"]):
            log["inp"].append([])
            for j in range(log["wIn"]):
                log["inp"][-1].append(int(lines[idx][:-1]))
                idx = idx + 1
                
        log["inner_logs"], idx = parse_next(lines, idx)

        log["out"] = []
        for j in range(log["wIn"]):
            log["out"].append(int(lines[idx][:-1]))
            idx = idx + 1
    elif tag == 111111100001:
        log["maxKeyHexLen"] = int(lines[idx][:-1])
        log["maxValueHexLen"] = int(lines[idx + 1][:-1])

        log["keyNibbleHexLen"] = int(lines[idx + 2][:-1])
        log["leafPathPrefixHexLen"] = int(lines[idx + 3][:-1])
        idx = idx + 4

        log["maxLeafRlpHexLen"] = 4 + log["maxKeyHexLen"] + 2 + 4 + log["maxValueHexLen"]        

        log["keyNibbleHexs"] = []
        log["valueHexs"] = []
        log["leafRlpHexs"] = []
        for idx2 in range(log["maxKeyHexLen"]):
            log["keyNibbleHexs"].append(int(lines[idx][:-1]))
            idx = idx + 1
        for idx2 in range(log["maxValueHexLen"]):
            log["valueHexs"].append(int(lines[idx][:-1]))
            idx = idx + 1
        for idx2 in range(log["maxLeafRlpHexLen"]):
            log["leafRlpHexs"].append(int(lines[idx][:-1]))
            idx = idx + 1

        log["inner_logs"], idx = parse_next(lines, idx)
            
        log["out"] = int(lines[idx][:-1])
        log["key_path_len_match.out"] = int(lines[idx + 1][:-1])
        log["key_path_match.out"] = int(lines[idx + 2][:-1])
        log["leaf_value_match.out"] = int(lines[idx + 3][:-1])
        idx = idx + 4
    elif tag == 111111100002:
        log["maxKeyHexLen"] = int(lines[idx][:-1])
        log["maxNodeRefHexLen"] = int(lines[idx + 1][:-1])

        log["keyNibbleHexLen"] = int(lines[idx + 2][:-1])
        log["nodeRefHexLen"] = int(lines[idx + 3][:-1])
        log["nodePathPrefixHexLen"] = int(lines[idx + 4][:-1])
        idx = idx + 5

        log["maxExtensionRlpHexLen"] = 4 + 2 + log["maxKeyHexLen"] + 2 + log["maxNodeRefHexLen"]        

        log["keyNibbleHexs"] = []
        log["nodeRefHexs"] = []
        log["nodeRlpHexs"] = []
        for idx2 in range(log["maxKeyHexLen"]):
            log["keyNibbleHexs"].append(int(lines[idx][:-1]))
            idx = idx + 1
        for idx2 in range(log["maxNodeRefHexLen"]):
            log["nodeRefHexs"].append(int(lines[idx][:-1]))
            idx = idx + 1
        for idx2 in range(log["maxExtensionRlpHexLen"]):
            log["nodeRlpHexs"].append(int(lines[idx][:-1]))
            idx = idx + 1

        log["inner_logs"], idx = parse_next(lines, idx)
            
        log["out"] = int(lines[idx][:-1])
        log["key_path_len_match.out"] = int(lines[idx + 1][:-1])
        log["key_path_match.out"] = int(lines[idx + 2][:-1])
        log["node_ref_match.out"] = int(lines[idx + 3][:-1])
        log["node_ref_len_match.out"] = int(lines[idx + 4][:-1])
        idx = idx + 5
    elif tag == 111111100004:
        log["maxNodeRefHexLen"] = int(lines[idx][:-1])

        log["keyNibble"] = int(lines[idx + 1][:-1])
        log["nodeRefHexLen"] = int(lines[idx + 2][:-1])
        log["maxBranchRlpHexLen"] = int(lines[idx + 3][:-1])
        idx = idx + 4

        log["nodeRefHexs"] = []
        log["nodeRlpHexs"] = []
        for idx2 in range(log["maxNodeRefHexLen"]):
            log["nodeRefHexs"].append(int(lines[idx][:-1]))
            idx = idx + 1
        for idx2 in range(log["maxBranchRlpHexLen"]):
            log["nodeRlpHexs"].append(int(lines[idx][:-1]))
            idx = idx + 1

        log["inner_logs"], idx = parse_next(lines, idx)
            
        log["out"] = int(lines[idx][:-1])
        log["node_ref_match.out"] = int(lines[idx + 1][:-1])
        log["node_ref_len_match.out"] = int(lines[idx + 2][:-1])
        idx = idx + 3            
    elif tag == 111111100007:
        log["maxDepth"] = int(lines[idx][:-1])
        log["keyHexLen"] = int(lines[idx + 1][:-1])
        log["maxValueHexLen"] = int(lines[idx + 2][:-1])
        idx = idx + 3

        log["inner_logs"], idx = parse_next(lines, idx)
        
        log["out"] = int(lines[idx][:-1])
        log["valueHexLen"] = int(lines[idx + 1][:-1])
        idx = idx + 2
        log["checksPassed"] = []
        for idx2 in range(log["maxDepth"]):
            log["checksPassed"].append(int(lines[idx][:-1]))
            idx = idx + 1
    elif tag == 555555500001:
        log["blockRlpHexs"] = []
        for idx2 in range(1112):
            log["blockRlpHexs"].append(int(lines[idx][:-1]))
            idx = idx + 1

        log["inner_logs"], idx = parse_next(lines, idx)

        log["out"] = int(lines[idx][:-1])
        idx = idx + 1
        log["blockHashHexs"] = []
        log["stateRoot"] = []
        log["transactionsRoot"] = []
        log["receiptsRoot"] = []
        log["number"] = []
        for idx2 in range(64):
            log["blockHashHexs"].append(int(lines[idx][:-1]))
            idx = idx + 1
        log["numberHexLen"] = int(lines[idx][:-1])
        idx = idx + 1
        for idx2 in range(64):
            log["stateRoot"].append(int(lines[idx][:-1]))
            idx = idx + 1
        for idx2 in range(64):
            log["transactionsRoot"].append(int(lines[idx][:-1]))
            idx = idx + 1
        for idx2 in range(64):
            log["receiptsRoot"].append(int(lines[idx][:-1]))
            idx = idx + 1
        for idx2 in range(6):
            log["number"].append(int(lines[idx][:-1]))
            idx = idx + 1
    elif tag == 555555500002:
        log["maxDepth"] = int(lines[idx][:-1])
        idx = idx + 1
        log["stateRootHexs"] = []
        log["addressHexs"] = []
        log["keyFragmentStarts"] = []
        log["addressValueRlpHexs"] = []
        for idx2 in range(64):
            log["stateRootHexs"].append(int(lines[idx][:-1]))
            idx = idx + 1
        for idx2 in range(40):
            log["addressHexs"].append(int(lines[idx][:-1]))
            idx = idx + 1
        for idx2 in range(log["maxDepth"]):
            log["keyFragmentStarts"].append(int(lines[idx][:-1]))
            idx = idx + 1
        for idx2 in range(228):
            log["addressValueRlpHexs"].append(int(lines[idx][:-1]))
            idx = idx + 1

        log["inner_logs"], idx = parse_next(lines, idx)

        log["out"] = int(lines[idx][:-1])
        log["nonceHexLen"] = int(lines[idx + 1][:-1])
        log["balanceHexLen"] = int(lines[idx + 2][:-1])
        idx = idx + 3

        log["nonceHexs"] = []
        log["balanceHexs"] = []
        log["storageRootHexs"] = []
        log["codeHashHexs"] = []
        for idx2 in range(64):
            log["nonceHexs"].append(int(lines[idx][:-1]))
            idx = idx + 1
        for idx2 in range(24):
            log["balanceHexs"].append(int(lines[idx][:-1]))
            idx = idx + 1
        for idx2 in range(64):
            log["storageRootHexs"].append(int(lines[idx][:-1]))
            idx = idx + 1
        for idx2 in range(64):
            log["codeHashHexs"].append(int(lines[idx][:-1]))
            idx = idx + 1
    elif tag == 555555500003:
        log["maxDepth"] = int(lines[idx][:-1])
        idx = idx + 1
        log["storageRootHexs"] = []
        log["slotHexs"] = []
        log["valueRlpHexs"] = []
        log["keyFragmentStarts"] = []
        for idx2 in range(64):
            log["storageRootHexs"].append(int(lines[idx][:-1]))
            idx = idx + 1
        for idx2 in range(64):
            log["slotHexs"].append(int(lines[idx][:-1]))
            idx = idx + 1
        for idx2 in range(66):
            log["valueRlpHexs"].append(int(lines[idx][:-1]))
            idx = idx + 1
        for idx2 in range(log["maxDepth"]):
            log["keyFragmentStarts"].append(int(lines[idx][:-1]))
            idx = idx + 1

        log["inner_logs"], idx = parse_next(lines, idx)

        log["out"] = int(lines[idx][:-1])
        idx = idx + 1
        log["slotValue"] = []
        for idx2 in range(64):
            log["slotValue"].append(int(lines[idx][:-1]))
            idx = idx + 1
        log["valueHexLen"] = int(lines[idx][:-1])
        idx = idx + 1
    elif tag == 555555500004:
        log["blockHash"] = []
        log["slot"] = []
        log["addressMaxDepth"] = int(lines[idx][:-1])
        log["storageMaxDepth"] = int(lines[idx + 1][:-1])
        log["blockHash"].append(int(lines[idx + 2][:-1]))
        log["blockHash"].append(int(lines[idx + 3][:-1]))
        log["address"] = int(lines[idx + 4][:-1])
        log["slot"].append(int(lines[idx + 5][:-1]))
        log["slot"].append(int(lines[idx + 6][:-1]))
        idx = idx + 7
        
        log["inner_logs"], idx = parse_next(lines, idx)

        log["out"] = int(lines[idx][:-1])
        log["block_hash_check.out"] = int(lines[idx + 1][:-1])
        log["address_proof.out"] = int(lines[idx + 2][:-1])
        log["storage_proof.out"] = int(lines[idx + 3][:-1])
        log["slotValue"] = []
        log["slotValue"].append(int(lines[idx + 4][:-1]))
        log["slotValue"].append(int(lines[idx + 5][:-1]))
        log["blockNumber"] = int(lines[idx + 6][:-1])
        idx = idx + 7
    elif tag == 111111100009:
        log["maxDepth"] = int(lines[idx][:-1])
        log["maxKeyHexLen"] = int(lines[idx + 1][:-1])
        log["maxValueHexLen"] = int(lines[idx + 2][:-1])
        log["keyHexLen"] = int(lines[idx + 3][:-1])
        log["depth"] = int(lines[idx + 4][:-1])
        idx = idx + 5

        log["inner_logs"], idx = parse_next(lines, idx)
        
        log["out"] = int(lines[idx][:-1])
        log["valueHexLen"] = int(lines[idx + 1][:-1])
        idx = idx + 2
        log["checksPassed"] = []
        for idx2 in range(log["maxDepth"]):
            log["checksPassed"].append(int(lines[idx][:-1]))
            idx = idx + 1
    else:
        print('Missing tag:', tag)

    return log, idx
    
parser = argparse.ArgumentParser()
parser.add_argument('--file_str', type=str)
parser.add_argument('--depth', type=int, default=4)
args = parser.parse_args()

def main():
    with open(args.file_str, 'r') as f:
        lines = f.readlines()

    logs, idx = parse_next(lines, 0)

    print(pprint.pformat(logs, width=120, compact=True, depth=args.depth))

if __name__ == '__main__':
    main()
