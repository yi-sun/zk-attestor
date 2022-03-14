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
    333333300001: 'SubArray',
    33333330001: 'SubArray',
    333333300002: 'ArrayEq',
    444444400001: 'Multiplexer'
}

def parse_next(lines, idx):
    logs = []
    while idx < len(lines):
        if int(lines[idx][:-2]) not in TAG_TO_NAME:
            break
        tag = int(lines[idx][:-2])
        name = TAG_TO_NAME[int(lines[idx][:-2])]
        log, idx = parse_one(lines, idx)
        logs.append(log)
#        print(pprint.pformat(log, width=100, compact=True, depth=1))
    return logs, idx

def parse_one(lines, idx):
    tag = int(lines[idx][:-2])
    
    log = {}
    if tag not in TAG_TO_NAME:
        return {"name": None}, idx
    else:
        log["_name"] = TAG_TO_NAME[tag]
        idx = idx + 1
        
    if tag in [333333300001, 33333330001]:
        log["nIn"] = int(lines[idx][:-2])
        log["maxSelect"] = int(lines[idx + 1][:-2])
        log["nInBits"] = int(lines[idx + 2][:-2])
        log["start"] = int(lines[idx + 3][:-2])
        log["end"] = int(lines[idx + 4][:-2])
        idx = idx + 5

        log["in"] = []
        for idx2 in range(log["nIn"]):
            log["in"].append(int(lines[idx][:-2]))
            idx = idx + 1

        log["inner_logs"], idx = parse_next(lines, idx)
            
        log["outLen"] = int(lines[idx][:-2])
        idx = idx + 1
        log["out"] = []
        for idx2 in range(log["maxSelect"]):
            log["out"].append(int(lines[idx][:-2]))
            idx = idx + 1
    elif tag == 333333300002:
        log["nIn"] = int(lines[idx][:-2])
        log["inLen"] = int(lines[idx + 1][:-2])
        idx = idx + 2

        log["a"] = []
        log["b"] = []
        for idx2 in range(log["nIn"]):
            log["a"].append(int(lines[idx][:-2]))
            idx = idx + 1
        for idx2 in range(log["nIn"]):
            log["b"].append(int(lines[idx][:-2]))
            idx = idx + 1

        log["inner_logs"], idx = parse_next(lines, idx)
        
        log["out"] = int(lines[idx][:-2])
        idx = idx + 1
    elif tag == 222222200001:
        log["inLenMin"] = int(lines[idx][:-2])
        log["inLenMax"] = int(lines[idx + 1][:-2])
        log["outLen"] = int(lines[idx + 2][:-2])
        log["inLen"] = int(lines[idx + 3][:-2])
        idx = idx + 4

        log["in"] = []
        for idx2 in range(log["inLenMax"]):
            log["in"].append(int(lines[idx][:-2]))
            idx = idx + 1

        log["inner_logs"], idx = parse_next(lines, idx)

        log["out"] = []
        for idx2 in range(log["outLen"]):
            log["out"].append(int(lines[idx][:-2]))
            idx = idx + 1
    elif tag == 222222200002:
        log["inLenMin"] = int(lines[idx][:-2])
        log["inLenMax"] = int(lines[idx + 1][:-2])
        log["outLen"] = int(lines[idx + 2][:-2])
        log["outLenBits"] = int(lines[idx + 3][:-2])
        log["inLen"] = int(lines[idx + 4][:-2])
        idx = idx + 5

        log["in"] = []
        for idx2 in range(log["inLenMax"]):
            log["in"].append(int(lines[idx][:-2]))
            idx = idx + 1
            
        log["inner_logs"], idx = parse_next(lines, idx)
        
        log["out"] = []            
        for idx2 in range(log["outLen"]):
            log["out"].append(int(lines[idx][:-2]))
            idx = idx + 1
    elif tag == 222222200003:
        log["inHex"] = []
        log["sBits"] = []
        for idx2 in range(272):
            log["inHex"].append(int(lines[idx][:-2]))
            idx = idx + 1
        for idx2 in range(25 * 64):
            log["sBits"].append(int(lines[idx][:-2]))
            idx = idx + 1

        log["inner_logs"], idx = parse_next(lines, idx)
        
        log["out"] = []
        for idx2 in range(25 * 64):
            log["out"].append(int(lines[idx][:-2]))
            idx = idx + 1
    elif tag == 222222200004:
        log["maxRounds"] = int(lines[idx][:-2])
        log["rounds"] = int(lines[idx + 1][:-2])
        idx = idx + 2

        log["inPaddedHex"] = []
        for idx2 in range(log["maxRounds"] * 272):
            log["inPaddedHex"].append(int(lines[idx][:-2]))
            idx = idx + 1

        log["inner_logs"], idx = parse_next(lines, idx)

        log["out"] = []
        for idx2 in range(256):
            log["out"].append(int(lines[idx][:-2]))
            idx = idx + 1
    elif tag == 222222200005:
        log["maxInLen"] = int(lines[idx][:-2])
        log["inLen"] = int(lines[idx + 1][:-2])
        idx = idx + 2

        log["in"] = []
        for idx2 in range(log["maxInLen"]):
            log["in"].append(int(lines[idx][:-2]))
            idx = idx + 1

        log["inner_logs"], idx = parse_next(lines, idx)

        log["outLen"] = int(lines[idx][:-2])
        idx = idx + 1
        log["out"] = []
        for idx2 in range(64):
            log["out"].append(int(lines[idx][:-2]))
            idx = idx + 1
    elif tag == 111111100001:
        log["maxKeyHexLen"] = int(lines[idx][:-2])
        log["maxValueHexLen"] = int(lines[idx + 1][:-2])

        log["keyNibbleHexLen"] = int(lines[idx + 2][:-2])
        log["leafRlpLengthHexLen"] = int(lines[idx + 3][:-2])
        log["leafPathRlpHexLen"] = int(lines[idx + 4][:-2])
        log["leafPathPrefixHexLen"] = int(lines[idx + 5][:-2])
        log["leafPathHexLen"] = int(lines[idx + 6][:-2])
        log["leafRlpValueLenHexLen"] = int(lines[idx + 7][:-2])
        log["leafValueLenHexLen"] = int(lines[idx + 8][:-2])
        idx = idx + 9

        log["maxLeafRlpHexLen"] = 4 + log["maxKeyHexLen"] + 2 + 4 + log["maxValueHexLen"]        

        log["keyNibbleHexs"] = []
        log["valueHexs"] = []
        log["leafRlpHexs"] = []
        for idx2 in range(log["maxKeyHexLen"]):
            log["keyNibbleHexs"].append(int(lines[idx][:-2]))
            idx = idx + 1
        for idx2 in range(log["maxValueHexLen"]):
            log["valueHexs"].append(int(lines[idx][:-2]))
            idx = idx + 1
        for idx2 in range(log["maxLeafRlpHexLen"]):
            log["leafRlpHexs"].append(int(lines[idx][:-2]))
            idx = idx + 1

        log["inner_logs"], idx = parse_next(lines, idx)
            
        log["out"] = int(lines[idx][:-2])
        log["key_path_len_match.out"] = int(lines[idx + 1][:-2])
        log["key_path_match.out"] = int(lines[idx + 2][:-2])
        log["leaf_value_match.out"] = int(lines[idx + 3][:-2])
        idx = idx + 4
    elif tag == 111111100002:
        log["maxKeyHexLen"] = int(lines[idx][:-2])
        log["maxNodeRefHexLen"] = int(lines[idx + 1][:-2])

        log["keyNibbleHexLen"] = int(lines[idx + 2][:-2])
        log["nodeRefHexLen"] = int(lines[idx + 3][:-2])
        log["nodeRlpLengthHexLen"] = int(lines[idx + 4][:-2])
        log["nodePathRlpHexLen"] = int(lines[idx + 5][:-2])
        log["nodePathPrefixHexLen"] = int(lines[idx + 6][:-2])
        log["nodePathHexLen"] = int(lines[idx + 7][:-2])
        log["nodeRefExtHexLen"] = int(lines[idx + 8][:-2])
        idx = idx + 9

        log["maxExtensionRlpHexLen"] = 4 + 2 + log["maxKeyHexLen"] + 2 + log["maxNodeRefHexLen"]        

        log["keyNibbleHexs"] = []
        log["nodeRefHexs"] = []
        log["nodeRlpHexs"] = []
        for idx2 in range(log["maxKeyHexLen"]):
            log["keyNibbleHexs"].append(int(lines[idx][:-2]))
            idx = idx + 1
        for idx2 in range(log["maxNodeRefHexLen"]):
            log["nodeRefHexs"].append(int(lines[idx][:-2]))
            idx = idx + 1
        for idx2 in range(log["maxExtensionRlpHexLen"]):
            log["nodeRlpHexs"].append(int(lines[idx][:-2]))
            idx = idx + 1

        log["inner_logs"], idx = parse_next(lines, idx)
            
        log["out"] = int(lines[idx][:-2])
        log["key_path_len_match.out"] = int(lines[idx + 1][:-2])
        log["key_path_match.out"] = int(lines[idx + 2][:-2])
        log["node_ref_match.out"] = int(lines[idx + 3][:-2])
        log["node_ref_len_match.out"] = int(lines[idx + 4][:-2])
        idx = idx + 5
    elif tag == 111111100003:
        log["maxNodeRefHexLen"] = int(lines[idx][:-2])

        log["keyNibble"] = int(lines[idx + 1][:-2])
        log["nodeRefHexLen"] = int(lines[idx + 2][:-2])
        log["nodeRlpLengthHexLen"] = int(lines[idx + 3][:-2])
        log["maxBranchRlpHexLen"] = int(lines[idx + 4][:-2])
        idx = idx + 5

        log["nodeRefHexs"] = []
        log["nodeValueLenHexLenHexs"] = []
        log["nodeRlpHexs"] = []
        for idx2 in range(log["maxNodeRefHexLen"]):
            log["nodeRefHexs"].append(int(lines[idx][:-2]))
            idx = idx + 1
        for idx2 in range(16):
            log["nodeValueLenHexLenHexs"].append(int(lines[idx][:-2]))
            idx = idx + 1
        for idx2 in range(log["maxBranchRlpHexLen"]):
            log["nodeRlpHexs"].append(int(lines[idx][:-2]))
            idx = idx + 1

        log["inner_logs"], idx = parse_next(lines, idx)
            
        log["out"] = int(lines[idx][:-2])
        log["node_ref_match.out"] = int(lines[idx + 1][:-2])
        log["node_ref_len_match.out"] = int(lines[idx + 2][:-2])
        idx = idx + 3
    elif tag == 111111100004:
        log["maxNodeRefHexLen"] = int(lines[idx][:-2])

        log["keyNibble"] = int(lines[idx + 1][:-2])
        log["nodeRefHexLen"] = int(lines[idx + 2][:-2])
        log["nodeRlpLengthHexLen"] = int(lines[idx + 3][:-2])
        log["maxBranchRlpHexLen"] = int(lines[idx + 4][:-2])
        idx = idx + 5

        log["nodeRefHexs"] = []
        log["nodeValueLenHexLenHexs"] = []
        log["nodeRlpHexs"] = []
        for idx2 in range(log["maxNodeRefHexLen"]):
            log["nodeRefHexs"].append(int(lines[idx][:-2]))
            idx = idx + 1
        for idx2 in range(16):
            log["nodeValueLenHexLenHexs"].append(int(lines[idx][:-2]))
            idx = idx + 1
        for idx2 in range(log["maxBranchRlpHexLen"]):
            log["nodeRlpHexs"].append(int(lines[idx][:-2]))
            idx = idx + 1

        log["inner_logs"], idx = parse_next(lines, idx)
            
        log["out"] = int(lines[idx][:-2])
        log["node_ref_match.out"] = int(lines[idx + 1][:-2])
        log["node_ref_len_match.out"] = int(lines[idx + 2][:-2])
        idx = idx + 3
    elif tag == 111111100005:
        log["maxNodeRefHexLen"] = int(lines[idx][:-2])
        log["maxValueHexLen"] = int(lines[idx + 1][:-2])

        log["keyNibble"] = int(lines[idx + 2][:-2])
        log["nodeRefHexLen"] = int(lines[idx + 3][:-2])
        log["nodeRlpLengthHexLen"] = int(lines[idx + 4][:-2])
        log["nodeVtRlpLenHexLen"] = int(lines[idx + 5][:-2])
        log["nodeVtValueHexLen"] = int(lines[idx + 6][:-2])

        log["maxBranchRlpHexLen"] = int(lines[idx + 7][:-2])
        idx = idx + 8

        log["nodeRefHexs"] = []
        log["nodeValueLenHexLenHexs"] = []
        log["nodeRlpHexs"] = []
        for idx2 in range(log["maxNodeRefHexLen"]):
            log["nodeRefHexs"].append(int(lines[idx][:-2]))
            idx = idx + 1
        for idx2 in range(16):
            log["nodeValueLenHexLenHexs"].append(int(lines[idx][:-2]))
            idx = idx + 1
        for idx2 in range(log["maxBranchRlpHexLen"]):
            log["nodeRlpHexs"].append(int(lines[idx][:-2]))
            idx = idx + 1

        log["inner_logs"], idx = parse_next(lines, idx)
            
        log["out"] = int(lines[idx][:-2])
        log["node_ref_match.out"] = int(lines[idx + 1][:-2])
        log["node_ref_len_match.out"] = int(lines[idx + 2][:-2])
        idx = idx + 3
    elif tag == 111111100006:
        log["maxNodeRefHexLen"] = int(lines[idx][:-2])
        log["maxValueHexLen"] = int(lines[idx + 1][:-2])

        log["valueHexLen"] = int(lines[idx + 2][:-2])
        log["nodeRlpLengthHexLen"] = int(lines[idx + 3][:-2])
        log["nodeVtRlpLenHexLen"] = int(lines[idx + 4][:-2])
        log["nodeVtValueHexLen"] = int(lines[idx + 5][:-2])
        log["maxBranchRlpHexLen"] = int(lines[idx + 6][:-2])
        idx = idx + 7

        log["valueHexs"] = []
        log["nodeValueLenHexLenHexs"] = []
        log["nodeRlpHexs"] = []
        for idx2 in range(log["maxValueHexLen"]):
            log["valueHexs"].append(int(lines[idx][:-2]))
            idx = idx + 1
        for idx2 in range(16):
            log["nodeValueLenHexLenHexs"].append(int(lines[idx][:-2]))
            idx = idx + 1
        for idx2 in range(log["maxBranchRlpHexLen"]):
            log["nodeRlpHexs"].append(int(lines[idx][:-2]))
            idx = idx + 1

        log["inner_logs"], idx = parse_next(lines, idx)
            
        log["out"] = int(lines[idx][:-2])
        log["value_match.out"] = int(lines[idx + 1][:-2])
        log["value_len_match.out"] = int(lines[idx + 2][:-2])
        idx = idx + 3
    elif tag == 111111100007:
        log["maxDepth"] = int(lines[idx][:-2])
        log["keyHexLen"] = int(lines[idx + 1][:-2])
        log["maxValueHexLen"] = int(lines[idx + 2][:-2])
        idx = idx + 3

        log["inner_logs"], idx = parse_next(lines, idx)
        
        log["out"] = int(lines[idx][:-2])
        idx = idx + 1
        log["checksPassed"] = []
        for idx2 in range(log["maxDepth"]):
            log["checksPassed"].append(int(lines[idx][:-2]))
            idx = idx + 1
    elif tag == 111111100008:
        log["maxDepth"] = int(lines[idx][:-2])
        log["maxKeyHexLen"] = int(lines[idx + 1][:-2])
        log["maxValueHexLen"] = int(lines[idx + 2][:-2])
        idx = idx + 3

        log["inner_logs"], idx = parse_next(lines, idx)
        
        log["out"] = int(lines[idx][:-2])
        idx = idx + 1
        log["checksPassed"] = []
        for idx2 in range(log["maxDepth"]):
            log["checksPassed"].append(int(lines[idx][:-2]))
            idx = idx + 1
    elif tag == 111111100009:
        log["maxDepth"] = int(lines[idx][:-2])
        log["maxKeyHexLen"] = int(lines[idx + 1][:-2])
        log["maxValueHexLen"] = int(lines[idx + 2][:-2])
        log["depth"] = int(lines[idx + 3][:-2])
        idx = idx + 4

        log["inner_logs"], idx = parse_next(lines, idx)
        
        log["out"] = int(lines[idx][:-2])
        idx = idx + 1
        log["checksPassed"] = []
        for idx2 in range(log["maxDepth"]):
            log["checksPassed"].append(int(lines[idx][:-2]))
            idx = idx + 1
    elif tag == 444444400001:
        log["wIn"] = int(lines[idx][:-2])
        log["nIn"] = int(lines[idx + 1][:-2])
        log["sel"] = int(lines[idx + 2][:-2])
        idx = idx + 3

        log["inp"] = []
        for i in range(log["nIn"]):
            log["inp"].append([])
            for j in range(log["wIn"]):
                log["inp"][-1].append(int(lines[idx][:-2]))
                idx = idx + 1
                
        log["inner_logs"], idx = parse_next(lines, idx)

        log["out"] = []
        for j in range(log["wIn"]):
            log["out"].append(int(lines[idx][:-2]))
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
        
    print(pprint.pformat(logs, width=150, compact=True, depth=args.depth))

if __name__ == '__main__':
    main()
