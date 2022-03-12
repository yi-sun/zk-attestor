import argparse
import json
import pprint
import rlp
import sha3

from mpt import MerklePatriciaTrie
import mpt

def byte_reverse(bin_str):
    ret = []
    for idx in range(len(bin_str) // 8):
        temp = bin_str[8 * idx: 8 * idx + 8][::-1]
        ret = ret + [int(x) for x in temp]
    return ret

def hex_to_int(arr):
    return arr[0] + 2 * arr[1] + 4 * arr[2] + 8 * arr[3]

def keccak256(x):
    k = sha3.keccak_256()
    k.update(bytearray.fromhex(x))
    return k.hexdigest()

def serialize_hex(val_hex):
    val_arr = [int(nib, 16) for nib in val_hex]
    return val_arr

def construct_mpt(d):
    storage = {}
    trie = MerklePatriciaTrie(storage)
    for key in d:
        trie.update(key, d[key])
    return trie, storage

def get_mpt_proof(storage, proof, node, path):
    if len(path) == 0:
        proof = proof + [node]
        return proof

    if type(node) is mpt.node.Node.Leaf:
        if node.path == path:
            proof = proof + [node]
            return proof
    elif type(node) is mpt.node.Node.Extension:
        if path.starts_with(node.path):
            rest_path = path.consume(len(node.path))
            proof = proof + [node]
            if len(node.next_ref) == 32:
                node = storage[node.next_ref]
            else:
                node = node.next_ref
            node = mpt.node.Node.decode(node)
            return get_mpt_proof(storage, proof, node, rest_path)
    elif type(node) is mpt.node.Node.Branch:
        branch = node.branches[path.at(0)]
        proof = proof + [node]
        if len(branch) == 32:
            node = storage[branch]
        else:
            node = branch
        node = mpt.node.Node.decode(node)            
        if len(branch) > 0:
            return get_mpt_proof(storage, proof, node, path.consume(1))

def gen_proof_input(proof, root, key, value, maxDepth, maxKeyHexLen, maxValueHexLen, debug=False):
    maxNodeRefLen = 64
    maxLeafRlpHexLen = 4 + (maxKeyHexLen + 2) + 4 + maxValueHexLen
    maxBranchRlpHexLen = 1064
    maxExtensionRlpHexLen = 4 + 2 + maxKeyHexLen + 2 + maxNodeRefLen

    keyHexLen = 0
    keyHexs = []
    valueHexLen = 0
    valueHexs = []
    rootHashHexs = []

    leafRlpLengthHexLen = 0
    leafPathRlpHexLen = 0
    leafPathPrefixHexLen = 0
    leafPathHexLen = 0
    leafRlpValueLenHexLen = 0
    leafValueLenHexLen = 0
    leafRlpHexs = []
    
    terminalBranchRlpLengthHexLen = 0
    terminalBranchNodeRefHexLen = []
    terminalBranchVtRlpLenHexLen = 0
    terminalBranchVtValueHexLen = 0

    terminalBranchRlpHexs = []

    nodeRlpLengthHexLen = []
    nodePathRlpHexLen = []
    nodePathPrefixHexLen = []
    nodePathHexLen = []
    nodeRefHexLen = []
    nodeVtRlpLenHexLen = []
    nodeVtValueHexLen = []

    nodeRlpHexs = []
     
    nodeTypes = []
    isTerminalBranch = 0
    depth = 0

    keyHexLen = len(key)
    keyHexs = serialize_hex(key)
    keyHexs = keyHexs + [0 for idx in range(maxKeyHexLen - len(keyHexs))]
    valueHexLen = len(value)
    valueHexs = serialize_hex(value)
    valueHexs = valueHexs + [0 for idx in range(maxValueHexLen - len(valueHexs))]
    rootHashHexs = serialize_hex(root)

    last = proof[-1]
    lhash = keccak256(last.encode().hex())
    if type(last) is mpt.node.Node.Branch:
        leafRlpHexs = [0 for idx in range(maxLeafRlpHexLen)]
        if debug:
            print('Branch', len(last.data.hex()))

        isTerminalBranch = 1
        last = last.encode().hex()
        rlp_prefix = last[:2]
        curr_idx = 2
        if int(rlp_prefix, 16) <= int('f7', 16):
            terminalBranchRlpLengthHexLen = 0
        else:
            terminalBranchRlpLengthHexLen = 2 * (int(rlp_prefix, 16) - int('f7', 16))
            curr_idx = curr_idx + terminalBranchRlpLengthHexLen

        temp = []
        for idx in range(16):
            rlp_len = last[curr_idx: curr_idx + 2]
            temp.append(2 * (int(rlp_len, 16) - int('80', 16)))
            curr_idx = curr_idx + 2 + 2 * (int(rlp_len, 16) - int('80', 16))
        terminalBranchNodeRefHexLen = temp
        
        rlp_prefix = last[curr_idx: curr_idx + 2]
        curr_idx = curr_idx + 2
        if int(rlp_prefix, 16) <= int('b7', 16):
            terminalBranchVtRlpLenHexLen = 0
            terminalBranchVtValueHexLen = 2 * (int(rlp_prefix, 16) - int('80', 16))
        elif int(rlp_prefix, 16) <= int('bf', 16):
            terminalBranchVtRlpLenHexLen = 2 * (int(rlp_prefix, 16) - int('b7', 16))
            str_len = last[curr_idx: curr_idx + terminalBranchVtRlpLenHexLen]
            curr_idx = curr_idx + terminalBranchVtRlpLenHexLen
            terminalBranchVtValueHexLen = 2 * int(str_len, 16)
        elif int(rlp_prefix, 16) <= int('f7', 16):
            terminalBranchVtRlpLenHexLen = 0
            terminalBranchVtValueHexLen = 2 * (int(rlp_prefix, 16) - int('c0', 16))
        elif int(rlp_prefix, 16) <= int('ff', 16):
            terminalBranchVtRlpLenHexLen = 2 * (int(rlp_prefix, 16) - int('f7', 16))
            str_len = last[curr_idx: curr_idx + terminalBranchVtRlpLenHexLen]
            curr_idx = curr_idx + terminalBranchVtRlpLenHexLen
            terminalBranchVtValueHexLen = 2 * int(str_len, 16)
                
        node_rlp = serialize_hex(last)
        if debug:
            print('LENGTH: {}'.format(len(node_rlp)))
        node_rlp = node_rlp + [0 for x in range(maxBranchRlpHexLen - len(node_rlp))]
        terminalBranchRlpHexs.append(node_rlp)
    else:
        if debug:
            print('Leaf', len(last.data.hex()), last.encode().hex(), last.path)
        terminalBranchNodeRefHexLen = [0 for idx in range(16)]
        terminalBranchRlpHexs = [0 for idx in range(maxBranchRlpHexLen)]

        isTerminalBranch = 0
        last = last.encode().hex()
        rlp_prefix = last[:2]
        curr_idx = 2
        if int(rlp_prefix, 16) <= int('f7', 16):
            leafRlpLengthHexLen = 0
        else:
            leafRlpLengthHexLen = 2 * (int(rlp_prefix, 16) - int('f7', 16))
            curr_idx = curr_idx + leafRlpLengthHexLen

        path_rlp_prefix = last[curr_idx: curr_idx + 2]
        curr_idx = curr_idx + 2
        is_no_prefix = False
        if int(path_rlp_prefix, 16) <= int('7f', 16):
            leafPathRlpHexLen = 0
            leafPathHexLen = 0
            is_no_prefix = True
        elif int(path_rlp_prefix, 16) <= int('b7', 16):
            leafPathRlpHexLen = 0
            leafPathHexLen = 2 * (int(path_rlp_prefix, 16) - int('80', 16))
        else:
            leafPathRlpHexLen = 2 * (int(path_rlp_prefix, 16) - int('b7', 16))
            len_nibbles = last[curr_idx: curr_idx + leafPathRlpHexLen] 
            curr_idx = curr_idx + leafPathRlpHexLen
            leafPathHexLen = 2 * int(len_nibbles, 16)

        if is_no_prefix:
            leafPathPrefixHexLen = 0
        else:
            path_prefix_nibble = last[curr_idx]
            if path_prefix_nibble == '2':
                curr_idx = curr_idx + 2
                leafPathPrefixHexLen = 2
            else:
                curr_idx = curr_idx + 1
                leafPathPrefixHexLen = 1

        leafPathHexLen = leafPathHexLen - leafPathPrefixHexLen
        curr_idx = curr_idx + leafPathHexLen

        rlp_prefix = last[curr_idx: curr_idx + 2]
        curr_idx = curr_idx + 2
        if int(rlp_prefix, 16) <= int('b7', 16):
            leafRlpValueLenHexLen = 0
            leafValueLenHexLen = 2 * (int(rlp_prefix, 16) - int('80', 16))
        elif int(rlp_prefix, 16) <= int('bf', 16):
            leafRlpValueLenHexLen = 2 * (int(rlp_prefix, 16) - int('b7', 16))
            str_len = last[curr_idx: curr_idx + leafRlpValueLenHexLen]
            curr_idx = curr_idx + leafRlpValueLenHexLen
            leafValueLenHexLen = 2 * int(str_len, 16)
        elif int(rlp_prefix, 16) <= int('f7', 16):
            leafRlpValueLenHexLen = 0
            leafValueLenHexLen = 2 * (int(rlp_prefix, 16) - int('c0', 16))
        elif int(rlp_prefix, 16) <= int('ff', 16):
            leafRlpValueLenHexLen = 2 * (int(rlp_prefix, 16) - int('f7', 16))
            str_len = last[curr_idx: curr_idx + leafRlpValueLenHexLen]
            curr_idx = curr_idx + leafRlpValueLenHexLen
            leafValueLenHexLen = 2 * int(str_len, 16)
            
        leafRlpHexs = serialize_hex(last)
        if debug:
            print('LENGTH: {}'.format(len(leafRlpHexs)))
        leafRlpHexs = leafRlpHexs + [0 for x in range(maxLeafRlpHexLen - len(leafRlpHexs))]

    for idx, node in enumerate(proof[:-1]):
        nhash = keccak256(node.encode().hex())
        node = node.encode().hex()
        
        node_decode = mpt.node.Node.decode(bytearray.fromhex(node))
        if debug:
            print(idx, node_decode, nhash, node)
        if type(node_decode) is mpt.node.Node.Branch:
            if debug:
                for idx, x in enumerate(node_decode.branches):
                    print(idx, x.hex())
            rlp_prefix = node[:2]
            curr_idx = 2
            if int(rlp_prefix, 16) <= int('f7', 16):
                nodeRlpLengthHexLen.append(0)
            else:
                nodeRlpLengthHexLen.append(2 * (int(rlp_prefix, 16) - int('f7', 16)))
                curr_idx = curr_idx + nodeRlpLengthHexLen[-1]

            nodePathRlpHexLen.append(0)
            nodePathPrefixHexLen.append(0)
            nodePathHexLen.append(0)

            temp = []
            for idx in range(16):
                rlp_len = node[curr_idx: curr_idx + 2]
                temp.append(2 * (int(rlp_len, 16) - int('80', 16)))
                curr_idx = curr_idx + 2 + 2 * (int(rlp_len, 16) - int('80', 16))
            nodeRefHexLen.append(temp)
            rlp_prefix = node[curr_idx: curr_idx + 2]
            curr_idx = curr_idx + 2
            if int(rlp_prefix, 16) <= int('b7', 16):
                nodeVtRlpLenHexLen.append(0)
                nodeVtValueHexLen.append(2 * (int(rlp_prefix, 16) - int('80', 16)))
            elif int(rlp_prefix, 16) <= int('bf', 16):
                nodeVtRlpLenHexLen.append(2 * (int(rlp_prefix, 16) - int('b7', 16)))
                str_len = node[curr_idx: curr_idx + nodeVtRlpLenHexLen[-1]]
                curr_idx = curr_idx + nodeVtRlpLenHexLen[-1]
                nodeVtValueHexLen.append(2 * int(str_len, 16))
            elif int(rlp_prefix, 16) <= int('f7', 16):
                nodeVtRlpLenHexLen.append(0)
                nodeVtValueHexLen.append(2 * (int(rlp_prefix, 16) - int('c0', 16)))
            elif int(rlp_prefix, 16) <= int('ff', 16):
                nodeVtRlpLenHexLen.append(2 * (int(rlp_prefix, 16) - int('f7', 16)))
                str_len = node[curr_idx: curr_idx + nodeVtRlpLenHexLen[-1]]
                curr_idx = curr_idx + nodeVtRlpLenHexLen[-1]
                nodeVtValueHexLen.append(2 * int(str_len, 16))
                
            node_rlp = serialize_hex(node)
            if debug:
                print('LENGTH: {}'.format(len(node_rlp)))
            node_rlp = node_rlp + [0 for x in range(maxBranchRlpHexLen - len(node_rlp))]
            nodeRlpHexs.append(node_rlp)
            
            nodeTypes.append(0)
            if debug:
                print('Branch', len(node_decode.data.hex()), nhash, node_decode.encode().hex(), node_decode.data.hex())
        elif type(node_decode) is mpt.node.Node.Extension:
            if debug:
                print(node_decode.path)
            rlp_prefix = node[:2]
            curr_idx = 2
            if int(rlp_prefix, 16) <= int('f7', 16):
                nodeRlpLengthHexLen.append(0)
            else:
                nodeRlpLengthHexLen.append(2 * (int(rlp_prefix, 16) - int('f7', 16)))
                curr_idx = curr_idx + nodeRlpLengthHexLen[-1]

            rlp_prefix = node[curr_idx: curr_idx + 2]
            curr_idx = curr_idx + 2
            if int(rlp_prefix, 16) <= int('b7', 16):
                nodePathRlpHexLen.append(0)
                nodePathHexLen.append(2 * (int(rlp_prefix, 16) - int('80', 16)))
            elif int(rlp_prefix, 16) <= int('bf', 16):
                nodePathRlpHexLen.append(2 * (int(rlp_prefix, 16) - int('b7', 16)))
                str_len = node[curr_idx: curr_idx + nodePathRlpHexLen[-1]]
                curr_idx = curr_idx + nodePathRlpHexLen[-1]
                nodePathHexLen.append(2 * int(str_len, 16))

            path_prefix_nibble = node[curr_idx]
            if path_prefix_nibble == '0':
                curr_idx = curr_idx + 2
                nodePathPrefixHexLen.append(2)
            elif path_prefix_nibble == '1':
                curr_idx = curr_idx + 1
                nodePathPrefixHexLen.append(1)
            nodePathHexLen[-1] = nodePathHexLen[-1] - nodePathPrefixHexLen[-1]
            curr_idx = curr_idx + nodePathHexLen[-1]
            
            rlp_prefix = node[curr_idx: curr_idx + 2]
            curr_idx = curr_idx + 2
            temp = []
            if int(rlp_prefix, 16) <= int('b7', 16):
                temp.append(2 * (int(rlp_prefix, 16) - int('80', 16)))
                curr_idx = curr_idx + temp[-1]
            temp = temp + [0 for idx in range(15)]
            nodeRefHexLen.append(temp)

            nodeVtRlpLenHexLen.append(0)
            nodeVtValueHexLen.append(0)

            temp = serialize_hex(node)
            if debug:
                print('LENGTH: {}'.format(len(temp)))
            temp = temp + [0 for idx in range(maxBranchRlpHexLen - len(temp))]
            nodeRlpHexs.append(temp)                        
            nodeTypes.append(1)

    for idx in range(maxDepth - len(proof)):
        nodeRlpLengthHexLen.append(0)
        nodePathRlpHexLen.append(0)
        nodePathPrefixHexLen.append(0)
        nodePathHexLen.append(0)
        nodeRefHexLen.append([0 for idx in range(16)])
        nodeRlpHexs.append([0 for x in range(maxBranchRlpHexLen)])
        nodeTypes.append(0)
        
    depth = len(proof)

    ret = {"keyHexLen": keyHexLen,
           "keyHexs": keyHexs,
           
           "valueHexLen": valueHexLen,
           "valueHexs": valueHexs, 
           "rootHashHexs": rootHashHexs,

           "leafRlpLengthHexLen": leafRlpLengthHexLen, 
           "leafPathRlpHexLen": leafPathRlpHexLen, 
           "leafPathPrefixHexLen": leafPathPrefixHexLen, 
           "leafPathHexLen": leafPathHexLen, 
           "leafRlpValueLenHexLen": leafRlpValueLenHexLen, 
           "leafValueLenHexLen": leafValueLenHexLen, 
           "leafRlpHexs": leafRlpHexs, 
    
           "nodeRlpLengthHexLen": nodeRlpLengthHexLen, 
           "nodePathRlpHexLen": nodePathRlpHexLen, 
           "nodePathPrefixHexLen": nodePathPrefixHexLen, 
           "nodePathHexLen": nodePathHexLen, 
           "nodeRefHexLen": nodeRefHexLen, 
           
           "nodeRlpHexs": nodeRlpHexs, 
           
           "nodeTypes": nodeTypes,
           "depth": depth }
    return ret

def get_raw_tx(tx):
    if tx['type'] == '0x0':
        raw_tx = [int(tx['nonce'], 16),
                  int(tx['gasPrice'], 16),
                  int(tx['gas'], 16),
                  bytearray.fromhex(tx['to'][2:]),
                  int(tx['value'], 16)]
        if tx['to'] == '':
            raw_tx.append(bytearray.fromhex(tx['init'][2:]))
        else:
            raw_tx.append(bytearray.fromhex(tx['input'][2:]))
        raw_tx = raw_tx + [
            int(tx['v'], 16),
            int(tx['r'], 16),
            int(tx['s'], 16)]
    elif tx['type'] == '0x2':
        raw_tx = [int(tx['chainId'], 16),
                  int(tx['nonce'], 16),
                  int(tx['maxPriorityFeePerGas'], 16),
                  int(tx['maxFeePerGas'], 16),
                  int(tx['gas'], 16),
                  bytearray.fromhex(tx['to'][2:]),
                  int(tx['value'], 16)]
        if tx['to'] == '':
            raw_tx.append(bytearray.fromhex(tx['init'][2:]))
        else:
            raw_tx.append(bytearray.fromhex(tx['input'][2:]))
        raw_tx = raw_tx + [
            tx['accessList'],
            int(tx['v'], 16),
            int(tx['r'], 16),
            int(tx['s'], 16)]
    else:
        assert('type not handled: {}'.format(tx['type']))
    return raw_tx

def get_pf(block, tx_idx, max_depth=None, max_key_len=64, max_val_len=234, debug=False):
    block = block['result']
    block_hash = block['hash']

    header = [
        bytearray.fromhex(block['parentHash'][2:]),
        bytearray.fromhex(block['sha3Uncles'][2:]),
        bytearray.fromhex(block['miner'][2:]),
        bytearray.fromhex(block['stateRoot'][2:]),
        bytearray.fromhex(block['transactionsRoot'][2:]),
        bytearray.fromhex(block['receiptsRoot'][2:]),
        bytearray.fromhex(block['logsBloom'][2:]),
        int(block['difficulty'], 0),
        int(block['number'], 0),
        int(block['gasLimit'], 0),
        int(block['gasUsed'], 0),
        int(block['timestamp'], 0),
        bytearray.fromhex(block['extraData'][2:]),
        bytearray.fromhex(block['mixHash'][2:]),
        bytearray.fromhex(block['nonce'][2:]),
        int(block['baseFeePerGas'], 0),
    ]

    tx_list = block['transactions']
    raw_tx_dict = {}
    if debug:
        print('{} tx in block'.format(len(tx_list)))
    for idx, tx in enumerate(tx_list):
        if tx['type'] == '0x0':
            raw_tx = get_raw_tx(tx)
            raw_tx_dict[rlp.encode(idx)] = rlp.encode(raw_tx)
        elif tx['type'] == '0x2':
            raw_tx = get_raw_tx(tx)
            raw_tx_dict[rlp.encode(idx)] = bytearray.fromhex('02') + rlp.encode(raw_tx)        
        else:
            print('type not handled: {}'.format(tx['type']))
        if debug:
            print(idx, rlp.encode(idx).hex(), tx['type'], tx['hash'], len(rlp.encode(raw_tx).hex()))

    trie, storage = construct_mpt(raw_tx_dict)

    root = mpt.node.Node.decode(storage[trie._root])
    path = mpt.nibble_path.NibblePath(rlp.encode(tx_idx))
    
    pf = get_mpt_proof(storage, [], root, path)
    value = trie.get(rlp.encode(tx_idx)).hex()

    ret = gen_proof_input(pf, keccak256(root.encode().hex()), rlp.encode(tx_idx).hex(), value, max_depth, max_key_len, max_val_len, debug=debug)
    return ret

parser = argparse.ArgumentParser()
parser.add_argument('--debug', action='store_true', default=False)
parser.add_argument('--tx_idx', type=int, default=2)
parser.add_argument('--file_str', type=str, default='inputs/input_tx_proof.json')
parser.add_argument('--max_depth', type=int, default=5)
parser.add_argument('--max_key_len', type=int, default=6)
parser.add_argument('--max_val_len', type=int, default=234)
args = parser.parse_args()

def main():
    with open('punk_block.json', 'r') as f:
        block = json.loads(f.read())

    pf = get_pf(block, args.tx_idx, max_depth=args.max_depth, max_key_len=args.max_key_len, max_val_len=args.max_val_len, debug=args.debug)
    print('tx_idx: {:3} depth: {:3} key_len: {:6} val_len: {:5}'.format(args.tx_idx, pf['depth'], len(rlp.encode(args.tx_idx).hex()), len(rlp.encode(get_raw_tx(block['result']['transactions'][args.tx_idx])).hex())))
          
    pf_str = pprint.pformat(pf, width=100, compact=True).replace("'", '"')
    with open(args.file_str, 'w') as f:
        f.write(pf_str)
        
    if args.debug:
        print(pf_str)
        for k in pf:
            if type(pf[k]) is not int and type(pf[k][0]) is not int:
                for a in pf[k]:
                    print(k, len(pf[k]), len(a))
            elif type(pf[k]) is not int:
                print(k, len(pf[k]))
            else:
                print(k)

if __name__ == '__main__':
    main()
