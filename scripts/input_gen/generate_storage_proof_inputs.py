import argparse
import json
import pprint

import mpt
import rlp
import sha3

from mpt import MerklePatriciaTrie

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

def gen_proof_input(proof, root, key, value, maxValueHexLen, maxDepth=None, debug=False):
    LEAF_RLP_HEXS_LEN = 74 + maxValueHexLen
    NODE_RLP_HEXS_LEN = 1064
    EXT_RLP_HEXS_LEN = 4 + 2 + 64 + 2 + 64
    
    keyHexs = []
    valueHexs = []
    rootHashHexs = []
    
    leafRlpLengthHexLen = 0
    
    leafPathRlpHexLen = 0
    leafPathPrefixHexLen = 2
    leafPathHexLen = 60
    
    leafRlpValueLenHexLen = 2
    leafValueLenHexLen = 4
    leafRlpHexs = []
    
    nodeRlpLengthHexLen = []
    nodePathRlpHexLen = []
    nodePathPrefixHexLen = []
    nodePathHexLen = []
    nodeRefHexLen = []
    nodeRlpHexs = []
    nodeTypes = []

    keyHexs = serialize_hex(key)
    valueHexs = serialize_hex(value)
    valueHexs = valueHexs + [0 for x in range(maxValueHexLen - len(valueHexs))]
    rootHashHexs = serialize_hex(root)

    for idx, node in enumerate(proof):
        nhash = keccak256(node[2:])
        
        node_decode = mpt.node.Node.decode(bytearray.fromhex(node[2:]))
        if debug:
            print(idx, node_decode, nhash, node)
        if type(node_decode) is mpt.node.Node.Leaf:
            rlp_prefix = node[2:4]
            curr_idx = 4
            if int(rlp_prefix, 16) <= int('f7', 16):
                leafRlpLengthHexLen = 0
            else:
                leafRlpLengthHexLen = 2 * (int(rlp_prefix, 16) - int('f7', 16))
                curr_idx = curr_idx + leafRlpLengthHexLen

            path_rlp_prefix = node[curr_idx: curr_idx + 2]
            curr_idx = curr_idx + 2
            if int(path_rlp_prefix, 16) <= int('b7', 16):
                leafPathRlpHexLen = 0
                leafPathHexLen = 2 * (int(path_rlp_prefix, 16) - int('80', 16))
            else:
                leafPathRlpHexLen = 2 * (int(path_rlp_prefix, 16) - int('b7', 16))
                len_nibbles = node[curr_idx: curr_idx + leafPathRlpHexLen] 
                curr_idx = curr_idx + leafPathRlpHexLen
                leafPathHexLen = 2 * int(len_nibbles, 16)

            path_prefix_nibble = node[curr_idx]
            if path_prefix_nibble == '2':
                curr_idx = curr_idx + 2
                leafPathPrefixHexLen = 2
            else:
                curr_idx = curr_idx + 1
                leafPathPrefixHexLen = 1

            leafPathHexLen = leafPathHexLen - leafPathPrefixHexLen
            curr_idx = curr_idx + leafPathHexLen

            value_rlp_prefix = node[curr_idx: curr_idx + 2]
            curr_idx = curr_idx + 2

            if int(value_rlp_prefix, 16) <= int('b7', 16):
                leafRlpValueLenHexLen = 0
                leafValueLenHexLen = 2 * (int(value_rlp_prefix, 16) - int('80', 16))
            elif int(value_rlp_prefix, 16) <= int('bf', 16):
                leafRlpValueLenHexLen = 2 * (int(value_rlp_prefix, 16) - int('b7', 16))
                len_nibbles = node[curr_idx: curr_idx + leafRlpValueLenHexLen] 
                curr_idx = curr_idx + leafRlpValueLenHexLen
                leafValueLenHexLen = 2 * int(len_nibbles, 16)
            elif int(value_rlp_prefix, 16) <= int('f7', 16):
                leafRlpValueLenHexLen = 0
                leafValueLenHexLen = 2 * (int(value_rlp_prefix, 16) - int('c0', 16))
            elif int(value_rlp_prefix, 16) <= int('ff', 16):
                leafRlpValueLenHexLen = 2 * (int(value_rlp_prefix, 16) - int('f7', 16))
                len_nibbles = node[curr_idx: curr_idx + leafRlpValueLenHexLen] 
                curr_idx = curr_idx + leafRlpValueLenHexLen
                leafValueLenHexLen = 2 * int(len_nibbles, 16)

            leafRlpHexs = serialize_hex(node[2:])
            leafRlpHexs = leafRlpHexs + [0 for x in range(LEAF_RLP_HEXS_LEN - len(leafRlpHexs))]

            if debug:
                print(idx, 'Leaf', node_decode.path._data.hex(), node_decode.data.hex())
                print(node_decode.path)
        elif type(node_decode) is mpt.node.Node.Branch:
            rlp_prefix = node[2:4]
            curr_idx = 4
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
            node_rlp = serialize_hex(node[2:])
            node_rlp = node_rlp + [0 for x in range(NODE_RLP_HEXS_LEN - len(node_rlp))]
            nodeRlpHexs.append(node_rlp)
            
            nodeTypes.append(0)
            if debug:
                print(idx, 'Branch', nhash, node_decode.encode().hex(), node_decode.data.hex())
                for idx2, b in enumerate(node_decode.branches):
                    print(idx, 'Branch', idx2, b.hex())
        elif type(node_decode) is mpt.node.Node.Extension:
            rlp_prefix = node[2:4]
            curr_idx = 4
            if int(rlp_prefix, 16) <= int('f7', 16):
                nodeRlpLengthHexLen.append(0)
            else:
                nodeRlpLengthHexLen.append(2 * (int(rlp_prefix, 16) - int('f7', 16)))
                curr_idx = curr_idx + nodeRlpLengthHexLen[-1]

            rlp_prefix = node[curr_idx: curr_idx + 2]
            curr_idx = curr_idx + 2
            is_no_prefix = False
            if int(rlp_prefix, 16) <= int('7f', 16):
                nodePathRlpHexLen.append(0)
                nodePathHexLen.append(0)
                is_no_prefix = True
            elif int(rlp_prefix, 16) <= int('b7', 16):
                nodePathRlpHexLen.append(0)
                nodePathHexLen.append(2 * (int(rlp_prefix, 16) - int('80', 16)))
            elif int(rlp_prefix, 16) <= int('bf', 16):
                nodePathRlpHexLen.append(2 * (int(rlp_prefix, 16) - int('b7', 16)))
                str_len = node[curr_idx: curr_idx + nodePathRlpHexLen[-1]]
                curr_idx = curr_idx + nodePathRlpHexLen[-1]
                nodePathHexLen.append(2 * int(str_len, 16))
            elif int(rlp_prefix, 16) <= int('f7', 16):
                nodePathRlpLenHexLen.append(0)
                nodePathHexLen.append(2 * (int(rlp_prefix, 16) - int('c0', 16)))
            elif int(rlp_prefix, 16) <= int('ff', 16):
                nodePathRlpHexLen.append(2 * (int(rlp_prefix, 16) - int('f7', 16)))
                str_len = node[curr_idx: curr_idx + nodePathRlpHexLen[-1]]
                curr_idx = curr_idx + nodePathRlpHexLen[-1]
                nodePathHexLen.append(2 * int(str_len, 16))

            if is_no_prefix:
                nodePathPrefixHexLen.append(0)
            else:
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

            temp = serialize_hex(node[2:])
            temp = temp + [0 for idx in range(NODE_RLP_HEXS_LEN - len(temp))]
            nodeRlpHexs.append(temp)                      
            nodeTypes.append(1)
            if debug:
                print(idx, 'Extension', nhash, node_decode.encode().hex())
                print(idx, 'Extension', node_decode.path._data.hex(), node_decode.next_ref.hex())

    if maxDepth is not None:
        for idx in range(maxDepth - len(proof)):
            nodeRlpLengthHexLen.append(0)
            nodePathRlpHexLen.append(0)
            nodePathPrefixHexLen.append(0)
            nodePathHexLen.append(0)
            nodeRefHexLen.append([0 for idx in range(16)])
            nodeRlpHexs.append([0 for x in range(NODE_RLP_HEXS_LEN)])
            nodeTypes.append(0)
    depth = len(proof)
    
    ret = {
        "keyHexs": keyHexs,
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
        "depth": depth
    }
    return ret

def get_storage_pf(punk_pfs, slot=None, debug=False):
    punk_pf = None
    for x in punk_pfs['result']['storageProof']:
        if x['key'] == slot:
            punk_pf = x
    assert(punk_pf is not None)
            
    key = keccak256(punk_pf['key'][2:])
    value = punk_pf['value'][2:]
    if len(value) % 2 == 1:
        value = '0' + value
    proof = punk_pf['proof']
    root = punk_pfs['result']['storageHash'][2:]

    if debug:
        print('addr:      {}'.format(punk_pfs['result']['address']))
        print('stor root: {}'.format(root))
        print('key:       {}'.format(key))
        print('value:     {}'.format(value))
    
    pf = gen_proof_input(proof, root, key, rlp.encode(bytearray.fromhex(value)).hex(), 114, debug=debug)
    return pf

def get_addr_pf(punk_pfs, debug=False):
    acct_pf = punk_pfs['result']['accountProof']
    key = keccak256(punk_pfs['result']['address'][2:])
    nonce = punk_pfs['result']['nonce'][2:]
    balance = punk_pfs['result']['balance'][2:]
    storageHash = punk_pfs['result']['storageHash'][2:]
    codeHash = punk_pfs['result']['codeHash'][2:]

    addr_rlp = rlp.encode([int(nonce, 16),
                           int(balance, 16),
                           bytearray.fromhex(storageHash),
                           bytearray.fromhex(codeHash)])

    if debug:
        print('key:         {}'.format(key))
        print('value:       {}'.format(addr_rlp.hex()))
        print('nonce:       {}'.format(nonce))
        print('balance:     {}'.format(balance))
        print('storageHash: {}'.format(storageHash))
        print('codeHash:    {}'.format(codeHash))

    pf = gen_proof_input(acct_pf, keccak256(acct_pf[0][2:]), key, addr_rlp.hex(), 228, debug=debug)
    return pf

parser = argparse.ArgumentParser()
parser.add_argument('--debug', action='store_true', default=False)
parser.add_argument('--addr', action='store_true', default=False)
parser.add_argument('--addr_file_str', type=str, default='inputs/input_address_proof.json')

parser.add_argument('--storage', action='store_true', default=False)
parser.add_argument('--storage_file_str', type=str, default='inputs/input_storage_proof.json')
parser.add_argument('--slot', type=int, default=10)
parser.add_argument('--punk_slot', type=int, default=0)
args = parser.parse_args()

def main():
    with open('punk_pfs.json', 'r') as f:
        punk_block = json.loads(f.read())

    if args.addr:
        addr_pf = get_addr_pf(punk_block, debug=args.debug)
        pf_str = pprint.pformat(addr_pf, width=100, compact=True).replace("'", '"')
        with open(args.addr_file_str, 'w') as f:
            f.write(pf_str)

        if args.debug:
            print(pf_str)
            for k in addr_pf:
                if type(addr_pf[k]) is not int and type(addr_pf[k][0]) is not int:
                    for a in addr_pf[k]:
                        print(k, len(addr_pf[k]), len(a))
                elif type(addr_pf[k]) is not int:
                    print(k, len(addr_pf[k]))
                else:
                    print(k)

    if args.storage:
        if args.slot < 10:
            x = hex(args.slot)[2:]
            x = ''.join(['0' for idx in range(64 - len(x))]) + x
            slot = x
        else:
            x = hex(args.punk_slot)[2:]
            x = ''.join(['0' for idx in range(64 - len(x))]) + x
            y = hex(10)[2:]
            y = ''.join(['0' for idx in range(64 - len(y))]) + y
            x = x + y
            slot = keccak256(x)
            
        storage_pf = get_storage_pf(punk_block, slot=slot, debug=args.debug)
        print('Punk {:5} depth {:3}'.format(args.punk_slot, storage_pf['depth']))
        
        pf_str = pprint.pformat(storage_pf, width=100, compact=True).replace("'", '"')
        with open(args.storage_file_str, 'w') as f:
            f.write(pf_str)

        if args.debug:
            print(pf_str)

if __name__ == '__main__':
    main()


