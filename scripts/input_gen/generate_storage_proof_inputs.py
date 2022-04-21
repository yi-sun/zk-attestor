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

def serialize_int(val_hex):
    ret = 0
    for idx in range(len(val_hex)):
        ret = ret + int(val_hex[idx], 16) * (16 ** (len(val_hex) - idx - 1))
    return str(ret)

def serialize_int2(val_hex):
    ret0, ret1 = 0, 0
    for idx in range(32):
        ret0 = ret0 + int(val_hex[idx], 16) * (16 ** (31 - idx))
        ret1 = ret1 + int(val_hex[32 + idx], 16) * (16 ** (31 - idx))
    return [str(ret0), str(ret1)]

def gen_proof_input(proof, root, key, value, maxValueHexLen, maxDepth=None, debug=False):
    LEAF_RLP_HEXS_LEN = 74 + maxValueHexLen
    NODE_RLP_HEXS_LEN = 1064
    EXT_RLP_HEXS_LEN = 4 + 2 + 64 + 2 + 64
    
    keyHexs = []
    valueHexs = []
    rootHashHexs = []
    
    leafRlpLengthHexLen = 0
    
    leafPathRlpLengthHexLen = 0
    leafPathPrefixHexLen = 2
    leafPathHexLen = 60
    
    leafValueRlpLengthHexLen = 2
    leafValueHexLen = 4
    leafRlpHexs = []
    
    nodeRlpLengthHexLen = []
    nodePathRlpLengthHexLen = []
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
                leafPathRlpLengthHexLen = 0
                leafPathHexLen = 2 * (int(path_rlp_prefix, 16) - int('80', 16))
            else:
                leafPathRlpLengthHexLen = 2 * (int(path_rlp_prefix, 16) - int('b7', 16))
                len_nibbles = node[curr_idx: curr_idx + leafPathRlpLengthHexLen] 
                curr_idx = curr_idx + leafPathRlpLengthHexLen
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
                leafValueRlpLengthHexLen = 0
                leafValueHexLen = 2 * (int(value_rlp_prefix, 16) - int('80', 16))
            elif int(value_rlp_prefix, 16) <= int('bf', 16):
                leafValueRlpLengthHexLen = 2 * (int(value_rlp_prefix, 16) - int('b7', 16))
                len_nibbles = node[curr_idx: curr_idx + leafValueRlpLengthHexLen] 
                curr_idx = curr_idx + leafValueRlpLengthHexLen
                leafValueHexLen = 2 * int(len_nibbles, 16)
            elif int(value_rlp_prefix, 16) <= int('f7', 16):
                leafValueRlpLengthHexLen = 0
                leafValueHexLen = 2 * (int(value_rlp_prefix, 16) - int('c0', 16))
            elif int(value_rlp_prefix, 16) <= int('ff', 16):
                leafValueRlpLengthHexLen = 2 * (int(value_rlp_prefix, 16) - int('f7', 16))
                len_nibbles = node[curr_idx: curr_idx + leafValueRlpLengthHexLen] 
                curr_idx = curr_idx + leafValueRlpLengthHexLen
                leafValueHexLen = 2 * int(len_nibbles, 16)

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

            nodePathRlpLengthHexLen.append(0)
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
            if int(rlp_prefix, 16) <= int('7f', 16):
                nodePathRlpLengthHexLen.append(0)
                nodePathHexLen.append(2)
                curr_idx = curr_idx - 2
            elif int(rlp_prefix, 16) <= int('b7', 16):
                nodePathRlpLengthHexLen.append(0)
                nodePathHexLen.append(2 * (int(rlp_prefix, 16) - int('80', 16)))
            elif int(rlp_prefix, 16) <= int('bf', 16):
                nodePathRlpLengthHexLen.append(2 * (int(rlp_prefix, 16) - int('b7', 16)))
                str_len = node[curr_idx: curr_idx + nodePathRlpLengthHexLen[-1]]
                curr_idx = curr_idx + nodePathRlpLengthHexLen[-1]
                nodePathHexLen.append(2 * int(str_len, 16))
            elif int(rlp_prefix, 16) <= int('f7', 16):
                nodePathRlpLengthHexLen.append(0)
                nodePathHexLen.append(2 * (int(rlp_prefix, 16) - int('c0', 16)))
            elif int(rlp_prefix, 16) <= int('ff', 16):
                nodePathRlpLengthHexLen.append(2 * (int(rlp_prefix, 16) - int('f7', 16)))
                str_len = node[curr_idx: curr_idx + nodePathRlpLengthHexLen[-1]]
                curr_idx = curr_idx + nodePathRlpLengthHexLen[-1]
                nodePathHexLen.append(2 * int(str_len, 16))

            print('Extension: {} nodePathHexLen: {}'.format(node, nodePathHexLen))
            print(node_decode.path)

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
            nodePathRlpLengthHexLen.append(0)
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
    
        "leafPathRlpLengthHexLen": leafPathRlpLengthHexLen,
        "leafPathPrefixHexLen": leafPathPrefixHexLen,
        "leafPathHexLen": leafPathHexLen,
    
        "leafValueRlpLengthHexLen": leafValueRlpLengthHexLen,
        "leafValueHexLen": leafValueHexLen,
        "leafRlpHexs": leafRlpHexs,
        
        "nodeRlpLengthHexLen": nodeRlpLengthHexLen,
        "nodePathRlpLengthHexLen": nodePathRlpLengthHexLen,
        "nodePathPrefixHexLen": nodePathPrefixHexLen,
        "nodePathHexLen": nodePathHexLen,
        "nodeRefHexLen": nodeRefHexLen,
        "nodeRlpHexs": nodeRlpHexs,
        "nodeTypes": nodeTypes,
        "depth": depth
    }
    return ret

def get_storage_pf(punk_pfs, slot=None, max_depth=8, debug=False):
    punk_pf = None
    for x in punk_pfs['result']['storageProof']:
        if x['key'] == slot:
            punk_pf = x
    assert(punk_pf is not None)

    key = keccak256(punk_pf['key'])
    value = punk_pf['value'][2:]
    if len(value) % 2 == 1:
        value = '0' + value
    proof = punk_pf['proof']
    root = punk_pfs['result']['storageHash'][2:]

    print('SlotValue: ' + punk_pf['value'][2:])
    
    if debug:
        print('addr:      {}'.format(punk_pfs['result']['address']))
        print('stor root: {}'.format(root))
        print('key:       {}'.format(key))
        print('value:     {}'.format(value))
    
    pf = gen_proof_input(proof, root, key, rlp.encode(bytearray.fromhex(value)).hex(), 66, maxDepth=max_depth, debug=debug)
    return pf

def get_addr_pf(punk_pfs, max_depth=8, debug=False):
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

    pf = gen_proof_input(acct_pf, keccak256(acct_pf[0][2:]), key, addr_rlp.hex(), 228, maxDepth=max_depth, debug=debug)
    return pf

def get_block_pf(block, debug=False):
    block_list = [
        bytearray.fromhex(block['parentHash'][2:]),
        bytearray.fromhex(block['sha3Uncles'][2:]),
        bytearray.fromhex(block['miner'][2:]),
        bytearray.fromhex(block['stateRoot'][2:]),
        bytearray.fromhex(block['transactionsRoot'][2:]),
        bytearray.fromhex(block['receiptsRoot'][2:]),
        bytearray.fromhex(block['logsBloom'][2:]),
        int(block['difficulty'], 16),
        int(block['number'], 16),
        int(block['gasLimit'], 16),
        int(block['gasUsed'], 16),
        int(block['timestamp'], 16),
        bytearray.fromhex(block['extraData'][2:]),
        bytearray.fromhex(block['mixHash'][2:]),
        bytearray.fromhex(block['nonce'][2:]),
        int(block['baseFeePerGas'], 16)
    ]
    rlp_block = rlp.encode(block_list).hex()
    print(rlp_block, len(rlp_block))
    print(keccak256(rlp_block))
    print('Hash: ' + block['hash'])
    print('Number: ' + block['number'])
    for x in block_list:
        print(len(rlp.encode(x).hex()), x)

    if args.debug:
        rlp_prefix = rlp_block[:2]
        print('rlp(block): {}'.format(rlp_block))
        print('rlp_prefix: {}'.format(rlp_prefix))
    
    ret = {
        "blockRlpHexs": serialize_hex(rlp_block) + [0 for x in range(1112 - len(rlp_block))],
    }
    return ret

def get_addr_storage_pf(block, pfs, slot, addr_max_depth, storage_max_depth, debug=False):
    block_pf = get_block_pf(block, debug=debug)
    addr_pf = get_addr_pf(pfs, max_depth=addr_max_depth, debug=debug)
    storage_pf = get_storage_pf(pfs, slot=slot, max_depth=storage_max_depth, debug=debug)

    if args.debug:
        print(block_pf.keys())
        print(addr_pf.keys())
        print(storage_pf.keys())

    ret = {}
    ret['blockHash'] = serialize_int2(block['hash'][2:])
    for k in block_pf:
        ret[k] = block_pf[k]

    print('Address: ' + pfs['result']['address'][2:])        
    ret['address'] = serialize_int(pfs['result']['address'][2:])
    ret['addressValueRlpHexs'] = addr_pf['valueHexs']
    for k in ['leafPathPrefixHexLen',
              'leafRlpHexs',
              'nodePathPrefixHexLen',
              'nodeRlpHexs',
              'nodeTypes',
              'depth']:
        new_key = 'address{}'.format(k[0].upper() + k[1:])
        ret[new_key] = addr_pf[k]

    ret['addressKeyFragmentStarts'] = []
    temp = 0
    for idx in range(addr_max_depth):
        ret['addressKeyFragmentStarts'].append(temp)
        if idx < ret['addressDepth'] - 1:
            if ret['addressNodeTypes'][idx] == 0:
                temp = temp + 1
            else:
                temp = temp + addr_pf['nodePathHexLen'][idx]
        elif idx == ret['addressDepth'] - 1:
            temp = temp + addr_pf['leafPathHexLen']

    print('Slot: ' + slot)

    ret['slot'] = serialize_int2(slot)
    ret['slotValueRlpHexs'] = storage_pf['valueHexs']
    for k in ['leafPathPrefixHexLen',
              'leafRlpHexs',
              'nodePathPrefixHexLen',
              'nodeRlpHexs',
              'nodeTypes',
              'depth']:
        new_key = 'storage{}'.format(k[0].upper() + k[1:])
        ret[new_key] = storage_pf[k]

    ret['storageKeyFragmentStarts'] = []
    temp = 0
    for idx in range(storage_max_depth):
        ret['storageKeyFragmentStarts'].append(temp)
        if idx < ret['storageDepth'] - 1:
            if ret['storageNodeTypes'][idx] == 0:
                temp = temp + 1
            else:
                temp = temp + storage_pf['nodePathHexLen'][idx]
        elif idx == ret['storageDepth'] - 1:
            temp = temp + storage_pf['leafPathHexLen']
        
    return ret

parser = argparse.ArgumentParser()
parser.add_argument('--debug', action='store_true', default=False)

parser.add_argument('--addr', action='store_true', default=False)
parser.add_argument('--addr_file_str', type=str, default='inputs/input_address_proof.json')
parser.add_argument('--addr_max_depth', type=int, default=8)

parser.add_argument('--storage', action='store_true', default=False)
parser.add_argument('--storage_file_str', type=str, default='inputs/input_storage_proof.json')
parser.add_argument('--storage_max_depth', type=int, default=8)
parser.add_argument('--slot', type=int, default=10)
parser.add_argument('--punk_slot', type=int, default=0)

parser.add_argument('--eth_block_hash', action='store_true', default=False)
parser.add_argument('--eth_block_hash_file_str', type=str, default='inputs/input_eth_block_hash.json')

parser.add_argument('--eth_addr_storage', action='store_true', default=False)
parser.add_argument('--eth_addr_storage_file_str', type=str, default='inputs/input_addr_storage.json')

args = parser.parse_args()

def main():
    with open('punk_pfs.json', 'r') as f:
        punk_pfs = json.loads(f.read())
    with open('punk_block.json', 'r') as f:
        punk_block = json.loads(f.read())
        punk_block = punk_block['result']

    if args.eth_block_hash:
        block_pf = get_block_pf(punk_block, debug=args.debug)
        block_str = pprint.pformat(block_pf, width=100, compact=True).replace("'", '"')
        with open(args.eth_block_hash_file_str, 'w') as f:
            f.write(block_str)
            
    if args.addr:
        addr_pf = get_addr_pf(punk_pfs, debug=args.debug)
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
            
        storage_pf = get_storage_pf(punk_pfs, slot=slot, max_depth=args.storage_max_depth, debug=args.debug)
        print('Punk {:5} depth {:3}'.format(args.punk_slot, storage_pf['depth']))
        
        pf_str = pprint.pformat(storage_pf, width=100, compact=True).replace("'", '"')
        with open(args.storage_file_str, 'w') as f:
            f.write(pf_str)

        if args.debug:
            print(pf_str)

    if args.eth_addr_storage:
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

        eth_addr_storage_pf = get_addr_storage_pf(punk_block, punk_pfs, slot,
                                                  args.addr_max_depth,
                                                  args.storage_max_depth,
                                                  debug=args.debug)
        eth_addr_storage_str = pprint.pformat(eth_addr_storage_pf, width=100, compact=True).replace("'", '"')
        with open(args.eth_addr_storage_file_str, 'w') as f:
            f.write(eth_addr_storage_str)

if __name__ == '__main__':
    main()


