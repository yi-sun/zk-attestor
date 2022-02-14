import json
import sha3

def keccak256(x):
    k = sha3.keccak_256()
    k.update(bytearray.fromhex(x))
    return k.hexdigest()

slot_keys = []
for idx in range(12):
    x = hex(idx)[2:]
    x = ''.join(['0' for idx in range(64 - len(x))]) + x
    slot_keys.append(x)

for idx in range(10000):
    x = hex(idx)[2:]
    x = ''.join(['0' for idx in range(64 - len(x))]) + x
    y = hex(10)[2:]
    y = ''.join(['0' for idx in range(64 - len(y))]) + y
    x = x + y
    slot_keys.append(keccak256(x))

query_dict = {
    "id": 1337,
    "jsonrpc": "2.0",
    "method": "eth_getProof",
    "params": [
        "0xb47e3cd837ddf8e4c57f05d70ab865de6e193bbb",
        slot_keys,
        "latest"
    ]
}

with open('punk_query.json', 'w') as f:
    f.write(json.dumps(query_dict, indent=4))
