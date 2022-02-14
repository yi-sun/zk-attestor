#!/bin/bash

ID_FILE="./INFURA_ID"
INFURA_ID=$(cat "$ID_FILE")

curl -X POST --header "Content-Type: application/json" --data '{"id":1337, "jsonrpc": "2.0", "method":"eth_getBlockByNumber","params": ["latest", true]}' https://mainnet.infura.io/v3/"$INFURA_ID" > $1
curl -X POST --header "Content-Type: application/json" --data @punk_query.json https://mainnet.infura.io/v3/"$INFURA_ID" > $2

