#!/bin/bash

for TX_IDX in {0..196}
do
    python generate_tx_proof_inputs.py --tx_idx "$TX_IDX" --max_depth 6 --max_key_len 6 --max_val_len 15000 --file_str inputs/input_tx_pf"$TX_IDX".json
done
