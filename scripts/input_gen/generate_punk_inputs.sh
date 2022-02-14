#!/bin/bash

for PUNK_IDX in {0..9999}
do
    python generate_storage_proof_inputs.py --storage --punk_slot "$PUNK_IDX" --storage_max_depth 8 --storage_file_str inputs/input_punk_pf"$PUNK_IDX".json
done
