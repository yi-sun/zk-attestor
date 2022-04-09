#!/bin/bash

PHASE1=../../circuits/pot24_final.ptau
BUILD_DIR=../../build/bug
CIRCUIT_NAME=bug

if [ -f "$PHASE1" ]; then
    echo "Found Phase 1 ptau file"
else
    echo "No Phase 1 ptau file found. Exiting..."
    exit 1
fi

if [ ! -d "$BUILD_DIR" ]; then
    echo "No build directory found. Creating build directory..."
    mkdir "$BUILD_DIR"
fi

echo $PWD

echo "****COMPILING CIRCUIT****"
start=`date +%s`
circom "$CIRCUIT_NAME".circom --r1cs --wasm --sym --c --wat --output "$BUILD_DIR"
end=`date +%s`
echo "DONE ($((end-start))s)"

echo "****GENERATING WITNESS FOR SAMPLE INPUT****"
start=`date +%s`
node "$BUILD_DIR"/"$CIRCUIT_NAME"_js/generate_witness.js "$BUILD_DIR"/"$CIRCUIT_NAME"_js/"$CIRCUIT_NAME".wasm bug.json "$BUILD_DIR"/witness_js.wtns
set -x
cd "$BUILD_DIR"/"$CIRCUIT_NAME"_cpp
make
./"$CIRCUIT_NAME" ../../../scripts/bug/bug.json ../witness_cpp.wtns
npx snarkjs wej ../witness_js.wtns ../witness_js.json
npx snarkjs wej ../witness_cpp.wtns ../witness_cpp.json
diff ../witness_js.wtns ../witness_cpp.wtns
diff ../witness_js.json ../witness_cpp.json
