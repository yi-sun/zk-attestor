#!/bin/bash

PHASE1=../../circuits/pot24_final.ptau
INPUT_DIR=../input_gen/inputs
BUILD_DIR=../../build/punk_test
CIRCUIT_NAME=punk_storage

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
#circom "$CIRCUIT_NAME".circom --O1 --wasm --output "$BUILD_DIR"
end=`date +%s`
echo "DONE ($((end-start))s)"

echo "****GENERATING ZKEY 0****"
start=`date +%s`
NODE_OPTIONS="--max-old-space-size=56000" npx snarkjs groth16 setup "$BUILD_DIR"/"$CIRCUIT_NAME".r1cs "$PHASE1" "$BUILD_DIR"/"$CIRCUIT_NAME"_0.zkey
end=`date +%s`
echo "DONE ($((end-start))s)"

echo "****GENERATING FINAL ZKEY****"
start=`date +%s`
NODE_OPTIONS="--max-old-space-size=56000" npx snarkjs zkey beacon "$BUILD_DIR"/"$CIRCUIT_NAME"_0.zkey "$BUILD_DIR"/"$CIRCUIT_NAME".zkey 0102030405060708090a0b0c0d0e0f101112231415161718221a1b1c1d1e1f 10 -n="Final Beacon phase2"
end=`date +%s`
echo "DONE ($((end-start))s)"

echo "****VERIFYING FINAL ZKEY****"
start=`date +%s`
#NODE_OPTIONS="--max-old-space-size=56000" npx snarkjs zkey verify -verbose "$BUILD_DIR"/"$CIRCUIT_NAME".r1cs "$PHASE1" "$BUILD_DIR"/"$CIRCUIT_NAME".zkey
end=`date +%s`
echo "DONE ($((end-start))s)"

echo "****EXPORTING VKEY****"
start=`date +%s`
npx snarkjs zkey export verificationkey "$BUILD_DIR"/"$CIRCUIT_NAME".zkey "$BUILD_DIR"/vkey.json
end=`date +%s`
echo "DONE ($((end-start))s)"


for PUNK_IDX in {0..9999}
do
echo "****GENERATING WITNESS FOR SAMPLE INPUT $PUNK_IDX****"
start=`date +%s`
set -x
node "$BUILD_DIR"/"$CIRCUIT_NAME"_js/generate_witness.js "$BUILD_DIR"/"$CIRCUIT_NAME"_js/"$CIRCUIT_NAME".wasm "$INPUT_DIR"/input_punk_pf"$PUNK_IDX".json "$BUILD_DIR"/witness"$PUNK_IDX".wtns > "$BUILD_DIR"/log"$PUNK_IDX".log
end=`date +%s`
echo "DONE ($((end-start))s)"

echo "****GENERATING PROOF FOR SAMPLE INPUT****"
start=`date +%s`
npx snarkjs groth16 prove "$BUILD_DIR"/"$CIRCUIT_NAME".zkey "$BUILD_DIR"/witness"$PUNK_IDX".wtns "$BUILD_DIR"/proof"$PUNK_IDX".json "$BUILD_DIR"/public"$PUNK_IDX".json
end=`date +%s`
echo "DONE ($((end-start))s)"

echo "****VERIFYING PROOF FOR SAMPLE INPUT****"
start=`date +%s`
npx snarkjs groth16 verify "$BUILD_DIR"/vkey.json "$BUILD_DIR"/public"$PUNK_IDX".json "$BUILD_DIR"/proof"$PUNK_IDX".json
end=`date +%s`
echo "DONE ($((end-start))s)"
done





