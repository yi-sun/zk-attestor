#!/bin/bash

PHASE1=../../circuits/pot24_final.ptau
BUILD_DIR=../../build/eth_tx
CIRCUIT_NAME=eth_tx

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
circom "$CIRCUIT_NAME".circom --r1cs --sym --c --output "$BUILD_DIR"
end=`date +%s`
echo "DONE ($((end-start))s)"

echo "****GENERATING WITNESS FOR SAMPLE INPUT****"
start=`date +%s`
set -x
cd "$BUILD_DIR"/"$CIRCUIT_NAME"_cpp 
make
./"$CIRCUIT_NAME" ../../../scripts/input_gen/inputs/input_tx2_proof.json ../witness.wtns > ../log.out
cd ../../../scripts/"$CIRCUIT_NAME"
end=`date +%s`
echo "DONE ($((end-start))s)"

echo "****GENERATING ZKEY 0****"
start=`date +%s`
~/node/out/Release/node --trace-gc --trace-gc-ignore-scavenger --max-old-space-size=2048000 --initial-old-space-size=2048000 --no-global-gc-scheduling --no-incremental-marking --max-semi-space-size=1024 --initial-heap-size=2048000 --expose-gc ~/snarkjs/cli.js zkey new "$BUILD_DIR"/"$CIRCUIT_NAME".r1cs "$PHASE1" "$BUILD_DIR"/"$CIRCUIT_NAME"_0.zkey
end=`date +%s`
echo "DONE ($((end-start))s)"

echo "****GENERATING FINAL ZKEY****"
start=`date +%s`
~/node/out/Release/node --trace-gc --trace-gc-ignore-scavenger --max-old-space-size=2048000 --initial-old-space-size=2048000 --no-global-gc-scheduling --no-incremental-marking --max-semi-space-size=1024 --initial-heap-size=2048000 --expose-gc ~/snarkjs/cli.js zkey beacon "$BUILD_DIR"/"$CIRCUIT_NAME"_0.zkey "$BUILD_DIR"/"$CIRCUIT_NAME".zkey 0102030405060708090a0b0c0d0e0f101112231415161718221a1b1c1d1e1f 10 -n="Final Beacon phase2"
end=`date +%s`
echo "DONE ($((end-start))s)"

echo "****VERIFYING FINAL ZKEY****"
start=`date +%s`
~/node/out/Release/node --trace-gc --trace-gc-ignore-scavenger --max-old-space-size=2048000 --initial-old-space-size=2048000 --no-global-gc-scheduling --no-incremental-marking --max-semi-space-size=1024 --initial-heap-size=2048000 --expose-gc ~/snarkjs/cli.js zkey verify "$BUILD_DIR"/"$CIRCUIT_NAME".r1cs "$PHASE1" "$BUILD_DIR"/"$CIRCUIT_NAME".zkey
end=`date +%s`
echo "DONE ($((end-start))s)"

echo "****EXPORTING VKEY****"
start=`date +%s`
~/node/out/Release/node --trace-gc --trace-gc-ignore-scavenger --max-old-space-size=2048000 --initial-old-space-size=2048000 --no-global-gc-scheduling --no-incremental-marking --max-semi-space-size=1024 --initial-heap-size=2048000 --expose-gc ~/snarkjs/cli.js zkey export verificationkey "$BUILD_DIR"/"$CIRCUIT_NAME".zkey "$BUILD_DIR"/vkey.json
end=`date +%s`
echo "DONE ($((end-start))s)"

echo "****EXPORTING Solidity Verifier****"
start=`date +%s`
~/node/out/Release/node --trace-gc --trace-gc-ignore-scavenger --max-old-space-size=2048000 --initial-old-space-size=2048000 --no-global-gc-scheduling --no-incremental-marking --max-semi-space-size=1024 --initial-heap-size=2048000 --expose-gc ~/snarkjs/cli.js zkey export solidityverifier "$BUILD_DIR"/"$CIRCUIT_NAME".zkey "$BUILD_DIR"/verifier.sol
end=`date +%s`
echo "DONE ($((end-start))s)"

echo "****GENERATING PROOF FOR SAMPLE INPUT****"
start=`date +%s`
~/rapidsnark/build/prover "$BUILD_DIR"/"$CIRCUIT_NAME".zkey "$BUILD_DIR"/witness.wtns "$BUILD_DIR"/proof.json "$BUILD_DIR"/public.json
#npx snarkjs groth16 prove "$BUILD_DIR"/"$CIRCUIT_NAME".zkey "$BUILD_DIR"/witness.wtns "$BUILD_DIR"/proof.json "$BUILD_DIR"/public.json
end=`date +%s`
echo "DONE ($((end-start))s)"

echo "****VERIFYING PROOF FOR SAMPLE INPUT****"
start=`date +%s`
~/node/out/Release/node --trace-gc --trace-gc-ignore-scavenger --max-old-space-size=2048000 --initial-old-space-size=2048000 --no-global-gc-scheduling --no-incremental-marking --max-semi-space-size=1024 --initial-heap-size=2048000 --expose-gc ~/snarkjs/cli.js groth16 verify "$BUILD_DIR"/vkey.json "$BUILD_DIR"/public.json "$BUILD_DIR"/proof.json
end=`date +%s`
echo "DONE ($((end-start))s)"

echo "****Generating Solidity input****"
start=`date +%s`
~/node/out/Release/node --trace-gc --trace-gc-ignore-scavenger --max-old-space-size=2048000 --initial-old-space-size=2048000 --no-global-gc-scheduling --no-incremental-marking --max-semi-space-size=1024 --initial-heap-size=2048000 --expose-gc ~/snarkjs/cli.js zkey export soliditycalldata "$BUILD_DIR"/public.json "$BUILD_DIR"/proof.json > "$BUILD_DIR"/solidity_input.in
end=`date +%s`
echo "DONE ($((end-start))s)"
