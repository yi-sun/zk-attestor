# eth-attestor

Scalable on-chain trustless attestations to data from any past Ethereum block or state.

## Project overview

This repository provides implementations of account, storage, and transaction proofs for
Ethereum.  Together, these enable a user to generate validity proofs for data from any
current or past Ethereum block or state using a trusted block hash alone.

## Install dependencies

* Run `yarn` at the top level to install npm dependencies (`snarkjs` and `circomlib`).
* You'll also need `circom` version >= 2.0.2 on your system. Installation instructions [here](https://docs.circom.io/getting-started/installation).
* Building these circuits requires a Powers of Tau file with `2^24` constraints in the `circuits` subdirectory with the name `pot24_final.ptau`. One such file can be downloaded from the Hermez trusted setup [here](https://github.com/iden3/snarkjs#7-prepare-phase-2).

## Building proving keys and witness generation files

We provide four circuits, which together enable attestations to all current or
historical Ethereum data available from an archive node:

* `eth_block_hash`: Prove state, transaction, and receipt roots corresponding to a block hash.
* `address_proof`: Prove an account state corresponding to a state root.
* `storage_proof`: Prove the contents of a storage slot with corresponding storage root.
* `tx_proof`: Prove the contents of a transaction with corresponding transaction root.

Run `yarn build:eth_block_hash`, `yarn build:address`, `yarn build:storage`, `yarn build:tx` at the
top level to compile proving keys and witness generators for each file.

## Testing

Run `yarn test` at the top level to run tests. Note that these tests only test correctness of witness generation.