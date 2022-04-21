# zkAttestor

Scalable on-chain trustless attestations to data from any past Ethereum block or state.

## Project overview

This repository provides implementations of account, storage, and transaction proofs for
Ethereum.  Together, these enable a user to generate validity proofs for data from any
current or past Ethereum block or state using a trusted block hash alone.

**These implementations are for demonstration purposes only**.  These circuits are not
audited, and this is not intended to be used as a library for production-grade applications.

## Install dependencies

* Run `yarn` at the top level to install npm dependencies (`snarkjs` and `circomlib`).
* You'll also need `circom` version >= 2.0.2 on your system. Installation instructions [here](https://docs.circom.io/getting-started/installation).
* Building these circuits requires a Powers of Tau file with `2^24` constraints in the `circuits` subdirectory with the name `pot24_final.ptau`. One such file can be downloaded from the Hermez trusted setup [here](https://github.com/iden3/snarkjs#7-prepare-phase-2).
* Finally, you'll need to follow the setup instructions at [Best Practices for Large Circuits](https://hackmd.io/V-7Aal05Tiy-ozmzTGBYPA).

## Building proving keys and witness generation files

We provide three circuits, which enable attestations to all current or
historical Ethereum data available from an archive node with the exception of receipts,
which are WIP:

* `eth_block_hash`: Prove state, transaction, and receipt roots corresponding to a block hash.
* `eth_addr_storage`: Prove the contents of a storage slot for an account from a block hash.
* `eth_tx_proof`: Prove the contents of a transaction from a block hash.

Run `yarn build:eth_block_hash`, `yarn build:eth_addr_storage`, `yarn build:eth_tx_proof` at the
top level to compile proving keys and witness generators for each file.

These circuits are fairly large and require special hardware and setup to run: see
[Best Practices for Large Circuits](https://hackmd.io/V-7Aal05Tiy-ozmzTGBYPA).

## Testing

Run `yarn test` at the top level to run tests. Note that these tests only test correctness
of witness generation.

## Acknowledgements

We use a [circom implementation of keccak](https://github.com/vocdoni/keccak256-circom) from Vocdoni
as well as the [eth-mpt Python library](https://pypi.org/project/eth-mpt) by [popzxc](https://github.com/popzxc).