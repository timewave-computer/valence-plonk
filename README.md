# Plonkish circuits for the Valence Coprocessor Trie
This repository will contain merkle proof circuits for our custom Trie implementation.

## Wrapping with Groth16
We will likely want to use [Succinct's GNARK verifier](https://github.com/succinctlabs/gnark-plonky2-verifier/blob/main/README.md) for wrapping our PLONK proofs.

## Serialization
Proof must be serialized and dumped to files - this is unfortunate but the GNARK verifier was implemented in Go and therefore
we must use some tooling or bash scripts (Succinct use a docker image) for wrapping.


## Poseidon
We are currently focussing on a poseidon implementation in Plonky2, see [here](src/poseidon.rs)