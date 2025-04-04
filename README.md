# Plonkish circuits for the Valence Coprocessor Trie
This repository will contain merkle proof circuits for our custom Trie implementation.

# 1. Plonky2
See [here](plonky-X/src/poseidon.rs)
## Wrapping with Groth16
We will likely want to use [Succinct's GNARK verifier](https://github.com/succinctlabs/gnark-plonky2-verifier/blob/main/README.md) for wrapping our PLONK proofs.

There is a serious, blocking issue with the wrapper, see [here](https://github.com/succinctlabs/gnark-plonky2-verifier/issues/56).
Unless resolved, we should not proceed with Plonky2 as a proof system for our poseidon tree.
## Data & Serialization
Proof must be serialized and dumped to files - this is unfortunate but the GNARK verifier was implemented in Go and therefore
we must use some tooling or bash scripts (Succinct use a docker image) for wrapping.
## Poseidon
We are currently focussing on a poseidon implementation in Plonky2, see [here](src/poseidon.rs)
## Developer Experience
Decent so long as not wrapping & using libraries.
## Painpoints
Wrapping, Trusted Setup

# 2. Halo2
See [here](halo2-scaffold/examples/poseidon.rs)
## Wrapping with Groth16

## Data & Serialization
Requires a complex structure which is mostly because of the trusted setup.
Many examples for serializing Halo2 proofs.
## Poseidon
Supported.
## Developer Experience
Beyond bad - very easy to make mistakes, probably even worse than circom.
## Painpoints
Dev X, Wrapping, Trusted Setup
