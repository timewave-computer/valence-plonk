use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitData};
use plonky2::plonk::config::{GenericConfig, Hasher, PoseidonGoldilocksConfig};
use plonky2::util::serialization::{DefaultGateSerializer, IoResult};
use serde::Serialize;
use std::fs;

use num_bigint::BigUint;
use serde_json::Value;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

/// Recursively convert all Vec<u64> into single bigint strings,
/// flatten any { "elements": [...] } objects,
/// and skip this behavior ONLY for the "public_inputs" key.
fn serialize_goldilocks_bigints(val: Value) -> Value {
    match val {
        Value::Object(mut map) => {
            // Flatten { "elements": [...] } to just the packed string
            if map.len() == 1 && map.contains_key("elements") {
                return serialize_goldilocks_bigints(map.remove("elements").unwrap());
            }

            let keys: Vec<String> = map.keys().cloned().collect();
            for k in keys {
                let v = map.remove(&k).unwrap();
                let new_v = if k == "public_inputs" {
                    v // leave untouched
                } else if k == "circuit_digest" {
                    serialize_goldilocks_digest(v)
                } else {
                    serialize_goldilocks_bigints(v)
                };
                map.insert(k, new_v);
            }

            Value::Object(map)
        }

        Value::Array(arr) => {
            if arr.iter().all(|v| v.is_u64()) {
                let limbs: Vec<u64> = arr.into_iter().map(|v| v.as_u64().unwrap()).collect();
                let packed = limbs.iter().fold(BigUint::from(0u64), |acc, &x| {
                    (acc << 64) + BigUint::from(x)
                });
                Value::String(packed.to_str_radix(10))
            } else {
                Value::Array(arr.into_iter().map(serialize_goldilocks_bigints).collect())
            }
        }

        other => other,
    }
}

fn serialize_goldilocks_digest(val: Value) -> Value {
    match val {
        Value::Array(arr) if arr.iter().all(|v| v.is_u64()) => {
            let limbs: Vec<u64> = arr
                .into_iter()
                .take(3)
                .map(|v| v.as_u64().unwrap())
                .collect();
            let packed = limbs.iter().fold(BigUint::from(0u64), |acc, &x| {
                (acc << 64) + BigUint::from(x)
            });
            Value::String(packed.to_str_radix(10))
        }
        other => serialize_goldilocks_bigints(other),
    }
}

pub(crate) fn save_files<C: GenericConfig<D>, const D: usize>(
    data: &plonky2::plonk::circuit_data::CircuitData<C::F, C, D>,
    proof: &plonky2::plonk::proof::ProofWithPublicInputs<C::F, C, D>,
) -> IoResult<()>
where
    C: Serialize,
{
    let common_data_json = serde_json::to_value(&data.common).unwrap();
    let verifier_only_json = serde_json::to_value(&data.verifier_only).unwrap();
    let proof_json = serde_json::to_value(&proof).unwrap();

    let converted_common = serialize_goldilocks_bigints(common_data_json);
    let converted_verifier = serialize_goldilocks_bigints(verifier_only_json);
    let converted_proof = serialize_goldilocks_bigints(proof_json);

    fs::write(
        "src/out/common_circuit_data.json",
        serde_json::to_string_pretty(&converted_common).unwrap(),
    )
    .unwrap();

    fs::write(
        "src/out/verifier_only_circuit_data.json",
        serde_json::to_string_pretty(&converted_verifier).unwrap(),
    )
    .unwrap();

    fs::write(
        "src/out/proof_with_public_inputs.json",
        serde_json::to_string_pretty(&converted_proof).unwrap(),
    )
    .unwrap();

    Ok(())
}

#[test]
fn poseidon_flat_public_inputs() -> anyhow::Result<()> {
    use plonky2::field::types::Field;

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let preimage = builder.add_virtual_target();
    let expected_hash = builder.add_virtual_hash();

    let inputs = vec![preimage];
    let hash_target = builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs);

    for e in expected_hash.elements {
        builder.register_public_input(e);
    }

    builder.connect_hashes(expected_hash, hash_target);

    let data = builder.build::<C>();

    let preimage_value = F::from_canonical_u64(7);
    let hash_val = PoseidonHash::hash_no_pad(&[preimage_value]);

    let mut pw = PartialWitness::new();
    pw.set_target(preimage, preimage_value).unwrap();
    pw.set_hash_target(expected_hash, hash_val).unwrap();

    let proof = data.prove(pw).unwrap();

    save_files(&data, &proof).unwrap();

    let elf_serialized = data
        .verifier_data()
        .to_bytes(&DefaultGateSerializer)
        .expect("Failed to serialize program ELF");

    let elf_deserialized: VerifierCircuitData<F, C, D> =
        VerifierCircuitData::from_bytes(elf_serialized, &DefaultGateSerializer)
            .expect("Failed to deserialize program ELF");

    elf_deserialized.verify(proof).unwrap();
    Ok(())
}
