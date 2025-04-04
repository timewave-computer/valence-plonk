use num_bigint::BigUint;
use num_traits::cast::ToPrimitive;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitData};
use plonky2::plonk::config::{GenericConfig, Hasher, PoseidonGoldilocksConfig};
use plonky2::util::serialization::{DefaultGateSerializer, IoResult};
use serde::Serialize;
use serde_json::Value;
use std::fs;
use std::str::FromStr;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

// The modulus for Goldilocks field
const MODULUS_HEX: &str = "FFFFFFFF00000001";

fn modpow_with_modulus(base: &BigUint, exponent: &BigUint, modulus: &BigUint) -> BigUint {
    base.modpow(exponent, modulus)
}

fn serialize_goldilocks_bigints(val: Value) -> Value {
    serialize_with_key_path(val, vec![])
}

fn serialize_with_key_path(val: Value, path: Vec<String>) -> Value {
    let modulus: BigUint = BigUint::parse_bytes(MODULUS_HEX.as_bytes(), 16).unwrap();

    match val {
        Value::Object(mut map) => {
            // Flatten {"elements": [...]}, except for the key "public_inputs"
            if map.len() == 1 && map.contains_key("elements") {
                return serialize_with_key_path(map.remove("elements").unwrap(), path);
            }

            let mut result = serde_json::Map::new();
            for (k, v) in map {
                let mut new_path = path.clone();
                new_path.push(k.clone());
                result.insert(k, serialize_with_key_path(v, new_path));
            }

            Value::Object(result)
        }

        Value::Array(arr) => {
            if arr.iter().all(|v| v.is_u64()) {
                let key = path.last().map(|s| s.as_str()).unwrap_or("");
                // Check for specific fields like "siblings", "constants_sigmas_cap" etc.
                if matches!(
                    key,
                    "siblings"
                        | "constants_sigmas_cap"
                        | "circuit_digest"
                        | "wires_cap"
                        | "quotient_polys_cap"
                        | "plonk_zs_partial_products_cap"
                ) {
                    let limbs: Vec<u64> = arr.into_iter().map(|v| v.as_u64().unwrap()).collect();
                    let packed = limbs.iter().fold(BigUint::from(0u64), |acc, &x| {
                        (acc << 64) + BigUint::from(x)
                    });

                    let reduced = packed % &modulus;
                    return Value::String(reduced.to_str_radix(10)); // Return reduced value as a string
                } else {
                    // Reduce all u64 values modulo the Goldilocks modulus
                    Value::Array(
                        arr.into_iter()
                            .map(|v| {
                                let reduced = BigUint::from(v.as_u64().unwrap()) % &modulus;
                                Value::Number(serde_json::Number::from(reduced.to_u64().unwrap()))
                            })
                            .collect(),
                    )
                }
            } else {
                // For non-u64 values, recursively call the function on the elements
                Value::Array(
                    arr.into_iter()
                        .map(|v| serialize_with_key_path(v, path.clone()))
                        .collect(),
                )
            }
        }

        // Handle cases for `BigInt` and other types
        Value::Number(ref n) => {
            if let Some(num) = n.as_u64() {
                let big_num = BigUint::from(num);
                let reduced = big_num % &modulus;
                Value::Number(serde_json::Number::from(reduced.to_u64().unwrap()))
            } else {
                // If it's a non-u64 number, simply return it
                val
            }
        }

        other => other.clone(), // Handle other types (e.g., strings, booleans, etc.)
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
