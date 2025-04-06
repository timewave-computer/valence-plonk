use num_bigint::BigUint;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitData};
use plonky2::plonk::config::{GenericConfig, Hasher, PoseidonGoldilocksConfig};
use plonky2::util::serialization::{DefaultGateSerializer, IoResult};
//use plonky2_bn254_poseidon::poseidon::PoseidonCircuit;
use plonky2::hash::poseidon::PoseidonHash;
use serde::Serialize;
use serde_json::Value;
use std::fs;
use std::str::FromStr;
use plonky2_bn254_poseidon::arithmetic::FrTarget;
use ark_bn254::Fr;
use plonky2::field::types::Field;
use num_traits::ToPrimitive;


const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

fn serialize_with_key_path(val: Value, path: Vec<String>) -> Value {
    fn is_bn254_field_array_key(path: &[String]) -> bool {
        matches!(
            path.last().map(|s| s.as_str()),
            Some(
                "siblings"
                    | "constants_sigmas_cap"
                    | "circuit_digest"
                    | "wires_cap"
                    | "quotient_polys_cap"
                    | "plonk_zs_partial_products_cap"
            )
        )
    }

    match val {
        Value::Object(mut map) => {
            if map.len() == 1 && map.contains_key("elements") && is_bn254_field_array_key(&path) {
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
            if is_bn254_field_array_key(&path) {
                // [[u64; 4], ...]
                if arr.iter().all(|v| matches!(v, Value::Array(inner) if inner.len() == 4 && inner.iter().all(|x| x.is_u64()))) {
                    let packed = arr.into_iter().map(|v| {
                        if let Value::Array(inner) = v {
                            let acc = inner
                                .into_iter()
                                .rev()
                                .fold(BigUint::from(0u64), |acc, x| {
                                    (acc << 64) + BigUint::from(x.as_u64().unwrap())
                                });
                            Value::String(acc.to_str_radix(10))
                        } else {
                            v // shouldn’t happen
                        }
                    }).collect();
                    return Value::Array(packed);
                }

                // Flat [u64, u64, ...]
                if arr.iter().all(|v| v.is_u64()) {
                    if arr.len() % 4 != 0 {
                        // 🛡️ Fallback to raw array (DON’T panic, DON’T wrap again)
                        return Value::Array(
                            arr.into_iter()
                                .map(|v| serialize_with_key_path(v, path.clone()))
                                .collect(),
                        );
                    }

                    let packed = arr
                        .chunks(4)
                        .map(|chunk| {
                            let acc = chunk
                                .iter()
                                .rev()
                                .fold(BigUint::from(0u64), |acc, x| {
                                    (acc << 64) + BigUint::from(x.as_u64().unwrap())
                                });
                            Value::String(acc.to_str_radix(10))
                        })
                        .collect();
                    return Value::Array(packed);
                }
            }

            // Default: recursively handle inner values, prevent nested string arrays
            Value::Array(
                arr.into_iter()
                    .map(|v| {
                        let inner = serialize_with_key_path(v, path.clone());
                        if let Value::Array(single) = &inner {
                            if single.len() == 1 && single[0].is_string() {
                                return single[0].clone();
                            }
                        }
                        inner
                    })
                    .collect(),
            )
        }

        Value::Number(ref n) => {
            if let Some(u) = n.as_u64() {
                Value::Number((BigUint::from(u) % F::order()).to_u64().unwrap().into())
            } else {
                val
            }
        }

        other => other,
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
    let proof_json = serde_json::to_value(proof).unwrap();

    let common_data_simplified = serialize_with_key_path(common_data_json, vec![]);
    let verifier_only_simplified = serialize_with_key_path(verifier_only_json, vec![]);
    let proof_simplified = serialize_with_key_path(proof_json, vec![]);

    fs::write(
        "src/out/common_circuit_data.json",
        serde_json::to_string_pretty(&common_data_simplified).unwrap(),
    ).unwrap();

    fs::write(
        "src/out/verifier_only_circuit_data.json",
        serde_json::to_string_pretty(&verifier_only_simplified).unwrap(),
    ).unwrap();

    fs::write(
        "src/out/proof_with_public_inputs.json",
        serde_json::to_string_pretty(&proof_simplified).unwrap(),
    ).unwrap();

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
