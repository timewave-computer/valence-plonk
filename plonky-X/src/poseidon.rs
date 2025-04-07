use num_bigint::BigUint;
use plonky2::hash::hash_types::{HashOut, RichField};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use serde::{Serialize, Serializer};
use serde_json::{Value, Map};
use plonky2::field::types::Field;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::{GenericConfig, Hasher, PoseidonGoldilocksConfig};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::util::serialization::{IoResult, DefaultGateSerializer};
use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitData};
use plonky2_bn254_poseidon::arithmetic::FrTarget;
use ark_bn254::Fr;
use num_traits::ToPrimitive;
use std::fs;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

fn serialize_with_key_path(val: Value, path: Vec<String>) -> Value {
    let modulus = BigUint::parse_bytes(b"FFFFFFFF00000001", 16).unwrap();
    let modulus_u64 = modulus.to_u64().unwrap();

    let current_key = path.last().map(|s| s.as_str());

    // ✅ Special-case: Don't touch `k_is`, just return raw u64 array
    if current_key == Some("k_is") {
        return val;
    }

    // Field elements known to be serialized in limb form
    let is_field_element_key = current_key.map_or(false, |key| {
        matches!(
            key,
            "siblings"
                | "constants_sigmas_cap"
                | "circuit_digest"
                | "wires_cap"
                | "quotient_polys_cap"
                | "plonk_zs_partial_products_cap"
        )
    });

    match val {
        Value::Object(mut map) => {
            // Auto-unwrap { "elements": [...] }
            if map.len() == 1 && map.contains_key("elements") {
                let inner = map.remove("elements").unwrap();
                return serialize_with_key_path(inner, path);
            }

            let mut out = Map::new();
            for (k, v) in map {
                let mut new_path = path.clone();
                new_path.push(k.clone());
                out.insert(k, serialize_with_key_path(v, new_path));
            }
            Value::Object(out)
        }

        Value::Array(arr) => {
            if is_field_element_key {
                // Case 1: Flat array of limbs
                if arr.iter().all(|v| v.is_u64()) && arr.len() % 4 == 0 {
                    let packed: Vec<_> = arr
                        .chunks(4)
                        .map(|chunk| {
                            let acc = chunk.iter().rev().fold(BigUint::from(0u64), |acc, limb| {
                                acc * &modulus + BigUint::from(limb.as_u64().unwrap())
                            });
                            Value::String(acc.to_string())
                        })
                        .collect();
                    return packed.first().unwrap().clone();
                }

                // Case 2: Nested arrays of limbs
                if arr.iter().all(|v| matches!(v, Value::Array(inner) if inner.len() == 4 && inner.iter().all(|x| x.is_u64()))) {
                    let packed: Vec<_> = arr
                        .into_iter()
                        .map(|inner| {
                            let inner = match inner {
                                Value::Array(inner) => inner,
                                _ => unreachable!(),
                            };
                            let acc = inner.into_iter().rev().fold(BigUint::from(0u64), |acc, limb| {
                                acc * &modulus + BigUint::from(limb.as_u64().unwrap())
                            });
                            Value::String(acc.to_string())
                        })
                        .collect();
                    return Value::Array(packed);
                }
            }

            // Generic case — recurse into sub-arrays
            Value::Array(
                arr.into_iter()
                    .map(|v| serialize_with_key_path(v, path.clone()))
                    .collect(),
            )
        }

        Value::Number(ref n) => {
            if let Some(u) = n.as_u64() {
                Value::Number(serde_json::Number::from(u % modulus_u64))
            } else {
                val
            }
        }

        other => other,
    }
}

// Save the relevant pieces as JSON files
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

    // Customized serializer that respects paths like `k_is`
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
fn add_public_inputs() -> anyhow::Result<()> {
    use plonky2::field::types::Field;

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Input setup
    let input = builder.add_virtual_target();
    let six = builder.constant(F::from_canonical_u64(6));
    let sum = builder.add(input, six);
    builder.register_public_input(sum);

    // Build and prove
    let data = builder.build::<C>();
    let input_value = F::from_canonical_u64(7);
    let mut pw = PartialWitness::new();
    pw.set_target(input, input_value).unwrap();
    let proof = data.prove(pw).unwrap();

    save_files(&data, &proof).unwrap();

    // Round-trip test for verifier data
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
