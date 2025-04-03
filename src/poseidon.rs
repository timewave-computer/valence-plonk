use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitData};
use plonky2::util::serialization::{DefaultGateSerializer, IoResult};
use plonky2::plonk::config::{GenericConfig, Hasher, PoseidonGoldilocksConfig};
use serde_json::Value;
use std::fs;
use serde::Serialize;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

/// Turn arrays of field elements under "elements" into a single string bigint
fn serialize_elements_as_bigint(val: Value) -> Value {
    match val {
        Value::Object(mut map) => {
            if let Some(elements) = map.remove("elements") {
                if let Value::Array(arr) = elements {
                    let joined = arr
                        .into_iter()
                        .map(|v| v.to_string())
                        .collect::<Vec<_>>()
                        .join(""); // join digits
                    return Value::String(joined);
                }
            }
            let keys: Vec<String> = map.keys().cloned().collect();
            for k in keys {
                if let Some(v) = map.remove(&k) {
                    map.insert(k, serialize_elements_as_bigint(v));
                }
            }
            Value::Object(map)
        }
        Value::Array(vec) => {
            Value::Array(vec.into_iter().map(serialize_elements_as_bigint).collect())
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
    let proof_json = serde_json::to_value(&proof).unwrap();

    let converted_common = serialize_elements_as_bigint(common_data_json);
    let converted_verifier = serialize_elements_as_bigint(verifier_only_json);
    let converted_proof = serialize_elements_as_bigint(proof_json);

    fs::write(
        "src/out/common_circuit_data.json",
        serde_json::to_string_pretty(&converted_common).unwrap(),
    ).unwrap();

    fs::write(
        "src/out/verifier_only_circuit_data.json",
        serde_json::to_string_pretty(&converted_verifier).unwrap(),
    ).unwrap();

    fs::write(
        "src/out/proof_with_public_inputs.json",
        serde_json::to_string_pretty(&converted_proof).unwrap(),
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
    pw.set_target(preimage, preimage_value);
    pw.set_hash_target(expected_hash, hash_val);

    let proof = data.prove(pw)?;

    save_files(&data, &proof).unwrap();

    let elf_serialized = data.verifier_data().to_bytes(&DefaultGateSerializer)
        .expect("Failed to serialize program ELF");

    let elf_deserialized: VerifierCircuitData<F, C, D> = VerifierCircuitData::from_bytes(
        elf_serialized,
        &DefaultGateSerializer,
    ).expect("Failed to deserialize program ELF");

    elf_deserialized.verify(proof)?;
    Ok(())
}
