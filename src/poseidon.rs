#[cfg(test)]
mod examples {
    use plonky2::field::types::Field;
    use plonky2::hash::poseidon::PoseidonHash;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitData};
    use plonky2::plonk::config::{GenericConfig, Hasher, PoseidonGoldilocksConfig};
    use plonky2::util::serialization::DefaultGateSerializer;

    #[test]
    fn poseidon() -> anyhow::Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let preimage = builder.add_virtual_target();

        let expected_hash_1 = builder.add_virtual_target();
        let expected_hash_2 = builder.add_virtual_target();
        let expected_hash_3 = builder.add_virtual_target();
        let expected_hash_4 = builder.add_virtual_target();

        builder.register_public_input(expected_hash_1);
        builder.register_public_input(expected_hash_2);
        builder.register_public_input(expected_hash_3);
        builder.register_public_input(expected_hash_4);

        let inputs = vec![preimage];
        let hash_target = builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs);

        builder.connect(hash_target.elements[0], expected_hash_1);
        builder.connect(hash_target.elements[1], expected_hash_2);
        builder.connect(hash_target.elements[2], expected_hash_3);
        builder.connect(hash_target.elements[3], expected_hash_4);

        let data = builder.build::<C>();
        let preimage_value = F::from_canonical_u64(7);
        let hash_val = PoseidonHash::hash_no_pad(&[preimage_value]);

        let mut pw = PartialWitness::new();
        // set the targets for the expected, constrained hash values
        pw.set_target(preimage, preimage_value)?;
        pw.set_target(expected_hash_1, hash_val.elements[0])?;
        pw.set_target(expected_hash_2, hash_val.elements[1])?;
        pw.set_target(expected_hash_3, hash_val.elements[2])?;
        pw.set_target(expected_hash_4, hash_val.elements[3])?;

        let proof = data.prove(pw)?;

        println!("Expected hash: {:?}", hash_val.elements.to_vec());
        println!("Proof public input: {:?}", proof.public_inputs.to_vec());
        let elf_serialized = data.verifier_data().to_bytes(&DefaultGateSerializer).expect("Failed to serialize program ELF");
        let elf_deserialized: VerifierCircuitData<F, C, D> = VerifierCircuitData::from_bytes(elf_serialized, &DefaultGateSerializer).expect("Failed to deserialize program ELF");
        elf_deserialized.verify(proof)?;
        Ok(())
    }

    // to hash poseidon hashs together in a merkle tree:
    // parent = PoseidonHash::hash_no_pad(&[...left.elements, ...right.elements])
}
