use ark_crypto_primitives::{
    crh::CRHSchemeGadget,
    crh::poseidon::{CRH, constraints::CRHGadget},
    sponge::poseidon::PoseidonConfig,
};

use ark_ed_on_bls12_381::Fq;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

pub struct PoseidonDemoCircuit {
    pub input: Option<Fq>, // private input
    pub params: PoseidonConfig<Fq>,
    pub expected_output: Option<Fq>, // public input
}

impl ConstraintSynthesizer<Fq> for PoseidonDemoCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fq>) -> Result<(), SynthesisError> {
        // Allocate the input variable (private witness)
        let input_var = FpVar::new_witness(cs.clone(), || {
            self.input.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Allocate the Poseidon parameters as constants
        let params_var =
            <CRHGadget<Fq> as CRHSchemeGadget<CRH<Fq>, Fq>>::ParametersVar::new_constant(
                cs.clone(),
                &self.params,
            )?;

        // Compute the hash in the circuit 100 times
        let mut current_hash = CRHGadget::<Fq>::evaluate(&params_var, &[input_var])?;

        // Hash 99 more times (total of 100)
        for _ in 1..100 {
            current_hash = CRHGadget::<Fq>::evaluate(&params_var, &[current_hash])?;
        }

        // Allocate the expected output as a public input
        let expected_output_var = FpVar::new_input(cs, || {
            self.expected_output
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Enforce that the computed hash equals the expected output
        current_hash.enforce_equal(&expected_output_var)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_crypto_primitives::crh::{CRHScheme, poseidon::CRH};
    use ark_ed_on_bls12_381::Fq;
    use ark_ff::AdditiveGroup;
    use ark_groth16::{Groth16, r1cs_to_qap::LibsnarkReduction};
    use ark_snark::SNARK;
    use ark_std::{rand::SeedableRng, rand::rngs::StdRng};

    #[test]
    fn test_poseidon_hash_proof() {
        let rng = &mut StdRng::seed_from_u64(0u64);

        // Create Poseidon parameters with correct dimensions
        let width = 3;
        let full_rounds = 8;
        let partial_rounds = 56;

        // Create MDS matrix of size width x width
        let mds = vec![
            vec![Fq::from(1); width],
            vec![Fq::from(2); width],
            vec![Fq::from(3); width],
        ];

        // Create ARK matrix of size (full_rounds + partial_rounds) x width
        let ark = vec![vec![Fq::from(1); width]; full_rounds + partial_rounds];

        let poseidon_params = PoseidonConfig {
            full_rounds,
            partial_rounds,
            alpha: 5,
            rate: 2,
            capacity: 1,
            mds,
            ark,
        };

        // Compute the hash of the input 100 times
        let input_value = Fq::from(42u32);
        let mut current_hash = input_value;

        // Hash 100 times
        for _ in 0..100 {
            let input_vec = vec![current_hash];
            current_hash = CRH::<Fq>::evaluate(&poseidon_params, input_vec.as_slice()).unwrap();
        }

        let final_hash = current_hash;

        // Create a circuit with a dummy witness for setup
        let setup_circuit = PoseidonDemoCircuit {
            input: Some(Fq::ZERO), // Use a dummy value for setup
            params: poseidon_params.clone(),
            expected_output: Some(Fq::ZERO), // Use a dummy value for setup
        };

        // Generate the proving and verification keys
        let (pk, vk) =
            Groth16::<ark_bls12_381::Bls12_381, LibsnarkReduction>::circuit_specific_setup(
                setup_circuit,
                rng,
            )
            .unwrap();

        // Create a circuit with the actual witness for proving
        let proof_circuit = PoseidonDemoCircuit {
            input: Some(input_value), // Use the actual input value
            params: poseidon_params.clone(),
            expected_output: Some(final_hash), // Use the actual hash value
        };

        // Generate the proof
        let proof =
            Groth16::<ark_bls12_381::Bls12_381, LibsnarkReduction>::prove(&pk, proof_circuit, rng)
                .unwrap();

        // The public input is the hash value
        let public_inputs = vec![final_hash];
        println!(
            "Public input (hash after 100 iterations): {:?}",
            public_inputs[0]
        );

        // Verify the proof
        let is_valid = Groth16::<ark_bls12_381::Bls12_381, LibsnarkReduction>::verify(
            &vk,
            &public_inputs,
            &proof,
        )
        .unwrap();
        assert!(is_valid);
        println!("Proof verified successfully!");
    }
}
