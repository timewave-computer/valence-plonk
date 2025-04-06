use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
    },
};

use super::arithmetic::FrTarget;

pub const RATE: usize = 2;
pub const CAPACITY: usize = 1;
pub const WIDTH: usize = RATE + CAPACITY;

pub struct PoseidonCircuit<F: RichField + Extendable<D>, const D: usize> {
    pub builder: CircuitBuilder<F, D>,
}

impl<F: RichField + Extendable<D>, const D: usize> PoseidonCircuit<F, D> {
    pub fn new() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let builder = CircuitBuilder::<F, D>::new(config);
        Self { builder }
    }

    pub fn hash_fr(&mut self, input: &[FrTarget<F, D>]) -> FrTarget<F, D> {
        let mut state = vec![FrTarget::<F, D>::zero(&mut self.builder); WIDTH];
        for (i, &x) in input.iter().enumerate() {
            state[i % RATE] = state[i % RATE].add(&x, &mut self.builder);
        }
        self.permute(&mut state);
        state[0]
    }

    fn permute(&mut self, state: &mut [FrTarget<F, D>]) {
        let rounds = 8;
        for _ in 0..rounds {
            // Add round constants
            for i in 0..WIDTH {
                state[i] = state[i].add(&FrTarget::<F, D>::one(&mut self.builder), &mut self.builder);
            }
            // SBox
            for i in 0..WIDTH {
                state[i] = self.sbox(&state[i]);
            }
            // Mix layer
            let mut new_state = vec![FrTarget::<F, D>::zero(&mut self.builder); WIDTH];
            for i in 0..WIDTH {
                for j in 0..WIDTH {
                    new_state[i] = new_state[i].add(&state[j], &mut self.builder);
                }
            }
            state.copy_from_slice(&new_state);
        }
    }

    fn sbox(&mut self, x: &FrTarget<F, D>) -> FrTarget<F, D> {
        let x2 = x.mul(x, &mut self.builder);
        let x4 = x2.mul(&x2, &mut self.builder);
        x4.mul(x, &mut self.builder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use plonky2::{
        field::types::Field,
        plonk::config::{GenericConfig, PoseidonGoldilocksConfig},
    };

    #[test]
    fn test_poseidon_hash() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let mut circuit = PoseidonCircuit::<F, D>::new();
        let input = vec![FrTarget::<F, D>::constant(&Fr::from(1u64), &mut circuit.builder)];
        let output = circuit.hash_fr(&input);
        let expected = Fr::from(1u64);
        assert_eq!(output.to_native(&circuit.builder), expected);
    }
}
