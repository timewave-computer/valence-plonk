use ark_bn254::Fr;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2_bn254_poseidon::{
    arithmetic::FrTarget,
    poseidon::PoseidonCircuit,
};

fn main() {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let x_value = Fr::from(1u64);
    let y_value = Fr::from(2u64);
    let z_value = Fr::from(3u64);

    let mut circuit = PoseidonCircuit::<F, D>::new();
    let input = vec![
        FrTarget::<F, D>::constant(&x_value, &mut circuit.builder),
        FrTarget::<F, D>::constant(&y_value, &mut circuit.builder),
        FrTarget::<F, D>::constant(&z_value, &mut circuit.builder),
    ];
    let output = circuit.hash_fr(&input);

    println!("Input values: {:?}, {:?}, {:?}", x_value, y_value, z_value);
    println!("Output value: {:?}", output.to_native(&circuit.builder));
}
