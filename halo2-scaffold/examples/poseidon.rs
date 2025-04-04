use clap::Parser;
use halo2_base::{
    gates::{circuit::builder::BaseCircuitBuilder, GateChip},
    poseidon::hasher::PoseidonHasher,
    utils::BigPrimeField,
    AssignedValue,
};
use halo2_scaffold::scaffold::{cmd::Cli, run};
use serde::{Deserialize, Serialize};
use snark_verifier_sdk::halo2::OptimizedPoseidonSpec;

const T: usize = 3;
const RATE: usize = 2;
const R_F: usize = 8;
const R_P: usize = 57;
const NUM_HASHES: usize = 100;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitInput {
    pub inputs: [String; 2], // two field elements, but as strings for easier deserialization
}

fn hash_two<F: BigPrimeField>(
    builder: &mut BaseCircuitBuilder<F>,
    inp: CircuitInput,
    make_public: &mut Vec<AssignedValue<F>>,
) {
    let ctx = builder.main(0);

    let [x, y] = inp.inputs.map(|x| ctx.load_witness(F::from_str_vartime(&x).unwrap()));

    // Commit input values to the public inputs (optional, but commonly done for transparency)
    make_public.extend([x, y]);

    let gate = GateChip::<F>::default();
    let mut poseidon =
        PoseidonHasher::<F, T, RATE>::new(OptimizedPoseidonSpec::new::<R_F, R_P, 0>());
    poseidon.initialize_consts(ctx, &gate);

    // Initial hash of the two inputs
    let mut hash = poseidon.hash_fix_len_array(ctx, &gate, &[x, y]);

    // Chain 99 more hashes using a constant for variety
    for i in 0..(NUM_HASHES - 1) {
        let const_val = ctx.load_constant(F::from(i as u64));
        hash = poseidon.hash_fix_len_array(ctx, &gate, &[hash, const_val]);
    }

    // 👇 Commit final hash to the public inputs of the circuit (this is the actual output)
    make_public.push(hash);

    println!("x: {:?}, y: {:?}, final_poseidon_hash: {:?}", x.value(), y.value(), hash.value());
}

fn main() {
    env_logger::init();

    let args = Cli::parse();
    run(hash_two, args);
}

#[cfg(test)]
mod tests {
    use snark_verifier_sdk::Snark;
    use std::fs::File;
    use std::io::BufReader;
    #[test]
    fn print_final_hash_commitment() {
        let file = File::open("/Users/chef/Desktop/halo2-scaffold/data/poseidon.snark")
            .expect("cannot open snark file");
        let reader = BufReader::new(file);

        let snark: Snark = bincode::deserialize_from(reader).expect("failed to deserialize snark");

        println!("Public inputs:");
        for (i, instance_group) in snark.instances.iter().enumerate() {
            println!("Instance group {}:", i);
            for val in instance_group {
                println!("{:?}", val); // Use Debug trait, not Display
            }
        }
    }
}
