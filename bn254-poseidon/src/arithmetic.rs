use std::marker::PhantomData;
use ark_bn254::Fr;
use ark_ff::{BigInteger, One, PrimeField, Zero};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};

#[derive(Debug)]
pub struct FrTarget<F: RichField + Extendable<D>, const D: usize> {
    pub target: Target,
    _phantom: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> FrTarget<F, D> {
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        let target = builder.add_virtual_target();
        Self { 
            target,
            _phantom: PhantomData,
        }
    }

    pub fn constant(value: &Fr, builder: &mut CircuitBuilder<F, D>) -> Self {
        let bytes = value.into_bigint().to_bytes_le();
        let target = builder.constant(F::from_canonical_u64(u64::from_le_bytes(bytes[0..8].try_into().unwrap())));
        Self { 
            target,
            _phantom: PhantomData,
        }
    }

    pub fn zero(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self::constant(&Fr::zero(), builder)
    }

    pub fn one(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self::constant(&Fr::one(), builder)
    }

    pub fn add(&self, other: &Self, builder: &mut CircuitBuilder<F, D>) -> Self {
        let sum = builder.add(self.target, other.target);
        Self { 
            target: sum,
            _phantom: PhantomData,
        }
    }

    pub fn sub(&self, other: &Self, builder: &mut CircuitBuilder<F, D>) -> Self {
        let diff = builder.sub(self.target, other.target);
        Self { 
            target: diff,
            _phantom: PhantomData,
        }
    }

    pub fn mul(&self, other: &Self, builder: &mut CircuitBuilder<F, D>) -> Self {
        let product = builder.mul(self.target, other.target);
        Self { 
            target: product,
            _phantom: PhantomData,
        }
    }

    pub fn exp_u64(&self, power: u64, builder: &mut CircuitBuilder<F, D>) -> Self {
        let mut result = Self::one(builder);
        let mut base = *self;
        let mut exp = power;

        while exp > 0 {
            if exp & 1 == 1 {
                result = result.mul(&base, builder);
            }
            base = base.mul(&base, builder);
            exp >>= 1;
        }

        result
    }

    pub fn to_native(&self, builder: &CircuitBuilder<F, D>) -> Fr {
        let value = builder.target_as_constant(self.target).unwrap();
        Fr::from(value.to_canonical_u64())
    }
}

impl<F: RichField + Extendable<D>, const D: usize> Copy for FrTarget<F, D> {}

impl<F: RichField + Extendable<D>, const D: usize> Clone for FrTarget<F, D> {
    fn clone(&self) -> Self {
        *self
    }
}
