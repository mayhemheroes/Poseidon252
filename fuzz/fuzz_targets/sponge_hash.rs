#![no_main]
use libfuzzer_sys::fuzz_target;
use dusk_poseidon::sponge;
use dusk_bls12_381::BlsScalar;

fuzz_target!(|input: Vec<[u64; 4]>| {
    let scalars: Vec<_> = input.iter().map(|c| BlsScalar::from_raw(*c)).collect();
    sponge::hash(&scalars);
});