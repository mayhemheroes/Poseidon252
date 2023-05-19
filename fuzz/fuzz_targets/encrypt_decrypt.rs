#![no_main]
use libfuzzer_sys::fuzz_target;
use dusk_poseidon::cipher;
use dusk_bls12_381::BlsScalar;
use dusk_jubjub::{JubJubScalar, GENERATOR, JubJubAffine};
use core::ops::Mul;

fuzz_target!(|input: (Vec<[u64; 4]>, [u8; 64], [u64; 4])| {
    let message: Vec<_> = input.0.iter().map(|c| BlsScalar::from_raw(*c)).collect();
    let secret = JubJubScalar::from_bytes_wide(&input.1);
    let secret: JubJubAffine = GENERATOR.to_niels().mul(&secret).into();
    let nonce = BlsScalar::from_raw(input.2);
    let cipher = cipher::PoseidonCipher::encrypt(&message, &secret, &nonce);
    cipher.decrypt(&secret, &nonce);
});