#![allow(unused_imports)]
use babyjubjub_rs::utils::modulus;
use num::BigInt;
use num_bigint::RandBigInt;
use crate::{
    B8, SUBORDER, get_eff_ecdsa_args, new_ecdsa_key, sign_ecdsa, verify_ecdsa, verify_eff_ecdsa,
};

#[test]
fn test_new_key_sign_verify_0_ecdsa() {
    let sk = new_ecdsa_key();
    let pk = B8.mul_scalar(&sk);
    let msg = BigInt::parse_bytes(b"1234567890123456789012345690", 10).unwrap();
    let sig = sign_ecdsa(msg.clone(), sk).unwrap();
    verify_ecdsa(msg.clone(), sig.clone(), pk.clone());
}

#[test]
fn test_new_key_sign_verify_0_eff_ecdsa() {
    let sk = new_ecdsa_key();
    let pk = B8.mul_scalar(&sk);
    let msg = BigInt::parse_bytes(b"1234567890123456789012345690", 10).unwrap();
    let sig = sign_ecdsa(msg.clone(), sk).unwrap();
    let (t, u) = get_eff_ecdsa_args(msg.clone(), sig.clone());
    verify_eff_ecdsa(sig, t, u, pk);
}

#[test]
fn test_new_key_sign_verify_1_ecdsa() {
    for _ in 0..100 {
        let sk = new_ecdsa_key();
        let pk = B8.mul_scalar(&sk);

        let mut rng = rand::thread_rng();

        let msg = modulus(
            &rng.gen_bigint_range(&BigInt::from(21341253), &SUBORDER.clone()),
            &SUBORDER,
        );

        let sig = sign_ecdsa(msg.clone(), sk).unwrap();
        verify_ecdsa(msg.clone(), sig.clone(), pk.clone());
    }
}

#[test]
fn test_new_key_sign_verify_1_eff_ecdsa() {
    for _ in 0..100 {
        let sk = new_ecdsa_key();
        let pk = B8.mul_scalar(&sk);

        let mut rng = rand::thread_rng();

        let msg = modulus(
            &rng.gen_bigint_range(&BigInt::from(21341253), &SUBORDER.clone()),
            &SUBORDER,
        );
        let sig = sign_ecdsa(msg.clone(), sk).unwrap();

        let (t, u) = get_eff_ecdsa_args(msg, sig.clone());
        verify_eff_ecdsa(sig, t, u, pk);
    }
}
