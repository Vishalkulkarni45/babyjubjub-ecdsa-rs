#![allow(unused_imports)]
use crate::{
    B8, SUBORDER, get_eff_ecdsa_args, new_ecdsa_key, sign_ecdsa, verify_ecdsa, verify_eff_ecdsa,
};
use babyjubjub_rs::utils::modulus;
use num::BigInt;
use num_bigint::RandBigInt;

#[test]
fn test_new_key_sign_verify_0_ecdsa() {
    let sk = new_ecdsa_key();
    let pk = B8.mul_scalar(&sk);
    let test_msg: Vec<u8> = [
        57, 48, 70, 53, 66, 49, 65, 56, 57, 54, 53, 50, 56, 51, 54, 51, 53, 55, 54, 0,
    ]
    .to_vec();
    let sig = sign_ecdsa(test_msg.clone(), sk).unwrap();
    verify_ecdsa(test_msg, sig.clone(), pk.clone());
}

#[test]
fn test_new_key_sign_verify_0_eff_ecdsa() {
    let sk = new_ecdsa_key();
    let pk = B8.mul_scalar(&sk);
    let msg = BigInt::parse_bytes(b"1234567890123456789012345690", 10).unwrap();
    let (_, msg_bytes) = msg.to_bytes_le();

    let sig = sign_ecdsa(msg_bytes, sk).unwrap();
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
        let (_, msg_bytes) = msg.to_bytes_le();
        let sig = sign_ecdsa(msg_bytes.clone(), sk).unwrap();
        verify_ecdsa(msg_bytes, sig.clone(), pk.clone());
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
        let (_, msg_bytes) = msg.to_bytes_le();
        let sig = sign_ecdsa(msg_bytes, sk).unwrap();
        let (t, u) = get_eff_ecdsa_args(msg.clone(), sig.clone());
        verify_eff_ecdsa(sig, t, u, pk);
    }
}
