use babyjubjub_rs::{
    Point, Signature,
    utils::{concatenate_arrays, modulus},
};
use ff::*;
use num_bigint::{BigInt, RandBigInt, Sign};
use num_traits::One;

use poseidon_rs::Poseidon;
pub type Fr = poseidon_rs::Fr;

#[cfg(not(feature = "aarch64"))]
use blake_hash::Digest;

#[cfg(feature = "aarch64")]
extern crate blake;

mod test;

use lazy_static::lazy_static;
lazy_static! {
    static ref D: Fr = Fr::from_str("168696").unwrap();
    static ref D_BIG: BigInt = BigInt::parse_bytes(b"168696", 10).unwrap();
    static ref A: Fr = Fr::from_str("168700").unwrap();
    static ref A_BIG: BigInt = BigInt::parse_bytes(b"168700", 10).unwrap();
    pub static ref Q: BigInt = BigInt::parse_bytes(
        b"21888242871839275222246405745257275088548364400416034343698204186575808495617",10
    )
        .unwrap();
    pub static ref B8: Point = Point {
        x: Fr::from_str(
               "5299619240641551281634865583518297030282874472190772894086521144482721001553",
           )
            .unwrap(),
            y: Fr::from_str(
                "16950150798460657717958625567821834550301663161624707787222815936182638968203",
            )
                .unwrap(),
    };
    static ref ORDER: Fr = Fr::from_str(
        "21888242871839275222246405745257275088614511777268538073601725287587578984328",
    )
        .unwrap();

    // SUBORDER = ORDER >> 3
    static ref SUBORDER: BigInt = &BigInt::parse_bytes(
        b"21888242871839275222246405745257275088614511777268538073601725287587578984328",
        10,
    )
        .unwrap()
        >> 3;
    static ref POSEIDON: poseidon_rs::Poseidon = Poseidon::new();
}

#[allow(non_snake_case)]
pub fn sign_ecdsa(msg: Vec<u8>, key: BigInt) -> Result<Signature, String> {
    // Convert the message and key to byte arrays
    let (_, key_bytes) = key.to_bytes_le();

    // Hash the message bytes
    let h: Vec<u8> = blh(&msg);

    // Concatenate key bytes and message hash to form the preimage for k
    let k_preimage = concatenate_arrays(&key_bytes, &h);

    // Deterministically generate the nonce k and reduce it modulo the subgroup order
    let k = modulus(
        &BigInt::from_bytes_le(Sign::Plus, &blh(&k_preimage)),
        &SUBORDER,
    );

    // Calculate the curve point R = k * G
    let R = B8.mul_scalar(&k);

    // Use the x-coordinate of R as r (after conversion and reduction)
    let r = R.x;
    let r_scalar = modulus(
        &BigInt::parse_bytes(to_hex(&r).as_bytes(), 16).unwrap(),
        &SUBORDER,
    );

    // Reject signatures where r is zero (invalid per ECDSA spec)
    if r_scalar == BigInt::from(0) {
        return Err("r is zero, invalid signature".to_string());
    }

    // Compute the modular inverse of k
    let k_inv = match k.modinv(&SUBORDER) {
        Some(k_inv) => k_inv,
        None => return Err("k inverse not found".to_string()),
    };

    // Sanity check: k * k_inv mod n == 1
    assert_eq!(modulus(&(k_inv.clone() * k), &SUBORDER), BigInt::one());

    // Hash the message to a scalar
    let msg_hash = get_msg_hash(msg)?;

    // Compute s = k_inv * (msg_hash + r * key) mod n
    let s = modulus(&(k_inv * (msg_hash + r_scalar * key)), &SUBORDER);

    // Reject signatures where s is zero (invalid per ECDSA spec)
    if s == BigInt::from(0) {
        return Err("s is zero, invalid signature".to_string());
    }

    // Return the signature (R point and scalar s)
    Ok(Signature { r_b8: R, s })
}
#[allow(non_snake_case)]
pub fn get_eff_ecdsa_args(msg: BigInt, sig: Signature) -> (Point, Point) {
    // Compute the hash of the message as a scalar
    let (_, msg_bytes) = msg.to_bytes_le();
    let msg_hash = get_msg_hash(msg_bytes).unwrap();

    // Recover r from the signature's R point x-coordinate, reduced modulo the subgroup order
    let r = modulus(
        &BigInt::parse_bytes(to_hex(&sig.r_b8.x).as_bytes(), 16).unwrap(),
        &SUBORDER,
    );

    // Compute the modular inverse of r modulo the subgroup order
    let r_inv = r.modinv(&SUBORDER).unwrap();

    // T = R * r_inv, where R is the signature's R point
    let T = sig.r_b8.mul_scalar(&r_inv);

    // U = G * (-r_inv * msg_hash mod n), where G is the generator
    let U = B8.mul_scalar(&(modulus(&(-r_inv * msg_hash), &SUBORDER)));

    // Return the two points (T, U) for efficient ECDSA verification
    (T, U)
}

pub fn verify_ecdsa(msg: Vec<u8>, sig: Signature, pk: Point) -> bool {
    let msg_hash = get_msg_hash(msg).unwrap();

    let s_inv = match sig.s.modinv(&SUBORDER) {
        Some(s_inv) => s_inv,
        None => return false,
    };

    let r = modulus(
        &BigInt::parse_bytes(to_hex(&sig.r_b8.x).as_bytes(), 16).unwrap(),
        &SUBORDER,
    );

    // u1 = msg_hash * s_inv mod n
    let u1 = modulus(&(msg_hash * &s_inv), &SUBORDER);
    // u2 = r * s_inv mod n
    let u2 = modulus(&(r.clone() * &s_inv), &SUBORDER);

    // R = u1*G + u2*pk
    let u1_g = B8.mul_scalar(&u1);
    let u2_pk = pk.mul_scalar(&u2);
    let r_point = u1_g.projective().add(&u2_pk.projective()).affine();

    // Check if R.x mod n == r
    let r_x = modulus(
        &BigInt::parse_bytes(to_hex(&r_point.x).as_bytes(), 16).unwrap(),
        &SUBORDER,
    );
    r_x == r
}

pub fn verify_eff_ecdsa(sig: Signature, t: Point, u: Point, pk: Point) {
    // Efficient ECDSA verification using precomputed points T and U:
    // Check if s*T + U == pk
    let lhs = t
        .mul_scalar(&sig.s)
        .projective()
        .add(&u.projective())
        .affine();
    assert!(lhs.equals(pk), "Efficient ECDSA verification failed");
}

#[cfg(not(feature = "aarch64"))]
fn blh(b: &[u8]) -> Vec<u8> {
    let hash = blake_hash::Blake512::digest(b);
    hash.to_vec()
}
#[cfg(feature = "aarch64")]
fn blh(b: &[u8]) -> Vec<u8> {
    let mut hash = [0; 64];
    blake::hash(512, b, &mut hash).unwrap();
    hash.to_vec()
}

fn get_msg_hash(msg_bytes: Vec<u8>) -> Result<BigInt, String> {
    // let msg_bytes_fr = msg_bytes
    //     .into_iter()
    //     .map(|x| Fr::from_str(&x.to_string()).unwrap())
    //     .collect::<Vec<Fr>>();

    let msg_big = BigInt::from_bytes_le(Sign::Plus, &msg_bytes);

    let msg_hash = POSEIDON.hash(vec![Fr::from_str(&msg_big.to_string()).unwrap()])?;

    let msg_hash_big = BigInt::parse_bytes(to_hex(&msg_hash).as_bytes(), 16).unwrap();
    let msg_hash = modulus(&msg_hash_big, &SUBORDER);
    Ok(msg_hash)
}
pub fn new_ecdsa_key() -> BigInt {
    let mut rng = rand::thread_rng();

    modulus(
        &rng.gen_bigint_range(&BigInt::from(21341253), &SUBORDER.clone()),
        &SUBORDER,
    )
}
