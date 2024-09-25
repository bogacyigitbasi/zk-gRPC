/// ChaumPedersen pick two generators from group G
/// a, b and compute y1= a^x mod p and y2 = b^x mod p where x is witness
/// pick a random value k and compute R1= a^k and R2 = b^k mod p (note that these values known by the both parties)
/// verifier picks a random challenge c and sends it to prover
/// response = s = k - c*x is the proof
/// verifier will verify if R1 == a^s . y1^c and if R2 == b^s. y2^c
use num_bigint::BigUint;

// calculate the g^x mod p
// using the default modpow function in BigInt
pub fn mod_exp(num: &BigUint, exp: &BigUint, p: &BigUint) -> BigUint {
    num.modpow(exp, p)
}

/// in chaum_pedersen we have response s = k - c*x mod p
/// where k is a random number, x witness and c is the challenge given by verifier
///
pub fn proof(k: &BigUint, c: &BigUint, p: &BigUint, x: &BigUint) -> BigUint {
    if *k >= c * x {
        return (k - c * x).modpow(&BigUint::from(1u32), p);
    } else {
        return p - (k - c * x).modpow(&BigUint::from(1u32), p); // k < cx
    }
}

/// verifier will verify if R1 == a^s . y1^c mod p and if R2 == b^s. y2^c mod p
pub fn verify(
    a: &BigUint,  // generator
    b: &BigUint,  // generator
    y1: &BigUint, //public generated using x
    y2: &BigUint, //public generated using x
    r1: &BigUint, //public generated using k
    r2: &BigUint, //public generated using k
    c: &BigUint,  // challenge
    s: &BigUint,  // response
    p: &BigUint,  // mod
) -> bool {
    let left = *r1 == mod_exp(a, s, p) * mod_exp(y1, c, p);
    let right = *r2 == mod_exp(b, s, p) * mod_exp(y2, c, p);
    left & right
}
