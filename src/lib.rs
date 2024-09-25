use num_bigint::BigUint;

// calculate the g^x mod p
// using the default modpow function in BigInt
pub fn mod_exp(num: &BigUint, exp: &BigUint, p: &BigUint) -> BigUint {
    num.modpow(exp, p)
}

/// in chaum_pedersen we have response s = k - c*x mod p
/// where k is a random number, x witness and c is the challenge given by verifier
///
pub fn compute(k: &BigUint, c: &BigUint, p: &BigUint, x: &BigUint) -> BigUint {
    if *k >= c * x {
        return (k - c * x).modpow(&BigUint::from(1u32), p);
    } else {
        return p - (k - c * x).modpow(&BigUint::from(1u32), p);
    }
}
