/// ChaumPedersen pick two generators from group G
/// a, b and compute y1= a^x mod p and y2 = b^x mod p where x is witness
/// pick a random value k and compute R1= a^k and R2 = b^k mod p (note that these values known by the both parties)
/// verifier picks a random challenge c and sends it to prover
/// response = s = k - c*x mod q (order?) is the proof
/// verifier will verify if R1 == a^s . y1^c and if R2 == b^s. y2^c
use num_bigint::{BigUint, RandBigInt};

// calculate the g^x mod p
// using the default modpow function in BigInt
pub fn mod_exp(num: &BigUint, exp: &BigUint, p: &BigUint) -> BigUint {
    num.modpow(exp, p)
}

/// in chaum_pedersen we have response s = k - c*x mod p
/// where k is a random number, x witness and c is the challenge given by verifier
///
pub fn proof(k: &BigUint, c: &BigUint, x: &BigUint, p: &BigUint) -> BigUint {
    if *k >= c * x {
        return (k - c * x).modpow(&BigUint::from(1u32), p);
    } else {
        return p - (c * x - k).modpow(&BigUint::from(1u32), p); // k < cx
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
    let left = *r1
        == mod_exp(
            &(mod_exp(a, s, p) * mod_exp(y1, c, p)),
            &BigUint::from(1u32),
            &p,
        );
    let right = *r2
        == mod_exp(
            &(mod_exp(b, s, p) * mod_exp(y2, c, p)),
            &BigUint::from(1u32),
            p,
        );
    left && right
}
/// generate random binguint
use rand;
pub fn gen_rand(max: &BigUint) -> BigUint {
    let mut rng = rand::thread_rng();
    rng.gen_biguint_below(max)
}

/// add unit tests
#[cfg(test)]
mod test {

    use super::*; // all functions above will be used

    #[test]
    fn test_ex() {
        // lets pick two generators
        let a = BigUint::from(4u32);
        let b = BigUint::from(9u32);
        // set a witness value.
        let w = BigUint::from(6u32);
        // module
        let p = BigUint::from(23u32);
        // order of group
        let q = BigUint::from(11u32);

        let y1 = mod_exp(&a, &w, &p);
        let y2 = mod_exp(&b, &w, &p);

        assert_eq!(y1, BigUint::from(2u32));
        assert_eq!(y2, BigUint::from(3u32));
        // generate random k
        // let mut rng = rand::thread_rng();
        // let k = rng.gen_biguint(32);
        let k = BigUint::from(7u32);
        let r1 = mod_exp(&a, &k, &p);
        let r2 = mod_exp(&b, &k, &p);

        assert_eq!(r1, BigUint::from(8u32));
        assert_eq!(r2, BigUint::from(4u32));
        let c = BigUint::from(4u32);

        // compute response
        let s = proof(&k, &c, &w, &q);
        assert_eq!(s, BigUint::from(5u32));
        // lets verify
        let verif = verify(&a, &b, &y1, &y2, &r1, &r2, &c, &s, &p);
        assert!(verif);
        // let left = mod_exp(&a, &s, &p) * mod_exp(&y1, &c, &p);
        // let right = mod_exp(&b, &s, &p) * mod_exp(&y2, &c, &p);

        // if (left == r1 && right == r2) {
        //     println!("Proven");
        // } else {
        //     println!("nono")
        // }
    }
    #[test]
    fn test_with_rand() {
        // lets pick two generators
        let a = BigUint::from(4u32);
        let b = BigUint::from(9u32);
        // set a witness value.
        let w = BigUint::from(6u32);
        // module
        let p = BigUint::from(23u32);
        // order of group
        let q = BigUint::from(11u32);

        let y1 = mod_exp(&a, &w, &p);
        let y2 = mod_exp(&b, &w, &p);

        assert_eq!(y1, BigUint::from(2u32));
        assert_eq!(y2, BigUint::from(3u32));
        // generate random k
        // let mut rng = rand::thread_rng();
        // let k = rng.gen_biguint(32);
        // let k = BigUint::from(7u32);
        let k = gen_rand(&q);

        let r1 = mod_exp(&a, &k, &p);
        let r2 = mod_exp(&b, &k, &p);

        // assert_eq!(r1, BigUint::from(8u32)); k is diffferent
        // assert_eq!(r2, BigUint::from(4u32));
        // let c = BigUint::from(4u32);
        let c = gen_rand(&q);
        // compute response
        let s = proof(&k, &c, &w, &q);
        // assert_eq!(s, BigUint::from(5u32)); //response is different now
        // lets verify
        let verif = verify(&a, &b, &y1, &y2, &r1, &r2, &c, &s, &p);
        assert!(verif);
        // let left = mod_exp(&a, &s, &p) * mod_exp(&y1, &c, &p);
        // let right = mod_exp(&b, &s, &p) * mod_exp(&y2, &c, &p);

        // if (left == r1 && right == r2) {
        //     println!("Proven");
        // } else {
        //     println!("nono")
        // }
    }
}
