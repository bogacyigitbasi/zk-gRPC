use hex;
/// ChaumPedersen pick two generators from group G
/// a, b and compute y1= a^x mod p and y2 = b^x mod p where x is witness
/// pick a random value k and compute R1= a^k and R2 = b^k mod p (note that these values known by the both parties)
/// verifier picks a random challenge c and sends it to prover
/// response = s = k - c*x mod q (order?) is the proof
/// verifier will verify if R1 == a^s . y1^c and if R2 == b^s. y2^c
use num_bigint::{BigUint, RandBigInt};
use rand;
// refactor and add static & global params in the struct for brevity
#[derive(Clone)]
pub struct ZKP {
    p: BigUint, //prime
    q: BigUint, //order of the function
    a: BigUint,
    b: BigUint, // generators
}

impl ZKP {
    pub fn init(a: &BigUint, b: &BigUint, p: &BigUint, q: &BigUint) -> ZKP {
        let zkp = ZKP {
            a: a.clone(),
            b: b.clone(),
            p: p.clone(),
            q: q.clone(),
        };
        zkp
    }
    // calculate the g^x mod p
    // using the default modpow function in BigInt
    pub fn mod_exp(num: &BigUint, exp: &BigUint, p: &BigUint) -> BigUint {
        num.modpow(exp, p)
    }

    /// in chaum_pedersen we have response s = k - c*x mod p
    /// where k is a random number, x witness and c is the challenge given by verifier
    ///
    pub fn proof(&self, k: &BigUint, c: &BigUint, x: &BigUint) -> BigUint {
        if *k >= c * x {
            return (k - c * x).modpow(&BigUint::from(1u32), &self.q);
        } else {
            return &self.q - (c * x - k).modpow(&BigUint::from(1u32), &self.q); // k < cx
        }
    }

    /// verifier will verify if R1 == a^s . y1^c mod p and if R2 == b^s. y2^c mod p
    pub fn verify(
        &self,
        y1: &BigUint, //public generated using x
        y2: &BigUint, //public generated using x
        r1: &BigUint, //public generated using k
        r2: &BigUint, //public generated using k
        c: &BigUint,  // challenge
        s: &BigUint,  // response
    ) -> bool {
        let left = *r1
            == Self::mod_exp(
                &(Self::mod_exp(&self.a, s, &self.p) * Self::mod_exp(y1, c, &self.p)),
                &BigUint::from(1u32),
                &self.p,
            );
        let right = *r2
            == Self::mod_exp(
                &(Self::mod_exp(&self.b, s, &self.p) * Self::mod_exp(y2, c, &self.p)),
                &BigUint::from(1u32),
                &self.p,
            );
        left && right
    }
    /// generate random binguint
    pub fn gen_rand(max: &BigUint) -> BigUint {
        let mut rng = rand::thread_rng();
        rng.gen_biguint_below(max)
    }
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

        let y1 = ZKP::mod_exp(&a, &w, &p);
        let y2 = ZKP::mod_exp(&b, &w, &p);

        let zkp = ZKP::init(&a, &b, &p, &q);

        assert_eq!(y1, BigUint::from(2u32));
        assert_eq!(y2, BigUint::from(3u32));
        // generate random k
        // let mut rng = rand::thread_rng();
        // let k = rng.gen_biguint(32);
        let k = BigUint::from(7u32);
        let r1 = ZKP::mod_exp(&a, &k, &p);
        let r2 = ZKP::mod_exp(&b, &k, &p);

        assert_eq!(r1, BigUint::from(8u32));
        assert_eq!(r2, BigUint::from(4u32));
        let c = BigUint::from(4u32);

        // compute response
        let s = zkp.proof(&k, &c, &w);
        assert_eq!(s, BigUint::from(5u32));
        // lets verify
        let verif = zkp.verify(&y1, &y2, &r1, &r2, &c, &s);
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
        let zkp = ZKP::init(&a, &b, &p, &q);
        let y1 = ZKP::mod_exp(&a, &w, &p);
        let y2 = ZKP::mod_exp(&b, &w, &p);

        assert_eq!(y1, BigUint::from(2u32));
        assert_eq!(y2, BigUint::from(3u32));
        // generate random k
        // let mut rng = rand::thread_rng();
        // let k = rng.gen_biguint(32);
        // let k = BigUint::from(7u32);
        let k = ZKP::gen_rand(&q);

        let r1 = ZKP::mod_exp(&a, &k, &p);
        let r2 = ZKP::mod_exp(&b, &k, &p);

        // assert_eq!(r1, BigUint::from(8u32)); k is diffferent
        // assert_eq!(r2, BigUint::from(4u32));
        // let c = BigUint::from(4u32);
        let c = ZKP::gen_rand(&q);
        // compute response
        let s = zkp.proof(&k, &c, &w);
        // assert_eq!(s, BigUint::from(5u32)); //response is different now
        // lets verify
        let verif = zkp.verify(&y1, &y2, &r1, &r2, &c, &s);
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
    fn test_1024_bits() {
        //
        //    Reference: https://www.rfc-editor.org/rfc/rfc5114#page-15
        //
        //    The hexadecimal value of the prime is:
        //
        //    p = B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6
        //        9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0
        //        13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70
        //        98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0
        //        A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708
        //        DF1FB2BC 2E4A4371
        //
        //    The hexadecimal value of the generator is:
        //
        //    g = A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F
        //        D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213
        //        160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1
        //        909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A
        //        D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24
        //        855E6EEB 22B3B2E5
        //
        //install hex cargo add hex to convert hexadecimal to biguint
        // set a witness value.
        let w = BigUint::from(6u32);
        // modulo hex -> from bytes to big endian
        let p = BigUint::from_bytes_be(&hex::decode("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371").unwrap());
        let q = BigUint::from_bytes_be(
            &hex::decode("F518AA8781A8DF278ABA4E7D64B7CB9D49462353").unwrap(),
        );
        // lets pick two generators

        let a = BigUint::from_bytes_be(
            &hex::decode("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5").unwrap(),
        );
        let b = ZKP::gen_rand(&q);

        let zkp = ZKP::init(&a, &b, &p, &q);
        let y1 = ZKP::mod_exp(&a, &w, &p);
        let y2 = ZKP::mod_exp(&b, &w, &p);

        assert_eq!(y1, BigUint::from(2u32));
        assert_eq!(y2, BigUint::from(3u32));
        // generate random k
        // let mut rng = rand::thread_rng();
        // let k = rng.gen_biguint(32);
        // let k = BigUint::from(7u32);
        let k = ZKP::gen_rand(&q);

        let r1 = ZKP::mod_exp(&a, &k, &p);
        let r2 = ZKP::mod_exp(&b, &k, &p);

        // assert_eq!(r1, BigUint::from(8u32)); k is diffferent
        // assert_eq!(r2, BigUint::from(4u32));
        // let c = BigUint::from(4u32);
        let c = ZKP::gen_rand(&q);
        // compute response
        let s = zkp.proof(&k, &c, &w);
        // assert_eq!(s, BigUint::from(5u32)); //response is different now
        // lets verify
        let verif = zkp.verify(&y1, &y2, &r1, &r2, &c, &s);
        assert!(verif);
    }
}
