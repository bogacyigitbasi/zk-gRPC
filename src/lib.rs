use std::collections;

use hex;
/// ChaumPedersen pick two generators from group G
/// a, b and compute y1= a^x mod p and y2 = b^x mod p where x is witness
/// pick a random value k and compute R1= a^k and R2 = b^k mod p (note that these values known by the both parties)
/// verifier picks a random challenge c and sends it to prover
/// response = s = k - c*x mod q (order?) is the proof
/// verifier will verify if R1 == a^s . y1^c and if R2 == b^s. y2^c
use num_bigint::{BigUint, RandBigInt};
use rand::{self, random, Rng};
// refactor and add static & global params in the struct for brevity
#[derive(Clone)]
pub struct ZKP {
    a: BigUint,
    b: BigUint, // generators
    p: BigUint, //prime
    q: BigUint, //order of the function
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
                &(Self::mod_exp(&self.a, &s, &self.p) * Self::mod_exp(y1, &c, &self.p)),
                &BigUint::from(1u32),
                &self.p,
            );
        let right = *r2
            == Self::mod_exp(
                &(Self::mod_exp(&self.b, &s, &self.p) * Self::mod_exp(y2, &c, &self.p)),
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

    pub fn get_constants() -> (BigUint, BigUint, BigUint, BigUint) {
        let p = BigUint::from_bytes_be(&hex::decode("AD107E1E9123A9D0D660FAA79559C51FA20D64E5683B9FD1B54B1597B61D0A75E6FA141DF95A56DBAF9A3C407BA1DF15EB3D688A309C180E1DE6B85A1274A0A66D3F8152AD6AC2129037C9EDEFDA4DF8D91E8FEF55B7394B7AD5B7D0B6C12207C9F98D11ED34DBF6C6BA0B2C8BBC27BE6A00E0A0B9C49708B3BF8A317091883681286130BC8985DB1602E714415D9330278273C7DE31EFDC7310F7121FD5A07415987D9ADC0A486DCDF93ACC44328387315D75E198C641A480CD86A1B9E587E8BE60E69CC928B2B9C52172E413042E9B23F10B0E16E79763C9B53DCF4BA80A29E3FB73C16B8E75B97EF363E2FFA31F71CF9DE5384E71B81C0AC4DFFE0C10E64F").unwrap());
        let q = BigUint::from_bytes_be(
            &hex::decode("801C0D34C58D93FE997177101F80535A4738CEBCBF389A99B36371EB").unwrap(),
        );
        // lets pick two generators

        let a = BigUint::from_bytes_be(
            &hex::decode("AC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF74866A08CFE4FFE3A6824A4E10B9A6F0DD921F01A70C4AFAAB739D7700C29F52C57DB17C620A8652BE5E9001A8D66AD7C17669101999024AF4D027275AC1348BB8A762D0521BC98AE247150422EA1ED409939D54DA7460CDB5F6C6B250717CBEF180EB34118E98D119529A45D6F834566E3025E316A330EFBB77A86F0C1AB15B051AE3D428C8F8ACB70A8137150B8EEB10E183EDD19963DDD9E263E4770589EF6AA21E7F5F2FF381B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269EDFE72FE9B6AA4BD7B5A0F1C71CFFF4C19C418E1F6EC017981BC087F2A7065B384B890D3191F2BFA").unwrap(),
        );

        // let b = ZKP::gen_rand(&q);
        let b = BigUint::from_bytes_be(
            &hex::decode("AC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF74866A08CFE4FFE3A6824A4E10B9A6F0DD921F01A70C4AFAAB739D7700C29F52C57DB17C620A8652BE5E9001A8D66AD7C17669101999024AF4D027275AC1348BB8A762D0521BC98AE247150422EA1ED409939D54DA7460CDB5F6C6B250717CBEF180EB34118E98D119529A45D6F834566E3025E316A330EFBB77A86F0C1AB15B051AE3D428C8F8ACB70A8137150B8EEB10E183EDD19963DDD9E263E4770589EF6AA21E7F5F2FF381B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269EDFE72FE9B6AA4BD7B5A0F1C71CFFF4C19C418E1F6EC017981BC087F2A7065B384B890D3191F2BFA").unwrap(),
        );
        return (a, b, p, q);
    }
    // directly from docs
    pub fn gen_rand_string(size: usize) -> String {
        rand::thread_rng()
            .sample_iter(rand::distributions::Alphanumeric)
            .take(size)
            .map(char::from)
            .collect()
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
        let q = BigUint::from(11u32);
        // lets pick two generators
        let a = BigUint::from(4u32);
        let b = BigUint::from(9u32);
        // set a witness value.
        let w = BigUint::from(6u32);
        // module
        let p = BigUint::from(23u32);
        // order of group
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
        //install hex cargo add hex to convert hexadecimal to biguint

        // modulo hex -> from bytes to big endian
        // let p = BigUint::from_bytes_be(&hex::decode("AD107E1E9123A9D0D660FAA79559C51FA20D64E5683B9FD1B54B1597B61D0A75E6FA141DF95A56DBAF9A3C407BA1DF15EB3D688A309C180E1DE6B85A1274A0A66D3F8152AD6AC2129037C9EDEFDA4DF8D91E8FEF55B7394B7AD5B7D0B6C12207C9F98D11ED34DBF6C6BA0B2C8BBC27BE6A00E0A0B9C49708B3BF8A317091883681286130BC8985DB1602E714415D9330278273C7DE31EFDC7310F7121FD5A07415987D9ADC0A486DCDF93ACC44328387315D75E198C641A480CD86A1B9E587E8BE60E69CC928B2B9C52172E413042E9B23F10B0E16E79763C9B53DCF4BA80A29E3FB73C16B8E75B97EF363E2FFA31F71CF9DE5384E71B81C0AC4DFFE0C10E64F").unwrap());
        // let q = BigUint::from_bytes_be(
        //     &hex::decode("801C0D34C58D93FE997177101F80535A4738CEBCBF389A99B36371EB").unwrap(),
        // );
        // // lets pick two generators

        // let a = BigUint::from_bytes_be(
        //     &hex::decode("AC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF74866A08CFE4FFE3A6824A4E10B9A6F0DD921F01A70C4AFAAB739D7700C29F52C57DB17C620A8652BE5E9001A8D66AD7C17669101999024AF4D027275AC1348BB8A762D0521BC98AE247150422EA1ED409939D54DA7460CDB5F6C6B250717CBEF180EB34118E98D119529A45D6F834566E3025E316A330EFBB77A86F0C1AB15B051AE3D428C8F8ACB70A8137150B8EEB10E183EDD19963DDD9E263E4770589EF6AA21E7F5F2FF381B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269EDFE72FE9B6AA4BD7B5A0F1C71CFFF4C19C418E1F6EC017981BC087F2A7065B384B890D3191F2BFA").unwrap(),
        // );
        // let b = ZKP::gen_rand(&q);

        let (p, q, a, b) = ZKP::get_constants();

        // set a witness value.
        let w = ZKP::gen_rand(&q);

        let zkp = ZKP::init(&a, &b, &p, &q);
        let y1 = ZKP::mod_exp(&a, &w, &p);
        let y2 = ZKP::mod_exp(&b, &w, &p);

        // assert_eq!(y1, BigUint::from(2u32));
        // assert_eq!(y2, BigUint::from(3u32));
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
