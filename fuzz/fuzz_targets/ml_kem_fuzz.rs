#![no_main]
use fips203::{
    ml_kem_1024, ml_kem_512, ml_kem_768,
    traits::{Decaps, Encaps, KeyGen, SerDes},
    RngCore, CryptoRng
};
use libfuzzer_sys::fuzz_target;

// Wrapper struct to help organize the fuzz input
#[derive(arbitrary::Arbitrary, Debug)]
struct FuzzInput {
    d: [u8; 32],
    z: [u8; 32],
    e: [u8; 32],
    ek_xor: [u8; ml_kem_1024::EK_LEN],
    dk_xor: [u8; ml_kem_1024::DK_LEN],
    ct_xor: [u8; ml_kem_1024::CT_LEN],
    sk_xor: [u8; fips203::SSK_LEN],
}

fuzz_target!(|input: FuzzInput| {
    // Generate keypair deterministically from fuzzer input
    let (ek1a, dk1a) = ml_kem_512::KG::keygen_from_seed(input.d, input.z);
    let (ek2a, dk2a) = ml_kem_768::KG::keygen_from_seed(input.d, input.z);
    let (ek3a, dk3a) = ml_kem_1024::KG::keygen_from_seed(input.d, input.z);

    // Serialize and deserialize encapsulation key; XOR
    let mut ek1a_bytes = ek1a.into_bytes();
    ek1a_bytes.iter_mut().zip(input.ek_xor.iter()).for_each(|(x1, x2)| *x1 ^= x2);
    let ek1b = match ml_kem_512::EncapsKey::try_from_bytes(ek1a_bytes) {
        Ok(k) => k,
        Err(_) => return,
    };

    let mut ek2a_bytes = ek2a.into_bytes();
    ek2a_bytes.iter_mut().zip(input.ek_xor.iter()).for_each(|(x1, x2)| *x1 ^= x2);
    let ek2b = match ml_kem_768::EncapsKey::try_from_bytes(ek2a_bytes) {
        Ok(k) => k,
        Err(_) => return,
    };

    let mut ek3a_bytes = ek3a.into_bytes();
    ek3a_bytes.iter_mut().zip(input.ek_xor.iter()).for_each(|(x1, x2)| *x1 ^= x2);
    let ek3b = match ml_kem_1024::EncapsKey::try_from_bytes(ek3a_bytes) {
        Ok(k) => k,
        Err(_) => return,
    };

    // Serialize and deserialize decapsulation key
    let mut dk1a_bytes = dk1a.into_bytes();
    dk1a_bytes.iter_mut().zip(input.dk_xor.iter()).for_each(|(x1, x2)| *x1 ^= x2);
    let dk1b = match ml_kem_512::DecapsKey::try_from_bytes(dk1a_bytes) {
        Ok(k) => k,
        Err(_) => return,
    };

    let mut dk2a_bytes = dk2a.into_bytes();
    dk2a_bytes.iter_mut().zip(input.dk_xor.iter()).for_each(|(x1, x2)| *x1 ^= x2);
    let dk2b = match ml_kem_768::DecapsKey::try_from_bytes(dk2a_bytes) {
        Ok(k) => k,
        Err(_) => return,
    };

    let mut dk3a_bytes = dk3a.into_bytes();
    dk3a_bytes.iter_mut().zip(input.dk_xor.iter()).for_each(|(x1, x2)| *x1 ^= x2);
    let dk3b = match ml_kem_1024::DecapsKey::try_from_bytes(dk3a_bytes) {
        Ok(k) => k,
        Err(_) => return,
    };


    let (ss1, ct1) = ek1b.encaps_from_seed(&input.e);
    let (ss2, ct2) = ek2b.encaps_from_seed(&input.e);
    let (ss3, ct3) = ek3b.encaps_from_seed(&input.e);

    // Serialize and deserialize ciphertext
    let mut ct1a_bytes = ct1.into_bytes();
    ct1a_bytes.iter_mut().zip(input.ct_xor.iter()).for_each(|(x1, x2)| *x1 ^= x2);
    let ct1b = match ml_kem_512::CipherText::try_from_bytes(ct1a_bytes) {
        Ok(c) => c,
        Err(_) => return,
    };

    let mut ct2a_bytes = ct2.into_bytes();
    ct2a_bytes.iter_mut().zip(input.ct_xor.iter()).for_each(|(x1, x2)| *x1 ^= x2);
    let ct2b = match ml_kem_768::CipherText::try_from_bytes(ct2a_bytes) {
        Ok(c) => c,
        Err(_) => return,
    };

    let mut ct3a_bytes = ct3.into_bytes();
    ct3a_bytes.iter_mut().zip(input.ct_xor.iter()).for_each(|(x1, x2)| *x1 ^= x2);
    let ct3b = match ml_kem_1024::CipherText::try_from_bytes(ct3a_bytes) {
        Ok(c) => c,
        Err(_) => return,
    };

    // Serialize and deserialize shared secret
    let mut sk1a_bytes = ss1.into_bytes();
    sk1a_bytes.iter_mut().zip(input.sk_xor.iter()).for_each(|(x1, x2)| *x1 ^= x2);
    let _sk1b = match fips203::SharedSecretKey::try_from_bytes(sk1a_bytes) {
        Ok(s) => s,
        Err(_) => return,
    };

    let mut sk2a_bytes = ss2.into_bytes();
    sk2a_bytes.iter_mut().zip(input.sk_xor.iter()).for_each(|(x1, x2)| *x1 ^= x2);
    let _sk2b = match fips203::SharedSecretKey::try_from_bytes(sk2a_bytes) {
        Ok(s) => s,
        Err(_) => return,
    };

    let mut sk3a_bytes = ss3.into_bytes();
    sk3a_bytes.iter_mut().zip(input.sk_xor.iter()).for_each(|(x1, x2)| *x1 ^= x2);
    let _sk3b = match fips203::SharedSecretKey::try_from_bytes(sk3a_bytes) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Test decapsulation
    let _ss2a = match dk1b.try_decaps(&ct1b) {
        Ok(s) => s,
        Err(_) => return,
    };
    let _ss2b = match dk2b.try_decaps(&ct2b) {
        Ok(s) => s,
        Err(_) => return,
    };
    let _ss2c = match dk3b.try_decaps(&ct3b) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Verify shared secrets match
    //assert_eq!(ss1, ss2);

    // Test keypair validation

    // ----- CUSTOM RNG TO REPLAY VALUES -----
    struct TestRng {
        data: Vec<Vec<u8>>,
    }

    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 { unimplemented!() }

        fn next_u64(&mut self) -> u64 { unimplemented!() }

        fn fill_bytes(&mut self, out: &mut [u8]) {
            let x = self.data.pop().expect("test rng problem");
            out.copy_from_slice(&x)
        }

        fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(out);
            Ok(())
        }
    }

    impl CryptoRng for TestRng {}

    impl TestRng {
        fn new() -> Self { TestRng { data: Vec::new() } }

        fn push(&mut self, new_data: &[u8]) {
            let x = new_data.to_vec();
            self.data.push(x);
        }
    }


    let mut rng = TestRng::new();
    rng.push(&input.d);
    let mut z = input.z;
    z.iter_mut().zip(input.ct_xor[0..1].iter()).for_each(|(x1, x2)| *x1 ^= x2);
    rng.push(&z);
    let (ek1a, dk1a) = match ml_kem_512::KG::try_keygen_with_rng(&mut rng) {
        Ok(k) => k,
        Err(_) => return,
    };
    rng.push(&input.d);
    rng.push(&z);
    ml_kem_512::KG::validate_keypair_with_rng_vartime(
        &mut rng,
        &ek1a.into_bytes(),
        &dk1a.into_bytes(),
    );

    rng.push(&input.d);
    rng.push(&z);
    let (ek2a, dk2a) = match ml_kem_768::KG::try_keygen_with_rng(&mut rng) {
        Ok(k) => k,
        Err(_) => return,
    };
    rng.push(&input.d);
    rng.push(&z);
    ml_kem_768::KG::validate_keypair_with_rng_vartime(
        &mut rng,
        &ek2a.into_bytes(),
        &dk2a.into_bytes(),
    );

    let (ek3a, dk3a) = match ml_kem_1024::KG::try_keygen() {
        Ok(k) => k,
        Err(_) => return,
    };
    let _ = ek3a.try_encaps();
    rng.push(&input.d);
    rng.push(&z);
    ml_kem_1024::KG::validate_keypair_with_rng_vartime(
        &mut rng,
        &ek3a.into_bytes(),
        &dk3a.into_bytes(),
    );
});
