#![no_main]

use fips203::ml_kem_512;
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
use libfuzzer_sys::fuzz_target;
use rand_core::{CryptoRng, RngCore};

const RND_SIZE: usize = 32;

// This is a 'fake' random number generator, that will regurgitate fuzz input
struct TestRng {
    data: Vec<Vec<u8>>,
}

impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 { unimplemented!() }

    fn next_u64(&mut self) -> u64 { unimplemented!() }

    fn fill_bytes(&mut self, _out: &mut [u8]) { unimplemented!() }

    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand_core::Error> {
        let x = self.data.pop().expect("TestRng problem");
        out.copy_from_slice(&x);
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


fuzz_target!(|data: [u8; 3328]| {
    let mut rng = TestRng::new();
    let mut start = 0; // Bump this forward as we pull out fuzz input

    // Load up the rng for keygen (2) and encaps (1)
    rng.push(&data[start..start + RND_SIZE]);
    start += RND_SIZE;
    rng.push(&data[start..start + RND_SIZE]);
    start += RND_SIZE;
    rng.push(&data[start..start + RND_SIZE]);
    start += RND_SIZE;

    // Fuzz input -> `try_keygen_with_rng_vt()` and `try_encaps_with_rng_vt()` via rng values
    let (ek1, dk1) = ml_kem_512::KG::try_keygen_with_rng_vt(&mut rng).unwrap(); // consumes 2 rng values
    let ct1 = ek1.try_encaps_with_rng_vt(&mut rng).unwrap().1; // consumes 1 rng value
    let ek1_bytes = ek1.clone().into_bytes();
    let dk1_bytes = dk1.clone().into_bytes();
    let ct1_bytes = ct1.clone().into_bytes();

    // Extract candidate (xor) bytes for EK deserialization
    let mut ek2_bytes = [0u8; ml_kem_512::EK_LEN];
    ek2_bytes.copy_from_slice(&data[start..start + ml_kem_512::EK_LEN]);
    start += ml_kem_512::EK_LEN;
    for i in 0..ml_kem_512::EK_LEN {
        ek2_bytes[i] = ek2_bytes[i] ^ ek1_bytes[i];
    }

    // Fuzz input -> `EncapsKey::try_from_bytes()`
    let ek2 = ml_kem_512::EncapsKey::try_from_bytes(ek2_bytes.try_into().unwrap());

    // Load up the rng for an encaps
    rng.push(&data[start..start + RND_SIZE]);
    start += RND_SIZE;

    // If fuzz input deserialized into an acceptable ek, then run encaps
    if ek2.is_ok() {
        // Fuzz input -> `EncapsKey::try_encaps_with_rng_vt()`
        let _res = ek2.unwrap().try_encaps_with_rng_vt(&mut rng); // consumes 1 rng value
    }

    // Extract candidate (xor) bytes for DK deserialization
    let mut dk2_bytes = [0u8; ml_kem_512::DK_LEN];
    dk2_bytes.copy_from_slice(&data[start..start + ml_kem_512::DK_LEN]);
    start += ml_kem_512::DK_LEN;
    for i in 0..ml_kem_512::DK_LEN {
        dk2_bytes[i] = dk2_bytes[i] ^ dk1_bytes[i];
    }

    // Fuzz input -> `DecapsKey::try_from_bytes()`
    let dk2 = ml_kem_512::DecapsKey::try_from_bytes(dk2_bytes.try_into().unwrap());

    // Fuzz input -> `KG::validate_keypair_vt()`
    let _ok = ml_kem_512::KG::validate_keypair_vt(
        &ek2_bytes.try_into().unwrap(),
        &dk2_bytes.try_into().unwrap(),
    );

    // Extract candidate (xor) bytes for CT deserialization
    let mut ct2_bytes = [0u8; ml_kem_512::CT_LEN];
    ct2_bytes.copy_from_slice(&data[start..start + ml_kem_512::CT_LEN]);
    start += ml_kem_512::CT_LEN;
    for i in 0..ml_kem_512::CT_LEN {
        ct2_bytes[i] = ct2_bytes[i] ^ ct1_bytes[i];
    }

    // Fuzz input -> `CipherText::try_from_bytes()`
    let ct2 = ml_kem_512::CipherText::try_from_bytes(ct2_bytes.try_into().unwrap()).unwrap(); // always good

    // Fuzz input -> `DecapsKey::try_decaps_vt()`
    let _res = dk1.try_decaps_vt(&ct2);

    if dk2.is_ok() {
        // Fuzz input -> `DecapsKey::try_decaps_vt()`
        let _res = dk2.unwrap().try_decaps_vt(&ct2);
    }

    assert_eq!(start, data.len()); // this doesn't appear to trigger (even when wrong)
});
