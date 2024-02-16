#![no_main]

use fips203::ml_kem_512;
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
use libfuzzer_sys::fuzz_target;
use rand_core::{CryptoRng, RngCore};

const RND_SIZE: usize = 32;


struct TestRng {
    data: Vec<Vec<u8>>,
}

impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 { unimplemented!() }

    fn next_u64(&mut self) -> u64 { unimplemented!() }

    fn fill_bytes(&mut self, out: &mut [u8]) {
        let x = self.data.pop().expect("TestRng problem");
        out.copy_from_slice(&x)
    }

    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(out);
        Ok(()) // panic on probs is OK
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
    let mut start = 0;
    rng.push(&data[start..start+RND_SIZE]);
    start += RND_SIZE;
    rng.push(&data[start..start+RND_SIZE]);
    start += RND_SIZE;
    let keypair = ml_kem_512::KG::try_keygen_with_rng_vt(&mut rng);  // consumes 2 rng values
    let (ek1, dk1) = keypair.unwrap();  // only rng can fail, which it won't

    let ek2_bytes = &data[start..start+ml_kem_512::EK_LEN];
    start += ml_kem_512::EK_LEN;
    let ek2 = ml_kem_512::EncapsKey::try_from_bytes(ek2_bytes.try_into().unwrap());

    rng.push(&data[start..start+RND_SIZE]);
    start += RND_SIZE;
    rng.push(&data[start..start+RND_SIZE]);
    start += RND_SIZE;

    if ek2.is_ok() {
        let _res = ek2.unwrap().try_encaps_with_rng_vt(&mut rng);
    }
    let _res = ek1.try_encaps_with_rng_vt(&mut rng);


    let dk2_bytes = &data[start..start+ml_kem_512::DK_LEN];
    start += ml_kem_512::DK_LEN;
    let dk2 = ml_kem_512::DecapsKey::try_from_bytes(dk2_bytes.try_into().unwrap());

    let ct_bytes = &data[start..start+ml_kem_512::CT_LEN];
    start += ml_kem_512::CT_LEN;
    let ct = ml_kem_512::CipherText::try_from_bytes(ct_bytes.try_into().unwrap()).unwrap();  // always good

    if dk2.is_ok() {
        let _res = dk2.unwrap().try_decaps_vt(&ct);
    }
    let _res = dk1.try_decaps_vt(&ct);

    assert_eq!(start, data.len());  // this doesn't appear to trigger (even when wrong)


});
