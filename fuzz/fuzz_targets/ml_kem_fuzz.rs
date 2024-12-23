#![no_main]
use fips203::{
    ml_kem_1024, ml_kem_512, ml_kem_768,
    traits::{Decaps, Encaps, KeyGen, SerDes},
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


    let (_ss1, ct1) = ek1b.encaps_from_seed(&input.e);
    let (_ss1, ct2) = ek2b.encaps_from_seed(&input.e);
    let (_ss1, ct3) = ek3b.encaps_from_seed(&input.e);

    // Test serialization/deserialization of ciphertext
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
    ml_kem_512::KG::validate_keypair_with_rng_vartime(
        &mut rand_core::OsRng,
        &ek1a_bytes,
        &dk1a_bytes,
    );

    ml_kem_768::KG::validate_keypair_with_rng_vartime(
        &mut rand_core::OsRng,
        &ek2a_bytes,
        &dk2a_bytes,
    );

    ml_kem_1024::KG::validate_keypair_with_rng_vartime(
        &mut rand_core::OsRng,
        &ek3a_bytes,
        &dk3a_bytes,
    );
});
