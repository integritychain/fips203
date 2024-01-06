#![no_main]
// rustup default nightly
// head -c 3200 </dev/urandom > seed1
// cargo fuzz run fuzz_all -j 4

use fips203::ml_kem_512;
use fips203::traits::{Decaps, Encaps, SerDes};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: [u8; 1632+800+768]| {  // dk_len + ek+len + ct_len = 3200

    let ek = ml_kem_512::EncapsKey::try_from_bytes(data[0..800].try_into().unwrap()).unwrap();
    let dk = ml_kem_512::DecapsKey::try_from_bytes(data[800..800+1632].try_into().unwrap()).unwrap();
    let ct = ml_kem_512::CipherText::try_from_bytes(data[800+1632..800+1632+768].try_into().unwrap()).unwrap();

    let _result = ek.try_encaps_vt();
    let _result = dk.try_decaps_vt(&ct);
});
