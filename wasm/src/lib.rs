use fips203::ml_kem_512;
// Could also be ml_kem_768 or ml_kem_1024.
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
use rand_chacha::rand_core::SeedableRng;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn run(seed: &str) -> String {
    let seed = seed.parse();
    if seed.is_err() { return "Unable to parse number".to_string(); };
    let seed = seed.unwrap();

    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);

    // Alice runs `key_gen()` and then serializes the encaps key `ek` for Bob (to bytes).
    let (alice_ek, alice_dk) = ml_kem_512::KG::try_keygen_with_rng_vt(&mut rng).expect("keygen failed");
    let alice_ek_bytes = alice_ek.into_bytes();

    // Alice sends the encaps key `ek_bytes` to Bob.
    let bob_ek_bytes = alice_ek_bytes;

    // Bob deserializes the encaps `ek_bytes` and then runs `encaps() to get the shared
    // secret `ssk` and ciphertext `ct`. He serializes the ciphertext `ct` for Alice (to bytes).
    let bob_ek = ml_kem_512::EncapsKey::try_from_bytes(bob_ek_bytes).expect("ek deser failed");
    let (bob_ssk, bob_ct) = bob_ek.try_encaps_with_rng_vt(&mut rng).expect("encaps failed");
    let bob_ct_bytes = bob_ct.into_bytes();

    // Bob sends the ciphertext `ct_bytes` to Alice
    let alice_ct_bytes = bob_ct_bytes;

    // Alice deserializes the ciphertext `ct` and runs `decaps()` with her decaps key
    let alice_ct = ml_kem_512::CipherText::try_from_bytes(alice_ct_bytes).expect("ct deser failed");
    let alice_ssk = alice_dk.try_decaps_vt(&alice_ct).expect("decaps failed");

    // Alice and Bob will now have the same secret key
    assert_eq!(bob_ssk.into_bytes(), alice_ssk.clone().into_bytes(), "shared secret not identical");

    let ek_hex = hex::encode(&bob_ek_bytes);
    let ct_hex = hex::encode(&bob_ct_bytes);
    let dk_hex = hex::encode(alice_dk.into_bytes());
    let ssk_hex = hex::encode(alice_ssk.into_bytes());

    let s0 = format!("The seed used to generate the keys is: {}\n\n", seed);
    let s1 = format!("The generated encaps key is: {}\n", ek_hex);
    let s2 = format!("The generated decaps key is: {}\n\n", dk_hex);
    let s3 = format!("The generated ciphertext is: {}\n", ct_hex);
    let s4 = format!("The shared secret is: {}\n", ssk_hex);
    let s5 = "Alice and Bob have an identical shared secret.";  // because the above assert! passed

    (s0 + &s1 + &s2 + &s3 + &s4 + &s5).into()
}
