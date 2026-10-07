// This file runs the Wycheproof ML-KEM vectors (Apache-2.0).
//   from: https://github.com/C2SP/wycheproof/tree/3fa63dd0344abb611f1fb1d77e119938603ea230/testvectors_v1
//   files: mlkem_{512,768,1024}_{keygen_seed_test,encaps_test,test,semi_expanded_decaps_test}.json
//
// Every case in each file runs through the public API. A key, seed or ciphertext of the wrong
// length cannot be expressed with the crate's fixed-size types, so such a case is counted as
// length-only and must be marked invalid. Each test counts its cases and fails unless every one
// was handled, apart from parameter sets whose feature is off. An unknown schema, group type,
// field, result or flag fails the test. The vectors are excluded from the published crate.

use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
use hex::decode;
use rand_chacha::rand_core::SeedableRng;
use serde_json::Value;
use std::fs;

#[cfg(feature = "ml-kem-1024")]
use fips203::ml_kem_1024;
#[cfg(feature = "ml-kem-512")]
use fips203::ml_kem_512;
#[cfg(feature = "ml-kem-768")]
use fips203::ml_kem_768;


const SETS: [&str; 3] = ["512", "768", "1024"];

const KNOWN_FLAGS: [&str; 6] = [
    "IncorrectCiphertextLength",
    "IncorrectDecapsulationKeyLength",
    "InvalidDecapsulationKey",
    "MalleableCiphertext",
    "ModulusOverflow",
    "Strcmp",
];


// ----- ACCOUNTING: EVERY CASE IN A FILE IS HANDLED, OR THE TEST FAILS -----
struct Tally {
    total: usize,
    ran: usize,
    length_only: usize,
    feature_skipped: usize,
}

impl Tally {
    fn new() -> Self { Tally { total: 0, ran: 0, length_only: 0, feature_skipped: 0 } }

    fn count(&mut self, handled: bool, length_only: bool) {
        match (handled, length_only) {
            (false, _) => self.feature_skipped += 1,
            (true, true) => self.length_only += 1,
            (true, false) => self.ran += 1,
        }
    }

    fn finish(&self, which: &str) {
        println!(
            "Wycheproof {which}: ran {}, length-only {}, feature-skipped {}, of {}",
            self.ran, self.length_only, self.feature_skipped, self.total
        );
        let handled = self.ran + self.length_only + self.feature_skipped;
        assert_eq!(handled, self.total, "Wycheproof {which}: some cases were not handled");
        assert!(self.ran > 0, "Wycheproof {which}: no cases ran");
    }
}

// Runs `$run!(module)` for the parameter set named `$set` and returns true. Returns false when
// that set's feature is off, and panics on a parameter set it does not know.
macro_rules! dispatch {
    ($set:expr, $run:ident) => {
        match $set {
            #[cfg(feature = "ml-kem-512")]
            "ML-KEM-512" => {
                $run!(ml_kem_512);
                true
            }
            #[cfg(feature = "ml-kem-768")]
            "ML-KEM-768" => {
                $run!(ml_kem_768);
                true
            }
            #[cfg(feature = "ml-kem-1024")]
            "ML-KEM-1024" => {
                $run!(ml_kem_1024);
                true
            }
            #[allow(unreachable_patterns)]
            "ML-KEM-512" | "ML-KEM-768" | "ML-KEM-1024" => false,
            other => panic!("unknown parameter set {other}"),
        }
    };
}

fn load(name: &str) -> Value {
    let path = format!("./tests/wycheproof/{name}");
    let vectors = fs::read_to_string(&path).expect("Unable to read file");
    serde_json::from_str(&vectors).unwrap()
}

fn cases(group: &Value) -> &Vec<Value> { group["tests"].as_array().expect("tests") }

fn hex(v: &Value, key: &str, loc: &str) -> Vec<u8> {
    decode(v[key].as_str().unwrap_or_else(|| panic!("{loc} missing {key}"))).unwrap()
}

fn valid(test: &Value) -> bool { test["result"] == "valid" }

/// Checks the file header and every group and case, adds the file's cases to the tally, and
/// returns the groups.
fn checked_groups<'a>(
    doc: &'a Value, file: &str, schema: &str, group_type: &str, set: &str, case_fields: &[&str],
    tally: &mut Tally,
) -> &'a Vec<Value> {
    assert_eq!(doc["algorithm"], "ML-KEM", "{file}: algorithm");
    assert_eq!(doc["schema"], schema, "{file}: schema");
    let groups = doc["testGroups"].as_array().expect("testGroups");
    let count: usize = groups.iter().map(|g| cases(g).len()).sum();
    assert_eq!(Some(count as u64), doc["numberOfTests"].as_u64(), "{file}: numberOfTests");
    tally.total += count;
    for group in groups {
        for key in group.as_object().expect("group").keys() {
            let known = ["parameterSet", "source", "tests", "type"];
            assert!(known.contains(&key.as_str()), "{file}: unknown group field {key}");
        }
        assert_eq!(group["type"], group_type, "{file}: group type");
        assert_eq!(group["parameterSet"], format!("ML-KEM-{set}"), "{file}: parameterSet");
        for test in cases(group) {
            let loc = format!("{file} tcId={}", test["tcId"]);
            for key in test.as_object().expect("test").keys() {
                assert!(case_fields.contains(&key.as_str()), "{loc}: unknown field {key}");
            }
            assert!(test["result"] == "valid" || test["result"] == "invalid", "{loc}: result");
            for flag in test["flags"].as_array().into_iter().flatten() {
                let flag = flag.as_str().expect("flag");
                assert!(KNOWN_FLAGS.contains(&flag), "{loc}: unknown flag {flag}");
            }
        }
    }
    groups
}


// Seed d || z -> (ek, dk)
#[test]
fn wycheproof_keygen_seed() {
    let mut tally = Tally::new();
    for set in SETS {
        let file = format!("mlkem_{set}_keygen_seed_test.json");
        let doc = load(&file);
        let fields = ["comment", "dk", "ek", "result", "seed", "tcId"];
        let schema = "mlkem_keygen_seed_test_schema.json";
        for group in checked_groups(&doc, &file, schema, "MLKEMKeyGen", set, &fields, &mut tally) {
            for test in cases(group) {
                let loc = format!("{file} tcId={}", test["tcId"]);
                let mut length_only = false;

                macro_rules! runtest {
                    ($pc:ident) => {{
                        let seed = hex(test, "seed", &loc);
                        if seed.len() != 64 {
                            assert!(
                                !valid(test),
                                "{loc}: valid case with a {}-byte seed",
                                seed.len()
                            );
                            length_only = true;
                        } else {
                            assert!(valid(test), "{loc}: invalid case with a 64-byte seed");
                            let (ek, dk) = $pc::KG::keygen_from_seed(
                                seed[..32].try_into().unwrap(),
                                seed[32..].try_into().unwrap(),
                            );
                            assert_eq!(hex(test, "ek", &loc), ek.into_bytes(), "{loc}");
                            assert_eq!(hex(test, "dk", &loc), dk.into_bytes(), "{loc}");
                        }
                    }};
                }
                let handled = dispatch!(group["parameterSet"].as_str().unwrap(), runtest);
                tally.count(handled, length_only);
            }
        }
    }
    tally.finish("keygen_seed");
}


// ek, m -> (c, K); an invalid ek must be rejected by EncapsKey::try_from_bytes (FIPS 203 §7.2)
#[test]
fn wycheproof_encaps() {
    let mut tally = Tally::new();
    for set in SETS {
        let file = format!("mlkem_{set}_encaps_test.json");
        let doc = load(&file);
        let fields = ["K", "c", "comment", "ek", "flags", "m", "result", "tcId"];
        let schema = "mlkem_encaps_test_schema.json";
        for group in
            checked_groups(&doc, &file, schema, "MLKEMEncapsTest", set, &fields, &mut tally)
        {
            for test in cases(group) {
                let loc = format!("{file} tcId={} ({})", test["tcId"], test["comment"]);
                let mut length_only = false;

                macro_rules! runtest {
                    ($pc:ident) => {{
                        let ek = hex(test, "ek", &loc);
                        if ek.len() != $pc::EK_LEN {
                            assert!(!valid(test), "{loc}: valid case with a {}-byte ek", ek.len());
                            length_only = true;
                        } else {
                            match $pc::EncapsKey::try_from_bytes(ek.try_into().unwrap()) {
                                Err(_) => assert!(!valid(test), "{loc}: valid ek rejected"),
                                Ok(ek) => {
                                    assert!(valid(test), "{loc}: invalid ek accepted");
                                    let m = hex(test, "m", &loc).try_into().expect("32-byte m");
                                    let (k, c) = ek.encaps_from_seed(&m);
                                    assert_eq!(hex(test, "c", &loc), c.into_bytes(), "{loc}");
                                    assert_eq!(hex(test, "K", &loc), k.into_bytes(), "{loc}");
                                }
                            }
                        }
                    }};
                }
                let handled = dispatch!(group["parameterSet"].as_str().unwrap(), runtest);
                tally.count(handled, length_only);
            }
        }
    }
    tally.finish("encaps");
}


// Seed d || z and c -> K, including implicit rejection of modified ciphertexts
#[test]
fn wycheproof_decaps_from_seed() {
    let mut tally = Tally::new();
    for set in SETS {
        let file = format!("mlkem_{set}_test.json");
        let doc = load(&file);
        let fields = ["K", "c", "comment", "ek", "flags", "result", "seed", "tcId"];
        let schema = "mlkem_test_schema.json";
        for group in checked_groups(&doc, &file, schema, "MLKEMTest", set, &fields, &mut tally) {
            for test in cases(group) {
                let loc = format!("{file} tcId={} ({})", test["tcId"], test["comment"]);
                let mut length_only = false;

                macro_rules! runtest {
                    ($pc:ident) => {{
                        let seed = hex(test, "seed", &loc);
                        let c = hex(test, "c", &loc);
                        if seed.len() != 64 || c.len() != $pc::CT_LEN {
                            assert!(!valid(test), "{loc}: valid case with a wrong length");
                            length_only = true;
                        } else {
                            assert!(valid(test), "{loc}: invalid case with correct lengths");
                            let (ek, dk) = $pc::KG::keygen_from_seed(
                                seed[..32].try_into().unwrap(),
                                seed[32..].try_into().unwrap(),
                            );
                            assert_eq!(hex(test, "ek", &loc), ek.into_bytes(), "{loc}");
                            let ct =
                                $pc::CipherText::try_from_bytes(c.try_into().unwrap()).unwrap();
                            let k = dk.try_decaps(&ct).unwrap();
                            assert_eq!(hex(test, "K", &loc), k.into_bytes(), "{loc}");
                        }
                    }};
                }
                let handled = dispatch!(group["parameterSet"].as_str().unwrap(), runtest);
                tally.count(handled, length_only);
            }
        }
    }
    tally.finish("decaps_from_seed");
}


// Expanded dk and c -> K; an invalid dk must be rejected by DecapsKey::try_from_bytes (FIPS 203
// §7.3), and validate_keypair_with_rng_vartime must agree with the expected result
#[test]
fn wycheproof_semi_expanded_decaps() {
    let mut tally = Tally::new();
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(123);
    for set in SETS {
        let file = format!("mlkem_{set}_semi_expanded_decaps_test.json");
        let doc = load(&file);
        let fields = ["K", "c", "comment", "dk", "ek", "flags", "result", "tcId"];
        let schema = "mlkem_semi_expanded_decaps_test_schema.json";
        let gtype = "MLKEMDecapsValidationTest";
        for group in checked_groups(&doc, &file, schema, gtype, set, &fields, &mut tally) {
            for test in cases(group) {
                let loc = format!("{file} tcId={} ({})", test["tcId"], test["comment"]);
                let mut length_only = false;

                macro_rules! runtest {
                    ($pc:ident) => {{
                        let dk = hex(test, "dk", &loc);
                        let c = hex(test, "c", &loc);
                        if dk.len() != $pc::DK_LEN || c.len() != $pc::CT_LEN {
                            assert!(!valid(test), "{loc}: valid case with a wrong length");
                            length_only = true;
                        } else {
                            let ek = hex(test, "ek", &loc);
                            if ek.len() == $pc::EK_LEN {
                                let pair_ok = $pc::KG::validate_keypair_with_rng_vartime(
                                    &mut rng,
                                    &ek.try_into().unwrap(),
                                    &dk.clone().try_into().unwrap(),
                                );
                                assert_eq!(valid(test), pair_ok, "{loc}: validate_keypair");
                            }
                            match $pc::DecapsKey::try_from_bytes(dk.try_into().unwrap()) {
                                Err(_) => assert!(!valid(test), "{loc}: valid dk rejected"),
                                Ok(dk) => {
                                    assert!(valid(test), "{loc}: invalid dk accepted");
                                    let ct = $pc::CipherText::try_from_bytes(c.try_into().unwrap())
                                        .unwrap();
                                    let k = dk.try_decaps(&ct).unwrap();
                                    assert_eq!(hex(test, "K", &loc), k.into_bytes(), "{loc}");
                                }
                            }
                        }
                    }};
                }
                let handled = dispatch!(group["parameterSet"].as_str().unwrap(), runtest);
                tally.count(handled, length_only);
            }
        }
    }
    tally.finish("semi_expanded_decaps");
}
