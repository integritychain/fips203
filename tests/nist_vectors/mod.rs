// This file implements the NIST ACVP vectors.
//   from: https://github.com/usnistgov/ACVP-Server/blob/ad33b3d9504491767f1aa76382464f3b3fa2359e/gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json
//   from: https://github.com/usnistgov/ACVP-Server/blob/ad33b3d9504491767f1aa76382464f3b3fa2359e/gen-val/json-files/ML-KEM-encapDecap-FIPS203/internalProjection.json
//
// Every vector in each file is applied, through the public API. Each test counts the cases in
// its file and fails unless every one ran, apart from parameter sets whose feature is off. A
// group field or function that this harness does not know fails the test, so a new kind of
// NIST group is never skipped.

use hex::decode;
use rand_core::{CryptoRng, RngCore};
use serde_json::Value;
use std::fs;

#[cfg(feature = "ml-kem-1024")]
use fips203::ml_kem_1024;
#[cfg(feature = "ml-kem-512")]
use fips203::ml_kem_512;
#[cfg(feature = "ml-kem-768")]
use fips203::ml_kem_768;

use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};


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


// ----- ACCOUNTING: EVERY CASE IN A FILE RUNS, OR THE TEST FAILS -----
struct Tally {
    total: usize,
    ran: usize,
    feature_skipped: usize,
}

impl Tally {
    fn new(doc: &Value) -> Self {
        let total = groups(doc).iter().map(|g| cases(g).len()).sum();
        Tally { total, ran: 0, feature_skipped: 0 }
    }

    fn count(&mut self, handled: bool) {
        if handled { self.ran += 1 } else { self.feature_skipped += 1 }
    }

    fn finish(&self, which: &str) {
        println!("NIST {which}: ran {}, feature-skipped {}, of {}", self.ran, self.feature_skipped, self.total);
        assert_eq!(self.ran + self.feature_skipped, self.total, "NIST {which}: some cases did not run");
        assert!(self.ran > 0, "NIST {which}: no cases ran");
    }
}

// Runs `$run!(module)` for the parameter set named `$set` and returns true. Returns false when
// that set's feature is off, and panics on a parameter set it does not know.
macro_rules! dispatch {
    ($set:expr, $run:ident) => {
        match $set {
            #[cfg(feature = "ml-kem-512")]
            "ML-KEM-512" => { $run!(ml_kem_512); true }
            #[cfg(feature = "ml-kem-768")]
            "ML-KEM-768" => { $run!(ml_kem_768); true }
            #[cfg(feature = "ml-kem-1024")]
            "ML-KEM-1024" => { $run!(ml_kem_1024); true }
            #[allow(unreachable_patterns)]
            "ML-KEM-512" | "ML-KEM-768" | "ML-KEM-1024" => false,
            other => panic!("unknown parameter set {other}"),
        }
    };
}

/// The function that an encapDecap group applies.
#[derive(Clone, Copy)]
enum Function {
    Encaps,
    Decaps,
    EncapsKeyCheck,
    DecapsKeyCheck,
}

fn function_of(group: &Value) -> Function {
    match (group["function"].as_str(), group["testType"].as_str()) {
        (Some("encapsulation"), Some("AFT")) => Function::Encaps,
        (Some("decapsulation"), Some("VAL")) => Function::Decaps,
        (Some("encapsulationKeyCheck"), Some("VAL")) => Function::EncapsKeyCheck,
        (Some("decapsulationKeyCheck"), Some("VAL")) => Function::DecapsKeyCheck,
        other => panic!("tgId {}: unknown group kind {other:?}", group["tgId"]),
    }
}

fn load(name: &str) -> Value {
    let path = format!("./tests/nist_vectors/{name}/internalProjection.json");
    let vectors = fs::read_to_string(&path).expect("Unable to read file");
    serde_json::from_str(&vectors).unwrap()
}

fn groups(doc: &Value) -> &Vec<Value> { doc["testGroups"].as_array().expect("testGroups") }

fn cases(group: &Value) -> &Vec<Value> { group["tests"].as_array().expect("tests") }

/// Fails on a group field that this harness does not know.
fn check_group(group: &Value, known: &[&str]) {
    for key in group.as_object().expect("group").keys() {
        assert!(known.contains(&key.as_str()), "tgId {}: unknown group field {key}", group["tgId"]);
    }
}

fn hex(v: &Value, key: &str, loc: &str) -> Vec<u8> {
    decode(v[key].as_str().unwrap_or_else(|| panic!("{loc} missing {key}"))).unwrap()
}


#[test]
fn test_keygen() {
    let v = load("ML-KEM-keyGen-FIPS203");
    let mut tally = Tally::new(&v);

    for test_group in groups(&v) {
        check_group(test_group, &["parameterSet", "testType", "tests", "tgId"]);
        assert_eq!(test_group["testType"], "AFT", "tgId {}: testType", test_group["tgId"]);
        let set = test_group["parameterSet"].as_str().expect("parameterSet");
        for test in cases(test_group) {
            let loc = format!("{set} tgId={} tcId={}", test_group["tgId"], test["tcId"]);
            let z = hex(test, "z", &loc);
            let d = hex(test, "d", &loc);
            let ek_exp = hex(test, "ek", &loc);
            let dk_exp = hex(test, "dk", &loc);

            macro_rules! runtest {
                ($pc:ident) => {{
                    let (ek_act, dk_act) = $pc::KG::keygen_from_seed(
                        d.clone().try_into().unwrap(),
                        z.clone().try_into().unwrap(),
                    );
                    assert_eq!(ek_exp, ek_act.into_bytes(), "{loc}");
                    assert_eq!(dk_exp, dk_act.into_bytes(), "{loc}");
                }};
            }
            tally.count(dispatch!(set, runtest));
        }
    }
    tally.finish("keyGen");
}


#[test]
fn test_encap_decap() {
    let v = load("ML-KEM-encapDecap-FIPS203");
    let mut tally = Tally::new(&v);

    for test_group in groups(&v) {
        check_group(test_group, &["function", "parameterSet", "testType", "tests", "tgId"]);
        let set = test_group["parameterSet"].as_str().expect("parameterSet");
        let function = function_of(test_group);
        for test in cases(test_group) {
            let loc = format!("{set} tgId={} tcId={}", test_group["tgId"], test["tcId"]);

            macro_rules! runtest {
                ($pc:ident) => {{
                    match function {
                        Function::Encaps => {
                            let ek = $pc::EncapsKey::try_from_bytes(hex(test, "ek", &loc).try_into().unwrap())
                                .unwrap();
                            let mut rnd = TestRng::new();
                            rnd.push(&hex(test, "m", &loc));
                            let (ssk_act, ct_act) = ek.try_encaps_with_rng(&mut rnd).unwrap();
                            assert_eq!(hex(test, "k", &loc), ssk_act.into_bytes(), "{loc}");
                            assert_eq!(hex(test, "c", &loc), ct_act.into_bytes(), "{loc}");
                        }
                        Function::Decaps => {
                            let dk = $pc::DecapsKey::try_from_bytes(hex(test, "dk", &loc).try_into().unwrap())
                                .unwrap();
                            let c = $pc::CipherText::try_from_bytes(hex(test, "c", &loc).try_into().unwrap())
                                .unwrap();
                            let k_act = dk.try_decaps(&c).unwrap();
                            assert_eq!(hex(test, "k", &loc), k_act.into_bytes(), "{loc} ({})", test["reason"]);
                        }
                        Function::EncapsKeyCheck => {
                            let ek = hex(test, "ek", &loc);
                            let passed_act = $pc::EncapsKey::try_from_bytes(ek.try_into().unwrap()).is_ok();
                            assert_eq!(test["testPassed"].as_bool().unwrap(), passed_act, "{loc} ({})", test["reason"]);
                        }
                        Function::DecapsKeyCheck => {
                            let dk = hex(test, "dk", &loc);
                            let passed_act = $pc::DecapsKey::try_from_bytes(dk.try_into().unwrap()).is_ok();
                            assert_eq!(test["testPassed"].as_bool().unwrap(), passed_act, "{loc} ({})", test["reason"]);
                        }
                    }
                }};
            }
            tally.count(dispatch!(set, runtest));
        }
    }
    tally.finish("encapDecap");
}
