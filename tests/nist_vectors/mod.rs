// This file implements a variety of top-level tests, including: official vectors, random
// round trips, and (soon) fails.

use std::fs;

use hex::decode;
use rand_core::{CryptoRng, RngCore};
use regex::Regex;

use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
use fips203::{ml_kem_1024, ml_kem_512, ml_kem_768};

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


// ----- EXTRACT I/O VALUES FROM OFFICIAL VECTORS -----

fn get_keygen_vec(filename: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let data = fs::read_to_string(filename).expect("Unable to read file");
    let z_regex = Regex::new(r"z: ([0-9a-fA-F]+)").unwrap();
    let z = decode(z_regex.captures(&data).unwrap().get(1).unwrap().as_str()).unwrap();
    let d_regex = Regex::new(r"d: ([0-9a-fA-F]+)").unwrap();
    let d = decode(d_regex.captures(&data).unwrap().get(1).unwrap().as_str()).unwrap();
    let ek_regex = Regex::new(r"ek: ([0-9a-fA-F]+)").unwrap();
    let ek_exp = decode(ek_regex.captures(&data).unwrap().get(1).unwrap().as_str()).unwrap();
    let dk_regex = Regex::new(r"dk: ([0-9a-fA-F]+)").unwrap();
    let dk_exp = decode(dk_regex.captures(&data).unwrap().get(1).unwrap().as_str()).unwrap();
    (d, z, ek_exp, dk_exp)
}

fn get_encaps_vec(filename: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let data = fs::read_to_string(filename).expect("Unable to read file");
    let ek_regex = Regex::new(r"ek: ([0-9a-fA-F]+)").unwrap();
    let ek = decode(ek_regex.captures(&data).unwrap().get(1).unwrap().as_str()).unwrap();
    let m_regex = Regex::new(r"m: ([0-9a-fA-F]+)").unwrap();
    let m = decode(m_regex.captures(&data).unwrap().get(1).unwrap().as_str()).unwrap();
    let ssk_regex = Regex::new(r"K: ([0-9a-fA-F]+)").unwrap();
    let ssk = decode(ssk_regex.captures(&data).unwrap().get(1).unwrap().as_str()).unwrap();
    let ct_regex = Regex::new(r"c: ([0-9a-fA-F]+)").unwrap();
    let ct = decode(ct_regex.captures(&data).unwrap().get(1).unwrap().as_str()).unwrap();
    (ek, m, ssk, ct)
}

fn get_decaps_vec(filename: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let data = fs::read_to_string(filename).expect("Unable to read file");
    let dk_regex = Regex::new(r"dk: ([0-9a-fA-F]+)").unwrap();
    let dk = decode(dk_regex.captures(&data).unwrap().get(1).unwrap().as_str()).unwrap();
    let c_regex = Regex::new(r"c: ([0-9a-fA-F]+)").unwrap();
    let c = decode(c_regex.captures(&data).unwrap().get(1).unwrap().as_str()).unwrap();
    let kprime_regex = Regex::new(r"KPrime: ([0-9a-fA-F]+)").unwrap();
    let kprime = decode(
        kprime_regex
            .captures(&data)
            .unwrap()
            .get(1)
            .unwrap()
            .as_str(),
    )
    .unwrap();
    (dk, c, kprime)
}

// ----- TEST KEYGEN, SIGN AND VERIFY

#[test]
fn test_keygen() {
    let (z, d, ek_exp, dk_exp) =
        get_keygen_vec("./tests/nist_vectors/Key Generation -- ML-KEM-512.txt");
    let mut rnd = TestRng::new();
    rnd.push(&d);
    rnd.push(&z);
    let (ek_act, dk_act) = ml_kem_512::KG::try_keygen_with_rng(&mut rnd).unwrap();
    assert_eq!(ek_exp, ek_act.into_bytes());
    assert_eq!(dk_exp, dk_act.into_bytes());

    let (z, d, ek_exp, dk_exp) =
        get_keygen_vec("./tests/nist_vectors/Key Generation -- ML-KEM-768.txt");
    let mut rnd = TestRng::new();
    rnd.push(&d);
    rnd.push(&z);
    let (ek_act, dk_act) = ml_kem_768::KG::try_keygen_with_rng(&mut rnd).unwrap();
    assert_eq!(ek_exp, ek_act.into_bytes());
    assert_eq!(dk_exp, dk_act.into_bytes());

    let (z, d, ek_exp, dk_exp) =
        get_keygen_vec("./tests/nist_vectors/Key Generation -- ML-KEM-1024.txt");
    let mut rnd = TestRng::new();
    rnd.push(&d);
    rnd.push(&z);
    let (ek_act, dk_act) = ml_kem_1024::KG::try_keygen_with_rng(&mut rnd).unwrap();
    assert_eq!(ek_exp, ek_act.into_bytes());
    assert_eq!(dk_exp, dk_act.into_bytes());
}

#[test]
fn test_encaps() {
    let (ek, m, ssk_exp, ct_exp) =
        get_encaps_vec("./tests/nist_vectors/Encapsulation -- ML-KEM-512.txt");
    let mut rnd = TestRng::new();
    rnd.push(&m);
    let ek = ml_kem_512::EncapsKey::try_from_bytes(ek.try_into().unwrap()).unwrap();
    let (ssk_act, ct_act) = ek.try_encaps_with_rng(&mut rnd).unwrap();
    assert_eq!(ssk_exp, ssk_act.into_bytes());
    assert_eq!(ct_exp, ct_act.into_bytes());

    let (ek, m, ssk_exp, ct_exp) =
        get_encaps_vec("./tests/nist_vectors/Encapsulation -- ML-KEM-768.txt");
    let mut rnd = TestRng::new();
    rnd.push(&m);
    let ek = ml_kem_768::EncapsKey::try_from_bytes(ek.try_into().unwrap()).unwrap();
    let (ssk_act, ct_act) = ek.try_encaps_with_rng(&mut rnd).unwrap();
    assert_eq!(ssk_exp, ssk_act.into_bytes());
    assert_eq!(ct_exp, ct_act.into_bytes());

    let (ek, m, ssk_exp, ct_exp) =
        get_encaps_vec("./tests/nist_vectors/Encapsulation -- ML-KEM-1024.txt");
    let mut rnd = TestRng::new();
    rnd.push(&m);
    let ek = ml_kem_1024::EncapsKey::try_from_bytes(ek.try_into().unwrap()).unwrap();
    let (ssk_act, ct_act) = ek.try_encaps_with_rng(&mut rnd).unwrap();
    assert_eq!(ssk_exp, ssk_act.into_bytes());
    assert_eq!(ct_exp, ct_act.into_bytes());
}

#[test]
fn test_decaps() {
    let (dk, c, kprime_exp) =
        get_decaps_vec("./tests/nist_vectors/Decapsulation -- ML-KEM-512.txt");
    let dk = ml_kem_512::DecapsKey::try_from_bytes(dk.try_into().unwrap()).unwrap();
    let c = ml_kem_512::CipherText::try_from_bytes(c.try_into().unwrap()).unwrap();
    let kprime_act = dk.try_decaps(&c).unwrap();
    assert_eq!(kprime_exp, kprime_act.into_bytes());

    let (dk, c, kprime_exp) =
        get_decaps_vec("./tests/nist_vectors/Decapsulation -- ML-KEM-768.txt");
    let dk = ml_kem_768::DecapsKey::try_from_bytes(dk.try_into().unwrap()).unwrap();
    let c = ml_kem_768::CipherText::try_from_bytes(c.try_into().unwrap()).unwrap();
    let kprime_act = dk.try_decaps(&c).unwrap();
    assert_eq!(kprime_exp, kprime_act.into_bytes());

    let (dk, c, kprime_exp) =
        get_decaps_vec("./tests/nist_vectors/Decapsulation -- ML-KEM-1024.txt");
    let dk = ml_kem_1024::DecapsKey::try_from_bytes(dk.try_into().unwrap()).unwrap();
    let c = ml_kem_1024::CipherText::try_from_bytes(c.try_into().unwrap()).unwrap();
    let kprime_act = dk.try_decaps(&c).unwrap();
    assert_eq!(kprime_exp, kprime_act.into_bytes());
}
