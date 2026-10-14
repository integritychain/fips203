// This file applies the C2SP CCTV ML-KEM vectors (CC0 1.0).
//   from: https://github.com/C2SP/CCTV/tree/fd8cecee5f7746d0c6b8c3f4530c8976d629cbfa/ML-KEM
//
// The vectors were made for the FIPS 203 draft. The final standard's K-PKE.KeyGen hashes d with
// k (G(d || k)), so the intermediate and unlucky keys no longer follow from their seeds. Those
// tests take ek and dk from the file and check Encaps and Decaps, which did not change; the
// unlucky rho is in ek, so Encaps still runs the long SampleNTT path. CCTV's accumulated ML-KEM
// hashes are also for the draft; tests/accumulated.rs applies Go's final-standard ones instead.
// This harness and its vectors are excluded from the published crate.

use std::fs;
use std::io::Read;

use flate2::read::GzDecoder;
use hex::decode;
use regex::Regex;

#[cfg(feature = "ml-kem-1024")]
use fips203::ml_kem_1024;
#[cfg(feature = "ml-kem-512")]
use fips203::ml_kem_512;
#[cfg(feature = "ml-kem-768")]
use fips203::ml_kem_768;
use fips203::traits::{Decaps, Encaps, SerDes};

// The keys, message, shared secret and ciphertext of an intermediate or unlucky file
#[allow(clippy::type_complexity)]
fn get_intermediate_vec(filename: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let data = fs::read_to_string(filename).expect("Unable to read file");
    let ek_regex = Regex::new(r"ek = ([0-9a-fA-F]+)").unwrap();
    let ek_exp = decode(ek_regex.captures(&data).unwrap().get(1).unwrap().as_str()).unwrap();
    let dk_regex = Regex::new(r"dk = ([0-9a-fA-F]+)").unwrap();
    let dk_exp = decode(dk_regex.captures(&data).unwrap().get(1).unwrap().as_str()).unwrap();
    let m_regex = Regex::new(r"m = ([0-9a-fA-F]+)").unwrap();
    let m = decode(m_regex.captures(&data).unwrap().get(1).unwrap().as_str()).unwrap();
    let k_regex = Regex::new(r"K = ([0-9a-fA-F]+)").unwrap();
    let k_exp = decode(k_regex.captures(&data).unwrap().get(1).unwrap().as_str()).unwrap();
    let c_regex = Regex::new(r"c = ([0-9a-fA-F]+)").unwrap();
    let c_exp = decode(c_regex.captures(&data).unwrap().get(1).unwrap().as_str()).unwrap();

    (ek_exp, dk_exp, m, k_exp, c_exp)
}

// The file's keys must encapsulate m to its K and c, and decapsulate c to K
macro_rules! encaps_decaps {
    ($pc:ident, $filename:expr) => {{
        let (ek_exp, dk_exp, m, k_exp, c_exp) = get_intermediate_vec($filename);
        let ek = $pc::EncapsKey::try_from_bytes(ek_exp.try_into().unwrap()).unwrap();
        let dk = $pc::DecapsKey::try_from_bytes(dk_exp.try_into().unwrap()).unwrap();
        let (k_act, c_act) = ek.encaps_from_seed(&m.try_into().unwrap());
        assert_eq!(k_exp, k_act.clone().into_bytes());
        assert_eq!(c_exp, c_act.clone().into_bytes());
        assert_eq!(k_act, dk.try_decaps(&c_act).unwrap());
    }};
}

#[test]
#[cfg(feature = "ml-kem-512")]
pub fn test_intermediate_512() {
    encaps_decaps!(ml_kem_512, "./tests/cctv_vectors/ML-KEM/intermediate/ML-KEM-512.txt");
}

#[test]
#[cfg(feature = "ml-kem-768")]
pub fn test_intermediate_768() {
    encaps_decaps!(ml_kem_768, "./tests/cctv_vectors/ML-KEM/intermediate/ML-KEM-768.txt");
}

#[test]
#[cfg(feature = "ml-kem-1024")]
pub fn test_intermediate_1024() {
    encaps_decaps!(ml_kem_1024, "./tests/cctv_vectors/ML-KEM/intermediate/ML-KEM-1024.txt");
}

fn get_strcmp_vec(filename: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let data = fs::read_to_string(filename).expect("Unable to read file");
    let dk_regex = Regex::new(r"dk = ([0-9a-fA-F]+)").unwrap();
    let dk_exp = decode(dk_regex.captures(&data).unwrap().get(1).unwrap().as_str()).unwrap();
    let k_regex = Regex::new(r"K = ([0-9a-fA-F]+)").unwrap();
    let k_exp = decode(k_regex.captures(&data).unwrap().get(1).unwrap().as_str()).unwrap();
    let c_regex = Regex::new(r"c = ([0-9a-fA-F]+)").unwrap();
    let c_exp = decode(c_regex.captures(&data).unwrap().get(1).unwrap().as_str()).unwrap();

    (dk_exp, k_exp, c_exp)
}

// CCTV strcmp vector: implicit rejection must not stop at an embedded 0x00.
#[test]
#[cfg(feature = "ml-kem-512")]
pub fn test_strcmp_512() {
    let (dk_exp, k_exp, c_exp) =
        get_strcmp_vec("./tests/cctv_vectors/ML-KEM/strcmp/ML-KEM-512.txt");
    let dk = ml_kem_512::DecapsKey::try_from_bytes(dk_exp.try_into().unwrap()).unwrap();
    let c = ml_kem_512::CipherText::try_from_bytes(c_exp.try_into().unwrap()).unwrap();
    let k_act = dk.try_decaps(&c).unwrap();
    assert_eq!(k_exp, k_act.into_bytes());
}

// CCTV strcmp vector: implicit rejection must not stop at an embedded 0x00.
#[test]
#[cfg(feature = "ml-kem-768")]
pub fn test_strcmp_768() {
    let (dk_exp, k_exp, c_exp) =
        get_strcmp_vec("./tests/cctv_vectors/ML-KEM/strcmp/ML-KEM-768.txt");
    let dk = ml_kem_768::DecapsKey::try_from_bytes(dk_exp.try_into().unwrap()).unwrap();
    let c = ml_kem_768::CipherText::try_from_bytes(c_exp.try_into().unwrap()).unwrap();
    let k_act = dk.try_decaps(&c).unwrap();
    assert_eq!(k_exp, k_act.into_bytes());
}

// CCTV strcmp vector: implicit rejection must not stop at an embedded 0x00.
#[test]
#[cfg(feature = "ml-kem-1024")]
pub fn test_strcmp_1024() {
    let (dk_exp, k_exp, c_exp) =
        get_strcmp_vec("./tests/cctv_vectors/ML-KEM/strcmp/ML-KEM-1024.txt");
    let dk = ml_kem_1024::DecapsKey::try_from_bytes(dk_exp.try_into().unwrap()).unwrap();
    let c = ml_kem_1024::CipherText::try_from_bytes(c_exp.try_into().unwrap()).unwrap();
    let k_act = dk.try_decaps(&c).unwrap();
    assert_eq!(k_exp, k_act.into_bytes());
}

#[test]
#[cfg(feature = "ml-kem-512")]
pub fn test_unlucky_512() {
    encaps_decaps!(ml_kem_512, "./tests/cctv_vectors/ML-KEM/unluckysample/ML-KEM-512.txt");
}

#[test]
#[cfg(feature = "ml-kem-768")]
pub fn test_unlucky_768() {
    encaps_decaps!(ml_kem_768, "./tests/cctv_vectors/ML-KEM/unluckysample/ML-KEM-768.txt");
}

#[test]
#[cfg(feature = "ml-kem-1024")]
pub fn test_unlucky_1024() {
    encaps_decaps!(ml_kem_1024, "./tests/cctv_vectors/ML-KEM/unluckysample/ML-KEM-1024.txt");
}

// CCTV modulus vector: an encapsulation key with any coefficient >= q must be rejected.
#[test]
#[cfg(feature = "ml-kem-512")]
fn test_modulus_512() {
    let gz = fs::read("./tests/cctv_vectors/ML-KEM/modulus/ML-KEM-512.txt.gz").unwrap();
    let mut d = GzDecoder::new(&gz[..]);
    let mut s = String::new();
    d.read_to_string(&mut s).unwrap();
    for line in s.lines() {
        let ek_bytes = decode(line).unwrap();
        let ek = ml_kem_512::EncapsKey::try_from_bytes(ek_bytes.try_into().unwrap());
        assert!(ek.is_err())
    }
}

// CCTV modulus vector: an encapsulation key with any coefficient >= q must be rejected.
#[test]
#[cfg(feature = "ml-kem-768")]
fn test_modulus_768() {
    let gz = fs::read("./tests/cctv_vectors/ML-KEM/modulus/ML-KEM-768.txt.gz").unwrap();
    let mut d = GzDecoder::new(&gz[..]);
    let mut s = String::new();
    d.read_to_string(&mut s).unwrap();
    for line in s.lines() {
        let ek_bytes = decode(line).unwrap();
        let ek = ml_kem_768::EncapsKey::try_from_bytes(ek_bytes.try_into().unwrap());
        assert!(ek.is_err())
    }
}

// CCTV modulus vector: an encapsulation key with any coefficient >= q must be rejected.
#[test]
#[cfg(feature = "ml-kem-1024")]
fn test_modulus_1024() {
    let gz = fs::read("./tests/cctv_vectors/ML-KEM/modulus/ML-KEM-1024.txt.gz").unwrap();
    let mut d = GzDecoder::new(&gz[..]);
    let mut s = String::new();
    d.read_to_string(&mut s).unwrap();
    for line in s.lines() {
        let ek_bytes = decode(line).unwrap();
        let ek = ml_kem_1024::EncapsKey::try_from_bytes(ek_bytes.try_into().unwrap());
        assert!(ek.is_err())
    }
}
