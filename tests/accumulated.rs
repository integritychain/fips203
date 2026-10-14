// This file runs Go's accumulated ML-KEM-768 test (BSD-3-Clause), which targets the final FIPS 203.
//   from: https://github.com/golang/go/blob/06fcd67cc3371f8b5c8b577a650afd123ab9dad4/src/crypto/mlkem/mlkem_test.go
//
// Each iteration reads a 64-byte seed (d || z), a message m and a random ciphertext from one
// SHAKE128 instance. The derived ek, the ciphertext and shared secret of encapsulating m, and the
// implicit-rejection secret of decapsulating the random ciphertext are written to a second
// SHAKE128 instance; decapsulating the real ciphertext must give the shared secret. The second
// instance's 32-byte output must match Go's value: 10 000 iterations in release builds, 100 in
// debug builds. Go publishes no values for ML-KEM-512 or ML-KEM-1024. No vector data is stored.

#[cfg(feature = "ml-kem-768")]
#[test]
fn accumulated_768() {
    use fips203::ml_kem_768;
    use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    use sha3::Shake128;

    let (n, expected) = if cfg!(debug_assertions) {
        (100, "1114b1b6699ed191734fa339376afa7e285c9e6acf6ff0177d346696ce564415")
    } else {
        (10_000, "8a518cc63da366322a8e7a818c7a0d63483cb3528d34a4cf42f35d5ad73f22fc")
    };
    let mut s = Shake128::default().finalize_xof();
    let mut o = Shake128::default();
    for _ in 0..n {
        let (mut d, mut z, mut m) = ([0u8; 32], [0u8; 32], [0u8; 32]);
        s.read(&mut d);
        s.read(&mut z);
        let (ek, dk) = ml_kem_768::KG::keygen_from_seed(d, z);
        o.update(&ek.clone().into_bytes());
        s.read(&mut m);
        let (k, ct) = ek.encaps_from_seed(&m);
        o.update(&ct.clone().into_bytes());
        o.update(&k.clone().into_bytes());
        assert_eq!(dk.try_decaps(&ct).unwrap(), k);
        let mut ct1 = [0u8; ml_kem_768::CT_LEN];
        s.read(&mut ct1);
        let k1 = dk.try_decaps(&ml_kem_768::CipherText::try_from_bytes(ct1).unwrap()).unwrap();
        o.update(&k1.into_bytes());
    }
    let mut out = [0u8; 32];
    o.finalize_xof().read(&mut out);
    assert_eq!(hex::encode(out), expected, "{n} iterations");
}
