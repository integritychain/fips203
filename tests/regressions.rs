// Regression tests for specific FIPS 203 conformance bugs.
#![cfg(feature = "ml-kem-512")]

use fips203::ml_kem_512;
use fips203::traits::{Decaps, Encaps, SerDes};
use hex_literal::hex;
use rand_core::{CryptoRng, RngCore};
use sha3::{Digest, Sha3_256};


// Supplies m = 0^32 to encapsulation, which is the only randomness `try_encaps_with_rng` draws.
struct ZeroRng;

impl RngCore for ZeroRng {
    fn next_u32(&mut self) -> u32 { 0 }

    fn next_u64(&mut self) -> u64 { 0 }

    fn fill_bytes(&mut self, out: &mut [u8]) { out.fill(0) }

    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand_core::Error> {
        out.fill(0);
        Ok(())
    }
}

impl CryptoRng for ZeroRng {}


// Decompress_d must round to the nearest integer (FIPS 203 eq. 4.8 and §2.3), not up.
//
// This ML-KEM-512 key pair passes the §7.2 modulus check and the §7.3 hash check, so a conformant
// Decaps must return the encapsulated K. It is t_hat = (NTT(277), 0), rho = 0, s_hat = 0 and
// z = 0x07^32; no KeyGen produces it. Encapsulating m = 0 gives three c2 coefficients equal to 4.
// FIPS 203 has Decompress_4(4) = 832, which Compress_1 maps to bit 0; rounding up gives 833, which
// maps to bit 1, so the re-encryption check fails and Decaps returns J(z || c) instead of K.
// Expected values from kyber-py 1.2.0 and the pq-crystals/kyber `standard` branch (d5b791c).
#[test]
fn decaps_decompress_rounding_512() {
    let mut ek = [0u8; ml_kem_512::EK_LEN];
    for chunk in ek[..384].chunks_exact_mut(3) {
        chunk.copy_from_slice(&[0x15, 0x01, 0x00]); // ByteEncode_12 of the pair (277, 0)
    }
    let mut dk = [0u8; ml_kem_512::DK_LEN];
    dk[768..1568].copy_from_slice(&ek);
    dk[1568..1600].copy_from_slice(&Sha3_256::digest(ek));
    dk[1600..].fill(0x07);

    let ek = ml_kem_512::EncapsKey::try_from_bytes(ek).expect("ek passes the modulus check");
    let dk = ml_kem_512::DecapsKey::try_from_bytes(dk).expect("dk passes the hash check");

    let (k_enc, ct) = ek.try_encaps_with_rng(&mut ZeroRng).unwrap();
    let k_dec = dk.try_decaps(&ct).unwrap();

    assert_eq!(
        Sha3_256::digest(ct.into_bytes())[..],
        hex!("5824de534eab92fac7c6cd9dbb143633d956ec178e22862c02858174645966cc")
    );
    assert_eq!(
        k_enc.into_bytes(),
        hex!("50b09012b43149cae6b95d77db1295c29bfdb0a3cdae9d3e99b93fcb37b0f1d9")
    );
    // Rounding up gives J(z || c) = 98f37c7692544aca18102d5a96c0fc719f69adc7541d499bb56164066f63c154
    assert_eq!(
        k_dec.into_bytes(),
        hex!("50b09012b43149cae6b95d77db1295c29bfdb0a3cdae9d3e99b93fcb37b0f1d9")
    );
}
