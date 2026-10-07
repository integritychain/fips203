// Negative tests for input checking.
#[cfg(feature = "ml-kem-1024")]
use fips203::ml_kem_1024;
#[cfg(feature = "ml-kem-512")]
use fips203::ml_kem_512;
#[cfg(feature = "ml-kem-768")]
use fips203::ml_kem_768;
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};


// Sets coefficient j of s_hat[i] in a serialized decaps key. ByteEncode_12 packs each pair of
// 12-bit coefficients into three bytes, low bits first.
#[allow(dead_code)]
fn set_s_hat(dk: &mut [u8], i: usize, j: usize, value: u16) {
    let b = 384 * i + 3 * (j / 2);
    if j % 2 == 0 {
        dk[b] = value as u8;
        dk[b + 1] = (dk[b + 1] & 0xF0) | (value >> 8) as u8;
    } else {
        dk[b + 1] = (dk[b + 1] & 0x0F) | ((value & 0x0F) << 4) as u8;
        dk[b + 2] = (value >> 4) as u8;
    }
}


// DecapsKey::try_from_bytes rejects an s_hat coefficient >= q, beyond the FIPS 203 §7.3 checks,
// so try_decaps cannot fail on a key it accepts. q - 1 stays valid. Each set checks the first
// coefficient (even, low bits) and the last (odd, high bits).
macro_rules! s_hat_range_test {
    ($name:ident, $feature:literal, $set:ident, $k:expr) => {
        #[test]
        #[cfg(feature = $feature)]
        fn $name() {
            let (ek, dk) = $set::KG::keygen_from_seed([1u8; 32], [2u8; 32]);
            let (ssk, ct) = ek.encaps_from_seed(&[3u8; 32]);
            let dk_bytes = dk.into_bytes();

            let dk = $set::DecapsKey::try_from_bytes(dk_bytes).unwrap();
            assert_eq!(dk.try_decaps(&ct).unwrap(), ssk);

            for (i, j) in [(0, 0), ($k - 1, 255)] {
                let mut bytes = dk_bytes;
                set_s_hat(&mut bytes, i, j, 3328);
                let dk = $set::DecapsKey::try_from_bytes(bytes).unwrap();
                assert!(dk.try_decaps(&ct).is_ok());

                for value in [3329, 4095] {
                    let mut bytes = dk_bytes;
                    set_s_hat(&mut bytes, i, j, value);
                    let res = $set::DecapsKey::try_from_bytes(bytes);
                    assert_eq!(res.err(), Some("Decaps key s_hat out of range"));
                }
            }
        }
    };
}

s_hat_range_test!(s_hat_range_512, "ml-kem-512", ml_kem_512, 2);
s_hat_range_test!(s_hat_range_768, "ml-kem-768", ml_kem_768, 3);
s_hat_range_test!(s_hat_range_1024, "ml-kem-1024", ml_kem_1024, 4);
