use crate::helpers::ensure;
use crate::Q;
use crate::types::Z256;

// /// Algorithm 2 `BitsToBytes(b)` on page 17.
// /// Converts a bit string (of length a multiple of eight) into an array of bytes.
// ///
// /// Input: bit array b ∈ {0,1}^{8·ℓ} <br>
// /// Output: byte array B ∈ B^ℓ
// pub(crate) fn bits_to_bytes(bits: &[u8], bytes: &mut [u8]) -> Result<(), &'static str> {
//     ensure!(bits.len() % 8 == 0, "Alg2: bit length not multiple of 8");
//     // bit_array is multiple of 8
//     ensure!(bits.len() == 8 * bytes.len(), "Alg2: bit length not 8 * byte length"); // bit_array length is 8ℓ
//
//     // 1: B ← (0, . . . , 0)  (returned mutable data struct is provided by the caller)
//     bytes.iter_mut().for_each(|b| *b = 0);
//
//     // 2: for (i ← 0; i < 8ℓ; i ++)
//     for i in 0..bits.len() {
//         //
//         // 3: B [⌊i/8⌋] ← B [⌊i/8⌋] + b[i] · 2^{i mod 8}
//         bytes[i / 8] += bits[i] * 2u8.pow(u32::try_from(i).map_err(|_| "impossible 1")? % 8);
//         //
//     } // 4: end for
//
//     Ok(())
// } // 5: return B


// /// Algorithm 3 `BytesToBits(B)` on page 18.
// /// Performs the inverse of `BitsToBytes`, converting a byte array into a bit array.
// ///
// /// Input: byte array B ∈ B^ℓ <br>
// /// Output: bit array b ∈ {0,1}^{8·ℓ}
// pub(crate) fn bytes_to_bits(bytes: &[u8], bits: &mut [u8]) -> Result<(), &'static str> {
//     ensure!(bits.len() % 8 == 0, "Alg3: bit length not multiple of 8");
//     // bit_array is multiple of 8
//     ensure!(bytes.len() * 8 == bits.len(), "Alg3: bit length not 8 * byte length"); // bit_array length is 8ℓ
//
//     // 1: for (i ← 0; i < ℓ; i ++)
//     for i in 0..bytes.len() {
//         //
//         let mut byte = bytes[i]; // for use in step 4 shifting
//
//         // 2: for ( j ← 0; j < 8; j ++)
//         for j in 0..8 {
//             //
//             // 3: b[8i + j] ← B[i] mod 2
//             bits[8 * i + j] = byte % 2;
//
//             // 4: B[i] ← ⌊B[i]/2⌋
//             byte /= 2;
//             //
//         } // 5: end for
//     } // 6: end for
//     Ok(())
// } // 7: return b

/// Algorithm 4 `ByteEncode<d>(F)` on page 19.
/// Encodes an array of d-bit integers into a byte array, for 1 ≤ d ≤ 12.
///
/// Input: integer array `F ∈ Z^256_m`, where `m = 2^d if d < 12` and `m = q if d = 12` <br>
/// Output: byte array B ∈ B^{32d}
pub(crate) fn byte_encode(
    d: u32, integers_f: &[Z256; 256], bytes_b: &mut [u8],
) -> Result<(), &'static str> {
    let mut temp = 0u64;
    let mut bit_index = 0;
    let mut byte_index = 0;
    let m = if d < 12 { 2u64.pow(d) } else { Q as u64 };
    for coeff in integers_f {
        let coeff = coeff.get_u16() as u64; //% Q as u16) as u64;
        ensure!(coeff <= m, "Alg4: Coeff out of range");
        let coeff = coeff & (2u64.pow(d) - 1);
        temp |= coeff << bit_index;
        bit_index += d as usize;
        while bit_index > 7 {
            bytes_b[byte_index] = temp as u8;
            temp >>= 8;
            byte_index += 1;
            bit_index -= 8;
        }
    }
    Ok(())
}

// /// Algorithm 4 `ByteEncode<d>(F)` on page 19.
// /// Encodes an array of d-bit integers into a byte array, for 1 ≤ d ≤ 12.
// ///
// /// Input: integer array `F ∈ Z^256_m`, where `m = 2^d if d < 12` and `m = q if d = 12` <br>
// /// Output: byte array B ∈ B^{32d}
// pub(crate) fn byte_encode2<const D: usize, const D_256: usize>(
//     integers_f: &[Z256; 256], bytes_b: &mut [u8],
// ) -> Result<(), &'static str> {
//     ensure!((1 <= D) & (D <= 12), "Alg4: const probs 1");
//     ensure!(D * 256 == D_256, "Alg4: const probs 2");
//     ensure!(integers_f.len() == 256, "Alg4: integers length not 256");
//     ensure!(bytes_b.len() == 32 * D, "Alg4: byte length not 32 * D");
//
//     let m_mod = if D < 12 {
//         2_u16.pow(u32::try_from(D).map_err(|_| "impossible 2")?)
//     } else {
//         u16::try_from(Q).map_err(|_| "impossible 3")?
//     };
//     let mut bit_array = [0u8; D_256];
//
//     // 1: for (i ← 0; i < 256; i ++)
//     for i in 0..256 {
//         //
//         // 2: a ← F[i]      ▷ a ∈ Z_{2^d}
//         let mut a = integers_f[i].get_u16() % m_mod;
//
//         // 3: for ( j ← 0; j < d; j ++)
//         for j in 0..D {
//             //
//             // 4: b[i · d + j] ← a mod 2        ▷ b ∈ {0, 1}^{256·d}
//             bit_array[i * D + j] = (&a % 2) as u8;
//
//             // 5: a ← (a − b[i · d + j])/2      ▷ note a − b[i · d + j] is always even.
//             a = (a - u16::from(bit_array[i * D + j])) / 2;
//             //
//         } // 6: end for
//     } // 7: end for
//     //
//     // 8: B ← BitsToBytes(b)
//     bits_to_bytes(&bit_array, bytes_b)?;
//     //
//     Ok(())
// } // 9: return B


/// Algorithm 5 `ByteDecode<d>(B)` on page 19.
/// Decodes a byte array into an array of d-bit integers, for 1 ≤ d ≤ 12.
///
/// Input: byte array B ∈ B^{32d} <br>
/// Output: integer array `F ∈ Z^256_m`, where `m = 2^d if d < 12` and `m = q if d = 12`
pub(crate) fn byte_decode(
    d: u32, bytes_b: &[u8], integers_f: &mut [Z256; 256],
) -> Result<(), &'static str> {
    let bitlen = d;
    let mut temp = 0u64;
    let mut int_index = 0;
    let mut bit_index = 0;
    for byte in bytes_b {
        temp |= (*byte as u64) << bit_index;
        bit_index += 8;
        while bit_index >= bitlen {
            let tmask = temp & (2u64.pow(bitlen) - 1);
            integers_f[int_index] = Z256(tmask as u16);
            bit_index -= bitlen;
            temp >>= bitlen;
            int_index += 1;
        }
    }
    let max = if d < 12 { 2u16.pow(d) } else { Q as u16 };
    ensure!(integers_f.iter().all(|e| e.get_u16() < max), "Alg5: integers out of range");
    Ok(())
}
// #[allow(dead_code)]
// pub(crate) fn byte_decode2<const D: usize, const D_256: usize>(
//     bytes_b: &[u8], integers_f: &mut [Z256; 256],
// ) -> Result<(), &'static str> {
//     ensure!((1 <= D) & (D <= 12), "Alg5: Const probs");
//     ensure!(D * 256 == D_256, "Alg5: const probs");
//     ensure!(bytes_b.len() == 32 * D, "Alg5: bytes length not 32 * D");
//     ensure!(integers_f.len() == 256, "Alg5: integer length not 256");
//
//     let m_mod = if D < 12 {
//         2_u16.pow(u32::try_from(D).map_err(|_| "impossible 4")?)
//     } else {
//         u16::try_from(Q).map_err(|_| "impossible 5")?
//     };
//     let mut bit_array = [0u8; D_256];
//
//     // 1: b ← BytesToBits(B)
//     bytes_to_bits(bytes_b, &mut bit_array)?;
//
//     // 2: for (i ← 0; i < 256; i ++)
//     for i in 0..256 {
//         //
//         // 3: F[i] ← ∑^{d-1}_{j=0} b[i · d + j] · 2 mod m
//         integers_f[i] = (0..D).fold(Z256(0), |acc: Z256, j| {
//             Z256(
//                 (acc.get_u16()
//                     + u16::from(bit_array[i * D + j]) * 2_u16.pow(u32::try_from(j).unwrap()))
//                     % m_mod, // TODO: refine away from %
//             )
//         });
//         //
//     } // 4: end for
//     Ok(())
// } // 5: return F


#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::vec;
    use alloc::vec::Vec;

    use rand::{Rng, SeedableRng};

    use crate::byte_fns::{byte_decode, byte_encode};
    use crate::types::Z256;

// #[test]
    // fn test_bytes_and_bits() {
    //     let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(123);
    //
    //     for _i in 0..100 {
    //         let num_bytes = rng.gen::<u8>();
    //         let bytes1: Vec<u8> = (0..num_bytes).map(|_| rng.gen()).collect();
    //         let mut bits = vec![0u8; num_bytes as usize * 8];
    //         bytes_to_bits(&bytes1, &mut bits[..]).unwrap();
    //         let mut bytes2 = vec![0u8; num_bytes as usize];
    //         bits_to_bytes(&bits, &mut bytes2[..]).unwrap();
    //         assert_eq!(bytes1, bytes2);
    //     }
    // }

    #[test]
    fn test_decode_and_encode() {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(123);
        let mut integer_array = [Z256(0); 256];
        for _i in 0..100 {
            let num_bytes = 32 * 11;
            let mut bytes2 = vec![0u8; num_bytes];
            let bytes1: Vec<u8> = (0..num_bytes).map(|_| rng.gen()).collect();
            byte_decode(11, &bytes1, &mut integer_array).unwrap();
            byte_encode(11, &integer_array, &mut bytes2).unwrap();
            assert_eq!(bytes1, bytes2);

            let num_bytes = 32 * 10;
            let bytes1: Vec<u8> = (0..num_bytes).map(|_| rng.gen()).collect();
            let mut bytes2 = vec![0u8; num_bytes];
            byte_decode(10, &bytes1, &mut integer_array).unwrap();
            byte_encode(10, &integer_array, &mut bytes2).unwrap();
            assert_eq!(bytes1, bytes2);

            let num_bytes = 32 * 5;
            let bytes1: Vec<u8> = (0..num_bytes).map(|_| rng.gen()).collect();
            let mut bytes2 = vec![0u8; num_bytes];
            byte_decode(5, &bytes1, &mut integer_array).unwrap();
            byte_encode(5, &integer_array, &mut bytes2).unwrap();
            assert_eq!(bytes1, bytes2);

            let num_bytes = 32 * 4;
            let bytes1: Vec<u8> = (0..num_bytes).map(|_| rng.gen()).collect();
            let mut bytes2 = vec![0u8; num_bytes];
            byte_decode(4, &bytes1, &mut integer_array).unwrap();
            byte_encode(4, &integer_array, &mut bytes2).unwrap();
            assert_eq!(bytes1, bytes2);
        }
    }
}
