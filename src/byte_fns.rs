use crate::helpers::ensure;
use crate::types::Z;
use crate::Q;


// Note: Algorithm 2 and 3 have been "optimized away" as they had a lot of overhead
// and made memory allocations tricky. The definitions are left here for reference.

// /// Algorithm 2 `BitsToBytes(b)` on page 17.
// /// Converts a bit string (of length a multiple of eight) into an array of bytes.
// ///
// /// Input: bit array b ∈ {0,1}^{8·ℓ} <br>
// /// Output: byte array B ∈ B^ℓ

// /// Algorithm 3 `BytesToBits(B)` on page 18.
// /// Performs the inverse of `BitsToBytes`, converting a byte array into a bit array.
// ///
// /// Input: byte array B ∈ B^ℓ <br>
// /// Output: bit array b ∈ {0,1}^{8·ℓ}


/// Algorithm 4 `ByteEncode_d(F)` on page 19.
/// Encodes an array of `d`-bit integers into a byte array, for `1 ≤ d ≤ 12`.
/// This is an optimized variant (which does not use individual bit functions).
///
/// Input: integer array `F ∈ Z^{256}_m`, where `m = 2^d if d < 12` and `m = q if d = 12` <br>
/// Output: byte array B ∈ B^{32·d}
pub(crate) fn byte_encode(
    d: u32, integers_f: &[Z; 256], bytes_b: &mut [u8],
) -> Result<(), &'static str> {
    debug_assert_eq!(bytes_b.len(), 32 * d as usize, "Alg 4: bytes len is not 32 * d");
    //
    // Our "working" register, from which to drop bytes out of
    let mut temp = 0u32;
    // Bit index of current temp contents, and byte index of current output
    let mut bit_index = 0;
    let mut byte_index = 0;
    // Choose m per spec
    let m = if d < 12 { 2u32.pow(d) } else { Q };

    // Work through each of the input integers
    for coeff in integers_f {
        //
        // Get coeff as u64, check magnitude, and clean off top bits
        let coeff = coeff.get_u32();
        ensure!(coeff <= m, "Alg4: Coeff out of range");
        let coeff = coeff & (2u32.pow(d) - 1);

        // Drop coeff into the upper unused bit positions of coeff; adjust bit index
        temp |= coeff << bit_index;
        bit_index += d as usize;

        // While we have enough bits to drop a byte, do so
        #[allow(clippy::cast_possible_truncation)] // Intentional truncation
        while bit_index > 7 {
            //
            // Drop the byte
            bytes_b[byte_index] = temp as u8;

            // Update the indices
            temp >>= 8;
            byte_index += 1;
            bit_index -= 8;
        }
    }
    Ok(())
}


/// Algorithm 5 `ByteDecode_d(B)` on page 19.
/// Decodes a byte array into an array of d-bit integers, for 1 ≤ d ≤ 12.
/// This is an optimized variant (which does not use individual bit functions).
///
/// Input: byte array B ∈ B^{32·d} <br>
/// Output: integer array `F ∈ Z^256_m`, where `m = 2^d if d < 12` and `m = q if d = 12`
pub(crate) fn byte_decode(
    d: u32, bytes_b: &[u8], integers_f: &mut [Z; 256],
) -> Result<(), &'static str> {
    debug_assert_eq!(bytes_b.len(), 32 * d as usize, "Alg 5: bytes len is not 32 * d");
    //
    // Our "working" register
    let mut temp = 0u64;
    // Bit index of current temp contents, and int index of current output
    let mut bit_index = 0;
    let mut int_index = 0;

    // Work through every byte in the input
    for byte in bytes_b {
        //
        // Drop the byte into the upper/empty portion of temp; update bit index
        temp |= u64::from(*byte) << bit_index;
        bit_index += 8;

        // If we have enough bits to drop an int, do so
        #[allow(clippy::cast_possible_truncation)] // Intentional truncation
        while bit_index >= d {
            //
            // Mask off the upport portion and drop it in
            let mut z = Z::default();
            z.set_u16(temp as u16 & (2u16.pow(d) - 1));
            integers_f[int_index] = z;

            // Update the indices
            bit_index -= d;
            temp >>= d;
            int_index += 1;
        }
    }

    let m = if d < 12 {
        2u16.pow(d)
    } else {
        u16::try_from(Q).unwrap()
    };
    ensure!(integers_f.iter().all(|e| e.get_u16() < m), "Alg5: integers out of range");
    Ok(())
}


#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::vec;
    use alloc::vec::Vec;

    use rand::{Rng, SeedableRng};

    use crate::byte_fns::{byte_decode, byte_encode};
    use crate::types::Z;

    // Simple round trip tests...
    #[test]
    fn test_decode_and_encode() {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(123);
        let mut integer_array = [Z::default(); 256];
        for num_bits in 2..12_u32 {
            for _i in 0..100 {
                let num_bytes = 32 * num_bits as usize;
                let mut bytes2 = vec![0u8; num_bytes];
                let bytes1: Vec<u8> = (0..num_bytes).map(|_| rng.gen()).collect();
                byte_decode(num_bits, &bytes1, &mut integer_array).unwrap();
                byte_encode(num_bits, &integer_array, &mut bytes2).unwrap();
                assert_eq!(bytes1, bytes2);
            }
        }
    }

    #[test]
    fn test_result_errs() {
        let mut integer_array = [Z::default(); 256];
        let num_bits = 12;
        let num_bytes = 32 * num_bits as usize;
        let bytes1: Vec<u8> = (0..num_bytes).map(|_| 0xFF).collect();
        let ret = byte_decode(num_bits, &bytes1, &mut integer_array);
        assert!(ret.is_err());
        integer_array.iter_mut().for_each(|x| x.set_u16(u16::MAX));
        let mut bytes2 = vec![0u8; num_bytes];
        let ret = byte_encode(num_bits, &integer_array, &mut bytes2);
        assert!(ret.is_err());
    }
}
