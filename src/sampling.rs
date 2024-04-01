use crate::types::Z;
use crate::Q;
use sha3::digest::XofReader;
use subtle::{Choice, ConditionallySelectable};

/// Algorithm 6 `SampleNTT(B)` on page 20.
/// If the input is a stream of uniformly random bytes, the output is a uniformly random element of `T_q`.
///
/// Input: byte stream B ∈ B^{∗} <br>
/// Output: array `a_hat` ∈ `Z^{256}_q`              ▷ the coefficients of the NTT of a polynomial
pub(crate) fn sample_ntt(mut byte_stream_b: impl XofReader) -> Result<[Z; 256], &'static str> {
    //
    let mut array_a_hat = [Z::default(); 256];
    let mut bbb = [0u8; 3]; // Space for 3 random (byte) draws

    // 1: i ← 0 (not needed as three bytes are repeatedly drawn from the rng bytestream via bbb)

    // 2: j ← 0
    let mut j = 0u32;

    // The original sampling loop has inherent timing variability based on the need to reject
    // `d1` > `Q` per step 6+ along with `d2` > `Q` per step 10+. The adapted loop below does
    // "too much, but a constant amount of work" with the additional margin impacting performance.
    // The proportion of fails is approx 3.098e-12 or 2**{-38}; re-run with fresh randomness.
    // See cdf at https://www.wolframalpha.com/input?i=binomial+distribution+calculator&assumption=%7B%22F%22%2C+%22BinomialProbabilities%22%2C+%22x%22%7D+-%3E%22256%22&assumption=%7B%22F%22%2C+%22BinomialProbabilities%22%2C+%22n%22%7D+-%3E%22384%22&assumption=%7B%22F%22%2C+%22BinomialProbabilities%22%2C+%22p%22%7D+-%3E%223329%2F4095%22
    // 3: while j < 256 do  --> this is adapted for constant-time operation
    for _k in 0..192 {
        //
        // Note: two samples (d1, d2) are drawn per loop iteration
        byte_stream_b.read(&mut bbb); // Draw 3 bytes

        // 4: d1 ← B[i] + 256 · (B[i + 1] mod 16)
        let d1 = u32::from(bbb[0]) + 256 * (u32::from(bbb[1]) & 0x0F);

        // 5: d2 ← ⌊B[i + 1]/16⌋ + 16 · B[i + 2]
        let d2 = (u32::from(bbb[1]) >> 4) + 16 * u32::from(bbb[2]);

        // 6: if d1 < q then
        let if_step6 = Choice::from(u8::from((d1 < u32::from(Q)) && (j < 256)));
        let d1 = u32::conditional_select(&0, &d1, if_step6);
        //
        // 7: a_hat[j] ← d1         ▷ a_hat ∈ Z256
        array_a_hat[j as usize & 0xFF] = array_a_hat[j as usize & 0xFF].or(d1);

        // 8: j ← j+1
        //j += 1 & mask;
        j.conditional_assign(&(j + 1), if_step6);

        // 9: end if

        // 10: if d2 < q and j < 256 then
        let if_step10 = Choice::from(u8::from((d2 < u32::from(Q)) && (j < 256)));
        let d2 = u32::conditional_select(&0, &d2, if_step10);

        // 11: a_hat[j] ← d2
        array_a_hat[j as usize & 0xFF] = array_a_hat[j as usize & 0xFF].or(d2);

        // 12: j ← j+1
        j.conditional_assign(&(j + 1), if_step10);

        // 13: end if

        // 14: i ← i+3  (not needed as we draw 3 more bytes next time

        // 15: end while
    }

    // Result does not need to be constant-time
    if j < 256 {
        Err("Alg 6: Sampling issue, please try again with fresh randomness")
    } else {
        //
        // 16: return a_hat
        Ok(array_a_hat)
    }
}


/// Algorithm 7 `SamplePolyCBDη(B)` on page 20.
/// If the input is a stream of uniformly random bytes, outputs a sample from the distribution `D_η(R_q)`. <br>
/// This function is an optimized version that avoids the `BytesToBits` function (algorithm 3).
///
/// Input: byte array B ∈ B^{64·η} <br>
/// Output: array f ∈ `Z^{256}_q`
#[must_use]
pub(crate) fn sample_poly_cbd(eta: u32, byte_array_b: &[u8]) -> [Z; 256] {
    debug_assert_eq!(byte_array_b.len(), 64 * eta as usize, "Alg 7: byte array not 64 * eta");
    let mut array_f: [Z; 256] = [Z::default(); 256];
    let mut temp = 0;
    let mut int_index = 0;
    let mut bit_index = 0;
    for byte in byte_array_b {
        temp |= u32::from(*byte) << bit_index;
        bit_index += 8;
        while bit_index >= 2 * (eta as usize) {
            let tmask_x = temp & ((1 << eta) - 1);
            let x = count_ones(tmask_x);
            let tmask_y = (temp >> eta) & ((1 << eta) - 1);
            let y = count_ones(tmask_y);
            let (mut xx, mut yy) = (Z::default(), Z::default());
            xx.set_u16(x);
            yy.set_u16(y);
            array_f[int_index] = xx.sub(yy);
            bit_index -= 2 * (eta as usize);
            temp >>= 2 * (eta as usize);
            int_index += 1;
        }
    }
    array_f
}


// the u types below and above could use a bit more thought
// Count u8 ones in constant time (u32 helps perf)
#[allow(clippy::cast_possible_truncation)] // return res as u16
fn count_ones(x: u32) -> u16 {
    let (mut res, mut x) = (x & 0xFF, x & 0xFF);
    for _i in 1..8 {
        x >>= 1;
        res -= x;
    }
    res as u16
}


// The original pseudocode for Algorithm 7 follows...
// Algorithm 7 `SamplePolyCBDη(B)` on page 20.
// If the input is a stream of uniformly random bytes, outputs a sample from the distribution `D_η(R_q)`.
//
// Input: byte array B ∈ B^{64·η}
// Output: array f ∈ Z^{256}_q
// 1: b ← BytesToBits(B)
// 2: for (i ← 0; i < 256; i ++)
// 3:   x ← ∑_{j=0}^{η-1} b[2iη + j] //
// 4:   y ← ∑_{j=0}^{η-1} b[2iη + η + j]
// 5:   f [i] ← x − y mod q
// 6: end for
// 7: return f
// }
