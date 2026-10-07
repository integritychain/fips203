use crate::ntt::multiply_ntts_acc;
use crate::types::Z;
use crate::Q;
use sha3::digest::core_api::{
    Buffer, ExtendableOutputCore, FixedOutputCore, UpdateCore, XofReaderCore,
};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Sha3_256, Sha3_512Core, Shake128, Shake256Core};
use zeroize::Zeroize;


/// If the condition is not met, return an error message. Borrowed from the `anyhow` crate.
macro_rules! ensure {
    ($cond:expr, $msg:literal $(,)?) => {
        if !$cond {
            return Err($msg);
        }
    };
}

pub(crate) use ensure; // make available throughout crate


// The vector helpers below work in place on caller-provided buffers and return nothing by value.
// A value returned by value can leave a copy in the callee's stack frame that no wipe can reach, so
// this is what lets the K-PKE functions destroy their intermediate values (FIPS 203 §3.3).

/// Polynomial addition in place: `poly_a` ← `poly_a` + `poly_b`
pub(crate) fn add_poly(poly_a: &mut [Z; 256], poly_b: &[Z; 256]) {
    for (a, b) in poly_a.iter_mut().zip(poly_b) {
        *a = a.add(*b);
    }
}


/// Vector addition in place; See commentary on 2.11 page 10: `vec_a` ← `vec_a` + `vec_b`
///
/// # Arguments
/// * `vec_a` - First vector of size K×256, which receives the element-wise sum
/// * `vec_b` - Second vector of size K×256
pub(crate) fn add_vecs<const K: usize>(vec_a: &mut [[Z; 256]; K], vec_b: &[[Z; 256]; K]) {
    for (a, b) in vec_a.iter_mut().zip(vec_b) {
        add_poly(a, b);
    }
}


/// Matrix by vector multiplication; See commentary on 2.12 page 10: `w_hat` = `A_hat` mul `u_hat`
///
/// # Arguments
/// * `a_hat` - Matrix of size K×K×256
/// * `u_hat` - Vector of size K×256
/// * `w_hat` - Output vector of size K×256, overwritten with `A_hat * u_hat`
pub(crate) fn mul_mat_vec<const K: usize>(
    a_hat: &[[[Z; 256]; K]; K], u_hat: &[[Z; 256]; K], w_hat: &mut [[Z; 256]; K],
) {
    for i in 0..K {
        w_hat[i].fill(Z::default());
        #[allow(clippy::needless_range_loop)] // alternative is harder to understand
        for j in 0..K {
            multiply_ntts_acc(&mut w_hat[i], &a_hat[i][j], &u_hat[j]);
        }
    }
}


/// Matrix transpose by vector multiplication; See commentary on 2.13 page 10: `y_hat` = `A_hat^T` mul `u_hat`
///
/// # Arguments
/// * `a_hat` - Matrix of size K×K×256 to be transposed before multiplication
/// * `u_hat` - Vector of size K×256
/// * `y_hat` - Output vector of size K×256, overwritten with `A_hat^T * u_hat`, where `^T` denotes transpose
pub(crate) fn mul_mat_t_vec<const K: usize>(
    a_hat: &[[[Z; 256]; K]; K], u_hat: &[[Z; 256]; K], y_hat: &mut [[Z; 256]; K],
) {
    #[allow(clippy::needless_range_loop)] // alternative is harder to understand
    for i in 0..K {
        y_hat[i].fill(Z::default());
        #[allow(clippy::needless_range_loop)] // alternative is harder to understand
        for j in 0..K {
            multiply_ntts_acc(&mut y_hat[i], &a_hat[j][i], &u_hat[j]); // i,j swapped vs above fn
        }
    }
}


/// Vector dot product; See commentary on 2.14 page 10: `z_hat` = `u_hat^T` mul `v_hat`
///
/// # Arguments
/// * `u_hat` - First vector of size K×256
/// * `v_hat` - Second vector of size K×256
/// * `z_hat` - Output 256-element array, overwritten with the sum of element-wise products
pub(crate) fn dot_t_prod<const K: usize>(
    u_hat: &[[Z; 256]; K], v_hat: &[[Z; 256]; K], z_hat: &mut [Z; 256],
) {
    z_hat.fill(Z::default());
    for j in 0..K {
        multiply_ntts_acc(z_hat, &u_hat[j], &v_hat[j]);
    }
}


/// Function PRF on page 18 (4.3).
/// Pseudorandom function that generates `ETA_64` bytes of output using SHAKE256
///
/// # Arguments
/// * `s` - 32-byte seed
/// * `b` - Single byte domain separator
/// * `out` - Output buffer for the `ETA_64` bytes
pub(crate) fn prf<const ETA_64: usize>(s: &[u8; 32], b: u8, out: &mut [u8; ETA_64]) {
    shake256_wiped(&[s, &[b]], out);
    scrub_hash_stack();
}


/// SHAKE256 over the concatenation of `inputs`, squeezed into `out`, for the secret inputs of PRF
/// and J. It absorbs through the `core_api`, with no wrapper to move or copy, so that the block
/// buffer (which keeps the unprocessed tail of the input, e.g. sigma || N) and each squeezed block
/// can be wiped (FIPS 203 §3.3). The Keccak state is wiped on drop by the sha3 `zeroize` feature.
/// Callers follow it with `scrub_hash_stack()`, so it must not be inlined.
#[inline(never)]
fn shake256_wiped(inputs: &[&[u8]], out: &mut [u8]) {
    let mut core = Shake256Core::default();
    let mut buffer = Buffer::<Shake256Core>::default();
    for i in inputs {
        buffer.digest_blocks(i, |blocks| core.update_blocks(blocks));
    }
    let mut reader = core.finalize_xof_core(&mut buffer);
    buffer.pad_with_zeros().as_mut_slice().zeroize();
    for chunk in out.chunks_mut(136) {
        let mut block = reader.read_block();
        chunk.copy_from_slice(&block[..chunk.len()]);
        block.as_mut_slice().zeroize();
    }
}


/// Overwrites the stack area that `shake256_wiped()` or `sha3_512_wiped()` just used. sha3 0.10
/// returns each squeezed block by value and permutes on stack copies of the state, so its own
/// frames can still hold secret-derived bytes that no wipe in this crate can reach (FIPS 203 §3.3).
/// It is called from the same frame as the hash function, so this frame overlays the hash's.
#[inline(never)]
fn scrub_hash_stack() {
    // 2 KiB, wiped a word at a time. It covers the hash frames of an optimized build (≤ 1.3 KiB
    // measured on x86_64), but not those of an unoptimized one (about 20 KiB).
    let mut area = [0u64; 256];
    area.zeroize();
    let _ = core::hint::black_box(&area);
}


/// Function XOF on page 19 (4.6), used with 32-byte `rho`
/// Expandable output function based on SHAKE128 for generating matrix elements
///
/// # Arguments
/// * `rho` - 32-byte seed for randomness
/// * `i` - Row index for matrix generation
/// * `j` - Column index for matrix generation
///
/// # Returns
/// An extendable output reader that can generate arbitrary length output
#[must_use]
pub(crate) fn xof(rho: &[u8; 32], i: u8, j: u8) -> impl XofReader {
    //debug_assert_eq!(rho.len(), 32);
    let mut hasher = Shake128::default();
    hasher.update(rho);
    hasher.update(&[i]);
    hasher.update(&[j]);
    hasher.finalize_xof()
}


/// Function G on page 19 (4.5).
/// Hash function that produces two 32-byte outputs from variable input
///
/// # Arguments
/// * `bytes` - Slice of byte slices to be hashed together
/// * `a`, `b` - Output buffers for the two 32-byte halves: (ρ, σ) in K-PKE.KeyGen, or (K, r) in
///   encapsulation and decapsulation
pub(crate) fn g(bytes: &[&[u8]], a: &mut [u8; 32], b: &mut [u8; 32]) {
    sha3_512_wiped(bytes, a, b);
    scrub_hash_stack();
}


/// SHA3-512 of the concatenation of `bytes`, split into `a` and `b`, for G. It absorbs and finalizes
/// through the `core_api`, with no wrapper to move or copy, so that the block buffer (which keeps
/// the tail of the secret input d || k or m || H(ek)) and the digest can be wiped (FIPS 203 §3.3).
/// The Keccak state is wiped on drop by the sha3 `zeroize` feature. The outputs go into the
/// caller's buffers rather than being returned by value. Callers follow it with
/// `scrub_hash_stack()`, so it must not be inlined.
#[inline(never)]
fn sha3_512_wiped(bytes: &[&[u8]], a: &mut [u8; 32], b: &mut [u8; 32]) {
    let mut core = Sha3_512Core::default();
    let mut buffer = Buffer::<Sha3_512Core>::default();
    for x in bytes {
        buffer.digest_blocks(x, |blocks| core.update_blocks(blocks));
    }
    let mut digest = sha3::digest::Output::<Sha3_512Core>::default();
    core.finalize_fixed_core(&mut buffer, &mut digest);
    buffer.pad_with_zeros().as_mut_slice().zeroize();
    a.copy_from_slice(&digest[0..32]);
    b.copy_from_slice(&digest[32..64]);
    digest.as_mut_slice().zeroize();
}


/// Function H on page 18 (4.4).
/// Hash function that produces a single 32-byte output
///
/// # Arguments
/// * `bytes` - Input bytes to hash (typically public key)
///
/// # Returns
/// 32-byte array representing the hash
#[must_use]
pub(crate) fn h(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, bytes);
    let digest = hasher.finalize();
    digest.into()
}


/// Function J on page 18 (4.4).
/// XOF-based hash function that derives the implicit-rejection key K̄ = J(z ‖ c) in decapsulation
///
/// # Arguments
/// * `z` - 32-byte seed
/// * `ct` - Variable length ciphertext
/// * `out` - Output buffer for the 32-byte implicit-rejection key K̄ derived from inputs
pub(crate) fn j(z: &[u8; 32], ct: &[u8], out: &mut [u8; 32]) {
    shake256_wiped(&[z, ct], out);
    scrub_hash_stack();
}


/// `Compress<d>` from page 21 (4.7).
/// x → ⌈(2^d/q) · x⌋ mod 2^d
///
/// This function compresses elements from `Z_q` to a smaller range by scaling them down.
/// The compression is lossy but maintains approximate ratios between elements.
///
/// # Arguments
/// * `d` - Compression parameter that determines output range (1 to 11)
/// * `inout` - Vector of elements to compress in-place
///
/// # Implementation Notes
/// * Works for all odd q values from 17 to 6307
/// * Input x must be in range 0 to q-1
/// * Uses pre-computed multiplier M to avoid floating-point arithmetic
/// * Does not reduce mod 2^d: inputs near q give 2^d, which `byte_encode` masks to 0
#[allow(clippy::cast_possible_truncation)]
pub(crate) fn compress_vector(d: u32, inout: &mut [Z]) {
    const M: u32 = (1u64 << 36).div_ceil(Q as u64) as u32;
    for x_ref in &mut *inout {
        let y = (x_ref.get_u32() << d) + (u32::from(Q) >> 1);
        let result = (u64::from(y) * u64::from(M)) >> 36;
        x_ref.set_u16(result as u16);
    }
}


/// `Decompress<d>` from page 21 (4.8).
/// y → ⌈(q/2^d) · y⌋
///
/// Inverse operation of `compress_vector` that expands compressed elements back to `Z_q`.
/// While not perfect due to lossy compression, attempts to restore original ratios.
///
/// # Arguments
/// * `d` - Same compression parameter used in `compress_vector`
/// * `inout` - Vector of compressed elements to decompress in-place
#[allow(clippy::cast_possible_truncation)]
pub(crate) fn decompress_vector(d: u32, inout: &mut [Z]) {
    for y_ref in &mut *inout {
        let qy = u32::from(Q) * y_ref.get_u32() + (1 << (d - 1)); // round(q*y / 2^d), halves up
        y_ref.set_u16((qy >> d) as u16);
    }
}


#[cfg(test)]
mod tests {
    use crate::helpers::{compress_vector, decompress_vector};
    use crate::types::Z;
    use crate::Q;

    // FIPS 203 eq. (4.7) and (4.8), rounding per §2.3 (halves up), in exact integer arithmetic:
    // round(a / b) = floor((2a + b) / 2b).
    fn spec_compress(d: u32, x: u32) -> u32 {
        ((x << (d + 1)) + u32::from(Q)) / (2 * u32::from(Q)) % (1 << d)
    }

    fn spec_decompress(d: u32, y: u32) -> u32 { (2 * u32::from(Q) * y + (1 << d)) >> (d + 1) }

    // [Z(0), Z(1), ..., Z(4095)]; each test uses a prefix, so no allocation is needed.
    fn zs() -> [Z; 4096] { core::array::from_fn(|i| Z(u16::try_from(i).unwrap())) }

    fn decompress(d: u32, y: u16) -> u32 {
        let mut a = [Z(y)];
        decompress_vector(d, &mut a);
        a[0].get_u32()
    }

    fn compress(d: u32, x: u16) -> u32 {
        let mut a = [Z(x)];
        compress_vector(d, &mut a);
        a[0].get_u32() % (1 << d)
    }

    #[test]
    fn decompress_exhaustive() {
        for d in 1..=11 {
            let mut a = zs();
            let v = &mut a[..1 << d];
            decompress_vector(d, v);
            for (y, z) in v.iter().enumerate() {
                let y = u32::try_from(y).unwrap();
                assert_eq!(z.get_u32(), spec_decompress(d, y), "Decompress_{d}({y})");
            }
        }
        // Hand-computed values: round(3329/16), round(3329/4), round(1664.5) (a tie, rounds up)
        assert_eq!(decompress(4, 1), 208);
        assert_eq!(decompress(2, 1), 832);
        assert_eq!(decompress(11, 1024), 1665);
    }

    #[test]
    fn compress_exhaustive() {
        for d in 1..=11 {
            let mut a = zs();
            let v = &mut a[..usize::from(Q)];
            compress_vector(d, v);
            for (x, z) in v.iter().enumerate() {
                let x = u32::try_from(x).unwrap();
                assert_eq!(z.get_u32() % (1 << d), spec_compress(d, x), "Compress_{d}({x})");
            }
        }
        // Hand-computed values: the Compress_1 decision boundaries near q/4 and 3q/4
        assert_eq!(compress(1, 832), 0);
        assert_eq!(compress(1, 833), 1);
        assert_eq!(compress(1, 2496), 1);
        assert_eq!(compress(1, 2497), 0);
    }

    // FIPS 203 §4.2.1: Compress_d(Decompress_d(y)) = y for all y in Z_{2^d} and all d < 12
    #[test]
    fn compress_decompress_roundtrip() {
        for d in 1..=11 {
            let mut a = zs();
            let v = &mut a[..1 << d];
            decompress_vector(d, v);
            compress_vector(d, v);
            for (y, z) in v.iter().enumerate() {
                let y = u32::try_from(y).unwrap();
                assert_eq!(z.get_u32() % (1 << d), y, "Compress_{d}(Decompress_{d}({y}))");
            }
        }
    }
}
