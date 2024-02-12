use sha3::{Digest, Sha3_256, Sha3_512, Shake128, Shake256};
use sha3::digest::{ExtendableOutput, XofReader};
use sha3::digest::Update;

use crate::ntt::multiply_ntts;
use crate::Q;
use crate::types::Z;

/// If the condition is not met, return an error message. Borrowed from the `anyhow` crate.
macro_rules! ensure {
    ($cond:expr, $msg:literal $(,)?) => {
        if !$cond {
            return Err($msg);
        }
    };
}

pub(crate) use ensure; // make available throughout crate


/// Vector addition; See bottom of page 9, second row: `z_hat` = `u_hat` + `v_hat`
#[must_use]
pub(crate) fn vec_add<const K: usize>(
    vec_a: &[[Z; 256]; K], vec_b: &[[Z; 256]; K],
) -> [[Z; 256]; K] {
    let mut result = [[Z::default(); 256]; K];
    for i in 0..vec_a.len() {
        for j in 0..vec_a[i].len() {
            result[i][j] = vec_a[i][j].add(vec_b[i][j]);
        }
    }
    result
}


/// Matrix by vector multiplication; See top of page 10, first row: `w_hat` = `A_hat` mul `u_hat`
#[must_use]
pub(crate) fn mat_vec_mul<const K: usize>(
    a_hat: &[[[Z; 256]; K]; K], u_hat: &[[Z; 256]; K],
) -> [[Z; 256]; K] {
    let mut w_hat = [[Z::default(); 256]; K];
    #[allow(clippy::needless_range_loop)]
    for i in 0..K {
        #[allow(clippy::needless_range_loop)]
        for j in 0..K {
            let tmp = multiply_ntts(&a_hat[i][j], &u_hat[j]);
            for k in 0..256 {
                w_hat[i][k] = w_hat[i][k].add(tmp[k]);
            }
        }
    }
    w_hat
}


/// Matrix transpose by vector multiplication; See top of page 10, second row: `y_hat` = `A_hat^T` mul `u_hat`
#[must_use]
pub(crate) fn mat_t_vec_mul<const K: usize>(
    a_hat: &[[[Z; 256]; K]; K], u_hat: &[[Z; 256]; K],
) -> [[Z; 256]; K] {
    let mut y_hat = [[Z::default(); 256]; K];
    #[allow(clippy::needless_range_loop)]
    for i in 0..K {
        #[allow(clippy::needless_range_loop)]
        for j in 0..K {
            let tmp = multiply_ntts(&a_hat[j][i], &u_hat[j]);
            for k in 0..256 {
                y_hat[i][k] = y_hat[i][k].add(tmp[k]);
            }
        }
    }
    y_hat
}


/// Vector dot product; See top of page 10, third row: `z_hat` = `u_hat^T` mul `v_hat`
#[must_use]
pub(crate) fn dot_t_prod<const K: usize>(
    u_hat: &[[Z; 256]; K], v_hat: &[[Z; 256]; K],
) -> [Z; 256] {
    let mut result = [Z::default(); 256];
    for j in 0..K {
        let tmp = multiply_ntts(&u_hat[j], &v_hat[j]);
        for k in 0..256 {
            result[k] = result[k].add(tmp[k]);
        }
    }
    result
}

// TODO: update hashers to take list of byte-strings to hash (to save assembly)

/// Function PRF on page 16 (4.1).
#[must_use]
pub(crate) fn prf<const ETA_64: usize>(s: &[u8; 32], b: u8) -> [u8; ETA_64] {
    let mut hasher = Shake256::default();
    hasher.update(s);
    hasher.update(&[b]);
    let mut reader = hasher.finalize_xof();
    let mut result = [0u8; ETA_64];
    reader.read(&mut result);
    result
}


/// Function XOF on page 16 (4.2).
#[must_use]
pub(crate) fn xof(rho: &[u8; 32], i: u8, j: u8) -> impl XofReader {
    let mut hasher = Shake128::default();
    hasher.update(rho);
    hasher.update(&[i]);
    hasher.update(&[j]);
    hasher.finalize_xof()
}


/// Function G on page 17 (4.4).
pub(crate) fn g(bytes: &[&[u8]]) -> ([u8; 32], [u8; 32]) {
    let mut hasher = Sha3_512::new();
    bytes.iter().for_each(|b| Digest::update(&mut hasher, b));
    //Digest::update(&mut hasher, bytes);
    let digest = hasher.finalize();
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a.copy_from_slice(&digest[0..32]);
    b.copy_from_slice(&digest[32..64]);
    (a, b)
}


/// Function H on page 17 (4.3).
#[must_use]
pub(crate) fn h(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, bytes);
    let digest = hasher.finalize();
    digest.into()
}


/// Function J n page 17 (4.4).
#[must_use]
pub(crate) fn j(bytes: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    bytes.iter().for_each(|b| hasher.update(b));
    // hasher.update(bytes);
    let mut reader = hasher.finalize_xof();
    let mut result = [0u8; 32];
    reader.read(&mut result);
    result
}


// BitRev7(i) from page 21 line 839-840 -- REMOVED DUE TO ZETA_TABLE IN ntt.rs


/// Round to nearest  TODO: refine/optimize
fn nearest(numerator: u32, denominator: u32) -> u16 {
    let remainder = numerator % denominator;
    let quotient = u16::try_from(numerator / denominator).unwrap();
    if (2 * remainder) >= denominator {
        quotient + 1
    } else {
        quotient
    }
}


/// Compress<d> from page 18 (4.5).
/// x → ⌈(2^d/q) · x⌋
pub(crate) fn compress(d: u32, inout: &mut [Z]) {
    for x_ref in &mut *inout {
        x_ref.set_u16(nearest(2u32.pow(d) * x_ref.get_u32(), Q));
    }
}


/// Decompress<d> from page 18 (4.6).
/// y → ⌈(q/2^d) · y⌋ .
pub(crate) fn decompress(d: u32, inout: &mut [Z]) {
    for y_ref in &mut *inout {
        y_ref.set_u16(nearest(Q * y_ref.get_u32(), 2u32.pow(d)));
    }
}
