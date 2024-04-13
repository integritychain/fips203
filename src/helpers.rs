use crate::ntt::multiply_ntts;
use crate::types::Z;
use crate::Q;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Sha3_256, Sha3_512, Shake128, Shake256};


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
pub(crate) fn add_vecs<const K: usize>(
    vec_a: &[[Z; 256]; K], vec_b: &[[Z; 256]; K],
) -> [[Z; 256]; K] {
    let mut result = [[Z::default(); 256]; K];
    for i in 0..K {
        for n in 0..256 {
            result[i][n] = vec_a[i][n].add(vec_b[i][n]);
        }
    }
    result
}


/// Matrix by vector multiplication; See top of page 10, first row: `w_hat` = `A_hat` mul `u_hat`
#[must_use]
pub(crate) fn mul_mat_vec<const K: usize>(
    a_hat: &[[[Z; 256]; K]; K], u_hat: &[[Z; 256]; K],
) -> [[Z; 256]; K] {
    let mut w_hat = [[Z::default(); 256]; K];
    for i in 0..K {
        #[allow(clippy::needless_range_loop)] // alternative is harder to understand
        for j in 0..K {
            let tmp = multiply_ntts(&a_hat[i][j], &u_hat[j]);
            for n in 0..256 {
                w_hat[i][n] = w_hat[i][n].add(tmp[n]);
            }
        }
    }
    w_hat
}


/// Matrix transpose by vector multiplication; See top of page 10, second row: `y_hat` = `A_hat^T` mul `u_hat`
#[must_use]
pub(crate) fn mul_mat_t_vec<const K: usize>(
    a_hat: &[[[Z; 256]; K]; K], u_hat: &[[Z; 256]; K],
) -> [[Z; 256]; K] {
    let mut y_hat = [[Z::default(); 256]; K];
    #[allow(clippy::needless_range_loop)] // alternative is harder to understand
    for i in 0..K {
        #[allow(clippy::needless_range_loop)] // alternative is harder to understand
        for j in 0..K {
            let tmp = multiply_ntts(&a_hat[j][i], &u_hat[j]);
            for n in 0..256 {
                y_hat[i][n] = y_hat[i][n].add(tmp[n]);
            }
        }
    }
    y_hat
}


/// Vector dot product; See top of page 10, third row: `z_hat` = `u_hat^T` mul `v_hat`
#[must_use]
pub(crate) fn dot_t_prod<const K: usize>(u_hat: &[[Z; 256]; K], v_hat: &[[Z; 256]; K]) -> [Z; 256] {
    let mut result = [Z::default(); 256];
    for j in 0..K {
        let tmp = multiply_ntts(&u_hat[j], &v_hat[j]);
        for n in 0..256 {
            result[n] = result[n].add(tmp[n]);
        }
    }
    result
}


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


/// Function XOF on page 16 (4.2), used with 32-byte `rho`
#[must_use]
pub(crate) fn xof(rho: &[u8; 32], i: u8, j: u8) -> impl XofReader {
    //debug_assert_eq!(rho.len(), 32);
    let mut hasher = Shake128::default();
    hasher.update(rho);
    hasher.update(&[i]);
    hasher.update(&[j]);
    hasher.finalize_xof()
}


/// Function G on page 17 (4.4). <br>
/// `g()` is utilized in several different fashions: on a single array as well
/// as on two concatenated arrays. The single signature here has sufficient
/// flexibility for reuse and avoiding an unnecessary prior concatenation.
pub(crate) fn g(bytes: &[&[u8]]) -> ([u8; 32], [u8; 32]) {
    let mut hasher = Sha3_512::new();
    bytes.iter().for_each(|b| Digest::update(&mut hasher, b));
    let digest = hasher.finalize();
    let a = digest[0..32].try_into().expect("g_a fail");
    let b = digest[32..64].try_into().expect("g_b fail");
    (a, b)
}


/// Function H on page 17 (4.3). <br>
/// `h()` is used on a variable-length ek, so the signature here is a slice.
#[must_use]
pub(crate) fn h(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, bytes);
    let digest = hasher.finalize();
    digest.into()
}


/// Function J n page 17 (4.4). <br>
/// `j()` is similar to `g()` above in that the second operand is a variable
/// length `ct`. The signature here is for ease of use.
#[must_use]
pub(crate) fn j(z: &[u8; 32], ct: &[u8]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(z);
    hasher.update(ct);
    let mut reader = hasher.finalize_xof();
    let mut result = [0u8; 32];
    reader.read(&mut result);
    result
}


/// Compress<d> from page 18 (4.5).
/// x → ⌈(2^d/q) · x⌋
/// `d` comes from fixed security parameter, `inout` saves some allocation.
/// This works for all odd q = 17 to 6307, d = 0 to 11, and x = 0 to q-1.
#[allow(clippy::cast_possible_truncation)] // last line (and const)
pub(crate) fn compress_vector(d: u32, inout: &mut [Z]) {
    const M: u32 = (((1u64 << 36) + Q as u64 - 1) / Q as u64) as u32;
    for x_ref in &mut *inout {
        let y = (x_ref.get_u32() << d) + (u32::from(Q) >> 1);
        let result = (u64::from(y) * u64::from(M)) >> 36;
        x_ref.set_u16(result as u16);
    }
}


/// Decompress<d> from page 18 (4.6).
/// y → ⌈(q/2^d) · y⌋
/// `d` comes from fixed security parameter, `inout` saves some allocation
#[allow(clippy::cast_possible_truncation)] // last line
pub(crate) fn decompress_vector(d: u32, inout: &mut [Z]) {
    for y_ref in &mut *inout {
        let qy = u32::from(Q) * y_ref.get_u32() + (1 << d) - 1;
        y_ref.set_u16((qy >> d) as u16);
    }
}
