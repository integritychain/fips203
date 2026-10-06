use crate::types::Z;
use crate::{Q, ZETA};


/// Algorithm 9 `NTT(f)` on page 26.
/// Computes the Number Theoretic Transform (NTT) representation `f_hat` of the given polynomial `f ∈ R_q`.
///
/// Input: array `f ∈ Z^{256}_q`    ▷ Coefficients of the input polynomial in standard basis
/// Output: array `f_hat ∈ Z^{256}_q`    ▷ Coefficients in NTT basis (frequency domain)
///
/// Computed in place: `f_hat` holds `f` on entry and `f_hat` on return. Returning nothing by value
/// leaves no copy of a secret input or output behind (FIPS 203 §3.3).
#[allow(clippy::module_name_repetitions)]
pub(crate) fn ntt(f_hat: &mut [Z; 256]) {
    //
    // 1: f_hat ← f    ▷ in place, see above

    // 2: i ← 1
    let mut i = 1;

    // 3: for (len ← 128; len ≥ 2; len ← len/2)
    for len in [128, 64, 32, 16, 8, 4, 2] {
        //
        // 4: for (start ← 0; start < 256; start ← start + 2 · len)
        for start in (0..256).step_by(2 * len) {
            //
            // 5: zeta ← ζ^{BitRev_7(i)} mod q
            let zeta = ZETA_TABLE[i << 1];

            // 6: i ← i + 1
            i += 1;

            // 7: for ( j ← start; j < start + len; j ++)
            for j in start..(start + len) {
                //
                // 8: t ← zeta · f_hat[j + len]    ▷ steps 8-10 done modulo q
                let t = f_hat[j + len].mul(zeta);

                // 9: f_hat[j + len] ← f_hat [j] − t
                f_hat[j + len] = f_hat[j].sub(t);

                // 10: f_hat[j] ← f_hat[j] + t
                f_hat[j] = f_hat[j].add(t);

                // 11: end for
            }

            // 12: end for
        }

        // 13: end for
    }

    // 14: return f_hat    ▷ in place
}


/// Algorithm 10 `NTTinv(f)` on page 26.
/// Computes the inverse NTT to convert from NTT representation back to standard polynomial form.
///
/// Input: array `f_hat ∈ Z^{256}`    ▷ Coefficients in NTT basis (frequency domain)
/// Output: array `f ∈ Z^{256}`    ▷ Coefficients of the polynomial in standard basis
///
/// Computed in place: `f` holds `f_hat` on entry and `f` on return, for the same reason as `ntt`.
#[allow(clippy::module_name_repetitions)]
pub(crate) fn ntt_inv(f: &mut [Z; 256]) {
    //
    // 1: f ← f_hat    ▷ in place, see above

    // 2: i ← 127
    let mut i = 127;

    // 3: for (len ← 2; len ≤ 128; len ← 2 · len)
    for len in [2, 4, 8, 16, 32, 64, 128] {
        //
        // 4: for (start ← 0; start < 256; start ← start + 2 · len)
        for start in (0..256).step_by(2 * len) {
            //
            // 5: zeta ← ζ^{BitRev_7(i)} mod q
            let zeta = ZETA_TABLE[i << 1];

            // 6: i ← i − 1
            i -= 1;

            // 7: for ( j ← start; j < start + len; j ++)
            for j in start..(start + len) {
                //
                // 8: t ← f[j]
                let t = f[j];

                // 9: f[j] ← t + f[j + len]    ▷ steps 9-10 done modulo q
                f[j] = t.add(f[j + len]);

                // 10: f[j + len] ← zeta · ( f[j + len] − t)
                f[j + len] = zeta.mul(f[j + len].sub(t));

                // 11: end for
            }

            // 12: end for
        }

        // 13: end for
    }

    // 14: f ← f · 3303 mod q    ▷ multiply every entry by 3303 ≡ 128^{−1} mod q
    let mut z3303 = Z::default();
    z3303.set_u16(3303);
    for item in f.iter_mut() {
        *item = item.mul(z3303);
    }

    // 15: return f    ▷ in place
}


/// Algorithm 11 `MultiplyNTTs(f_hat, g_hat)` on page 27, fused with the addition that follows it at
/// every call site: `h_hat ← h_hat + MultiplyNTTs(f_hat, g_hat)`.
/// Performs polynomial multiplication efficiently by multiplying NTT representations pointwise.
///
/// Input: Two arrays `f_hat ∈ Z^{256}_q` and `g_hat ∈ Z^{256}_q`    ▷ Coefficients of two polynomials in NTT basis
/// Input/Output: An array `h_hat ∈ Z^{256}_q`    ▷ Their product in NTT basis is added to it
///
/// Accumulating in place means no product is held in a temporary or returned by value, so no
/// copy of one is left behind (FIPS 203 §3.3).
pub(crate) fn multiply_ntts_acc(h_hat: &mut [Z; 256], f_hat: &[Z; 256], g_hat: &[Z; 256]) {
    //
    // for (i ← 0; i < 128; i ++)
    for i in 0..128 {
        //
        // 2: (h_hat[2i], h_hat[2i + 1]) ← BaseCaseMultiply(f_hat[2i], f_hat[2i + 1], g_hat[2i], g_hat[2i + 1], ζ^{2BitRev7(i) + 1})
        let zt = ZETA_TABLE[i ^ 0x80];
        let (h_hat_2i, h_hat_2ip1) =
            base_case_multiply(f_hat[2 * i], f_hat[2 * i + 1], g_hat[2 * i], g_hat[2 * i + 1], zt);
        h_hat[2 * i] = h_hat[2 * i].add(h_hat_2i);
        h_hat[2 * i + 1] = h_hat[2 * i + 1].add(h_hat_2ip1);

        // 3: end for
    }

    // 4: return h_hat    ▷ in place
}


/// Algorithm 12 `BaseCaseMultiply(a0, a1, b0, b1, gamma)` on page 27.
/// Multiplies two degree-one polynomials modulo `X^2 - γ`.
///
/// Input: `a0, a1, b0, b1 ∈ Z_q`    ▷ Coefficients of `a0 + a1X` and `b0 + b1X`
/// Input: `γ ∈ Z_q`    ▷ Defines the modulus `X^2 - γ`
/// Output: `(c0, c1)` where `c0, c1 ∈ Z_q`    ▷ Coefficients of the resulting product polynomial
#[must_use]
pub(crate) fn base_case_multiply(a0: Z, a1: Z, b0: Z, b1: Z, gamma: Z) -> (Z, Z) {
    // 1: c0 ← a0 · b0 + a1 · b1 · γ    ▷ steps 1-2 done modulo q
    let c0 = a0.base_mul(a1, b0, b1, gamma);

    // 2: c1 ← a0 · b1 + a1 · b0
    let c1 = a0.base_mul2(a1, b0, b1);

    // 3: return c0, c1
    (c0, c1)
}


// ----------
// The functionality below calculates the Zeta array at compile-time. Thus, not particularly optimal or CT.

#[must_use]
#[allow(clippy::cast_possible_truncation)] // const fns cannot use u32::from() etc...
const fn gen_zeta_table() -> [Z; 256] {
    let mut result = [Z(0); 256];
    let mut x = 1u32;
    let mut i = 0u32;
    while i < 256 {
        result[(i as u8).reverse_bits() as usize] = Z(x as u16); // as u16;
        x = (x * (ZETA as u32)) % (Q as u32);
        i += 1;
    }
    result
}

pub(crate) static ZETA_TABLE: [Z; 256] = gen_zeta_table();


#[cfg(test)]
mod tests {
    use crate::ntt::gen_zeta_table;
    use crate::traits::SerDes;
    use crate::SharedSecretKey;

    #[test]
    fn test_zeta_misc() {
        let res = gen_zeta_table();
        assert_eq!(res[4].0, 2580);

        let ssk_bytes = [0u8; 32];
        let ssk = SharedSecretKey::try_from_bytes(ssk_bytes);
        assert!(ssk.is_ok());
    }
}
