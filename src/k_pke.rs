use rand_core::CryptoRngCore;

use crate::byte_fns::{byte_decode, byte_encode};
use crate::helpers::{
    compress, decompress, dot_t_prod, ensure, g, mat_t_vec_mul, mat_vec_mul, prf, vec_add, xof,
};
use crate::ntt::{ntt, ntt_inv};
use crate::sampling::{sample_ntt, sample_poly_cbd};
use crate::types::Z;

/// Algorithm 12 `K-PKE.KeyGen()` on page 26.
/// Generates an encryption key and a corresponding decryption key.
///
/// Output: encryption key `ekPKE ∈ B^{384·k+32}` <br>
/// Output: decryption key `dkPKE ∈ B^{384·k}`
#[allow(clippy::similar_names, clippy::module_name_repetitions)]
pub fn k_pke_key_gen<const K: usize, const ETA1_64: usize>(
    rng: &mut impl CryptoRngCore, eta1: u32, ek_pke: &mut [u8], dk_pke: &mut [u8],
) -> Result<(), &'static str> {
    ensure!(ek_pke.len() == 384 * K + 32, "Alg12: ek_pke not 384 * K + 32");
    ensure!(dk_pke.len() == 384 * K, "Alg12: dk_pke not 384 * K");

    // 1: d ←− B^{32}                   ▷ d is 32 random bytes (see Section 3.3)
    let mut d = [0u8; 32];
    rng.try_fill_bytes(&mut d)
        .map_err(|_| "Alg12: random number generator failed")?;

    // 2: 2: (ρ, σ) ← G(d)             ▷ expand to two pseudorandom 32-byte seeds
    let (rho, sigma) = g(&[&d]);

    // 3: 3: N ← 0
    let mut n = 0;
    let mut a_hat = [[[Z::default(); 256]; K]; K];

    // 4: for (i ← 0; i < k; i++)        ▷ generate matrix A ∈ (Z^{256}_q)^{k×k}
    for (i, row) in a_hat.iter_mut().enumerate().take(K) {
        //
        // 5: for (j ← 0; j < k; j++)
        for (j, entry) in row.iter_mut().enumerate().take(K) {
            //
            // 6: A_hat[i, j] ← SampleNTT(XOF(ρ, i, j))     ▷ each entry of Â uniform in NTT domain
            // See page 21 regarding transpose of i, j -? j, i in XOF() https://csrc.nist.gov/files/pubs/fips/203/ipd/docs/fips-203-initial-public-comments-2023.pdf
            *entry = sample_ntt(xof(&rho, u8::try_from(j).unwrap(), u8::try_from(i).unwrap()));

            // 7: end for
        }
        // 8: end for
    }

    let mut s = [[Z::default(); 256]; K];

    // 9: for (i ← 0; i < k; i ++)          ▷ generate s ∈ (Z_q^{256})^k
    for s_i in s.iter_mut().take(K) {
        //
        // 10: s[i] ← SamplePolyCBDη1(PRFη1(σ, N))     ▷ s[i] ∈ Z^{256}_q sampled from CBD
        *s_i = sample_poly_cbd(eta1, &prf::<ETA1_64>(&sigma, n));

        // 11: N ← N +1
        n += 1;

        // 12: end for
    }

    let mut e = [[Z::default(); 256]; K];

    // 13: for (i ← 0; i < k; i++)                     ▷ generate e ∈ (Z_q^{256})^k
    for e_i in e.iter_mut().take(K) {
        //
        // 14: e[i] ← SamplePolyCBDη1(PRFη1(σ, N))     ▷ e[i] ∈ Z^{256}_q sampled from CBD
        *e_i = sample_poly_cbd(eta1, &prf::<ETA1_64>(&sigma, n));

        // 15: N ← N +1
        n += 1;

        // 16: end for
    }

    let mut s_hat = [[Z::default(); 256]; K];

    // 17: s_hat ← NTT(s)       ▷ NTT is run k times (once for each coordinate of s)
    for i in 0..K {
        s_hat[i] = ntt(&s[i]);
    }
    let mut e_hat = [[Z::default(); 256]; K];

    // 18: ê ← NTT(e)           ▷ NTT is run k times
    for i in 0..K {
        e_hat[i] = ntt(&e[i]);
    }

    // 19: t̂ ← Â ◦ ŝ + ê
    let as_hat = mat_vec_mul(&a_hat, &s_hat);
    let t_hat = vec_add(&as_hat, &e_hat);

    // 20: ek_{PKE} ← ByteEncode12(t̂)∥ρ        ▷ ByteEncode12 is run k times; include seed for Â
    for i in 0..K {
        byte_encode(12, &t_hat[i], &mut ek_pke[i * 384..(i + 1) * 384])?;
    }
    ek_pke[K * 384..].copy_from_slice(&rho);

    // 21: dk_{PKE} ← ByteEncode12(ŝ)          ▷ ByteEncode12 is run k times
    for i in 0..K {
        byte_encode(12, &s_hat[i], &mut dk_pke[i * 384..(i + 1) * 384])?;
    }

    // 22: return (ekPKE , dkPKE )
    Ok(())
}


/// Algorithm 13 `K-PKE.Encrypt(ekPKE , m, r)` on page 27.
/// Uses the encryption key to encrypt a plaintext message using the randomness r.
///
/// Input: encryption key `ekPKE` ∈ `B^{384·k+32}` <br>
/// Input: message `m` ∈ `B^{32}` <br>
/// Input: encryption randomness `r` ∈ `B^{32}` <br>
/// Output: ciphertext `c` ∈ `B^{32(du·k+dv)}` <br>
#[allow(clippy::many_single_char_names, clippy::too_many_arguments)]
pub(crate) fn k_pke_encrypt<const K: usize, const ETA1_64: usize, const ETA2_64: usize>(
    du: u32, dv: u32, eta1: u32, eta2: u32, ek: &[u8], m: &[u8], randomness: &[u8; 32],
    ct: &mut [u8],
) -> Result<(), &'static str> {
    ensure!(ek.len() == 384 * K + 32, "Alg13: ek len not 384 * K + 32");
    ensure!(m.len() == 32, "Alg13: m len not 32");
    ensure!(eta1 as usize * 64 == ETA1_64, "Alg13: const probs 1");
    ensure!(eta2 as usize * 64 == ETA2_64, "Alg13: const probs 2");

    // 1: N ← 0
    let mut n = 0;

    // 2: t̂ ← ByteDecode12 (ekPKE [0 : 384k])
    let mut t_hat = [[Z::default(); 256]; K];
    for i in 0..K {
        byte_decode(12, &ek[384 * i..384 * (i + 1)], &mut t_hat[i])?;
    }

    // 3: 3: ρ ← ekPKE [384k : 384k + 32]           ▷ extract 32-byte seed from ekPKE
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&ek[384 * K..(384 * K + 32)]);
    let mut a_hat = [[[Z::default(); 256]; K]; K];

    // 4: for (i ← 0; i < k; i++)      ▷ re-generate matrix A_hat(Z_q{256})^{k×k}
    for (i, row) in a_hat.iter_mut().enumerate().take(K) {
        //
        // 5: for (j ← 0; j < k; j++)
        for (j, entry) in row.iter_mut().enumerate().take(K) {
            //
            // 6: Â[i, j] ← SampleNTT(XOF(ρ, i, j))
            *entry = sample_ntt(xof(&rho, u8::try_from(j).unwrap(), u8::try_from(i).unwrap()));

            // 7: end for
        }
        // 8: end for
    }

    let mut r = [[Z::default(); 256]; K];

    // 9: for (i ← 0; i < k; i ++)
    for r_i in r.iter_mut().take(K) {
        //
        // 10: r[i] ← SamplePolyCBDη 1 (PRFη 1 (r, N))      ▷ r[i] ∈ Z^{256}_q sampled from CBD
        *r_i = sample_poly_cbd(eta1, &prf::<ETA1_64>(randomness, n));

        // 11: N ← N +1
        n += 1;

        // 12: end for
    }

    let mut e1 = [[Z::default(); 256]; K];

    // 13: for (i ← 0; i < k; i ++)         ▷ generate e1 ∈ (Z_q^{256})^k
    for e1_i in e1.iter_mut().take(K) {
        //
        // 14: e1 [i] ← SamplePolyCBDη2(PRFη2(r, N))        ▷ e1 [i] ∈ Z^{256}_q sampled from CBD
        *e1_i = sample_poly_cbd(eta2, &prf::<ETA2_64>(randomness, n));

        // 15: N ← N +1
        n += 1;

        // 16: end for
    }

    // 17: 17: e2 ← SamplePolyCBDη(PRFη2(r, N))     ▷ sample e2 ∈ Z^{256}_q from CBD
    let e2 = sample_poly_cbd(eta2, &prf::<ETA2_64>(randomness, n));

    // 18: 18: r̂ ← NTT(r)              ▷ NTT is run k times
    let mut r_hat = [[Z::default(); 256]; K];
    for i in 0..K {
        r_hat[i] = ntt(&r[i]);
    }

    // 19: u ← NTT−1 (Â⊺ ◦ r̂) + e1
    let mut u = mat_t_vec_mul(&a_hat, &r_hat);
    for u_i in u.iter_mut().take(K) {
        *u_i = ntt_inv(u_i);
    }
    u = vec_add(&u, &e1);

    // 20: µ ← Decompress1(ByteDecode1(m)))
    let mut mu = [Z::default(); 256];
    byte_decode(1, m, &mut mu)?;
    decompress(1, &mut mu);

    // 21: v ← NTT−1 (t̂⊺ ◦ r̂) + e2 + µ        ▷ encode plaintext m into polynomial v.
    let mut v = ntt_inv(&dot_t_prod(&t_hat, &r_hat));
    v = vec_add(&vec_add(&[v], &[e2]), &[mu])[0];

    // 22: c1 ← ByteEncode_{du}(Compress_{du}(u))       ▷ ByteEncodedu is run k times
    let step = 32 * du as usize;
    for i in 0..K {
        compress(du, &mut u[i]);
        byte_encode(du, &u[i], &mut ct[i * step..(i + 1) * step])?;
    }

    // 23: c2 ← ByteEncode_{dv}(Compress_{dv}(v))
    compress(dv, &mut v);
    byte_encode(dv, &v, &mut ct[K * step..(K * step + 32 * dv as usize)])?;

    // 24: return c ← (c1 ∥ c2 )
    Ok(())
}


/// Algorithm 14 `K-PKE.Decrypt(dkPKE, c)` on page 28.
/// Uses the decryption key to decrypt a ciphertext.
///
/// Input: decryption key `dk_{PKE}` ∈ `B^{384·k}`
/// Input: ciphertext `c` ∈ `B^{32(du·k+dv)}`
/// Output: message `m` ∈ `B^{32}`
pub(crate) fn k_pke_decrypt<const K: usize>(
    du: u32, dv: u32, dk: &[u8], ct: &[u8],
) -> Result<[u8; 32], &'static str> {
    ensure!(dk.len() == 384 * K, "Alg14: dk len not 384 * K");
    ensure!(ct.len() == 32 * (du as usize * K + dv as usize), "Alg14: 32 * (DU * K + DV)");

    // 1: c1 ← c[0 : 32du k]
    let c1 = &ct[0..32 * du as usize * K];

    // 2: c2 ← c[32du k : 32(du*k + dv)]
    let c2 = &ct[32 * du as usize * K..32 * (du as usize * K + dv as usize)];

    // 3: 3: u ← Decompress_{du}(ByteDecode_{du}(c_1))      ▷ ByteDecode_{du} invoked k times
    let mut u = [[Z::default(); 256]; K];
    for i in 0..K {
        byte_decode(du, &c1[32 * du as usize * i..32 * du as usize * (i + 1)], &mut u[i])?;
        decompress(du, &mut u[i]);
    }

    // 4: v ← Decompress_{dv}(ByteDecode_{dv}(c_2))
    let mut v = [Z::default(); 256];
    byte_decode(dv, c2, &mut v)?;
    decompress(dv, &mut v);

    // 5: s_hat ← ByteDecode_{12}(dk_{PKE{)
    let mut s_hat = [[Z::default(); 256]; K];
    for i in 0..K {
        byte_decode(12, &dk[384 * i..384 * (i + 1)], &mut s_hat[i])?;
    }

    // 6: w ← v − NTT−1 (ŝ⊺ ◦ NTT(u))           ▷ NTT−1 and NTT invoked k times
    let mut w = [Z::default(); 256];
    let mut ntt_u = [[Z::default(); 256]; K];
    for i in 0..K {
        ntt_u[i] = ntt(&u[i]);
    }
    let st_ntt_u = dot_t_prod(&s_hat, &ntt_u);
    for _i in 0..K {
        let yy = ntt_inv(&st_ntt_u);
        for i in 0..256 {
            w[i] = v[i].sub(yy[i]);
        }
    }

    // 7: m ← ByteEncode1 (Compress1 (w))       ▷ decode plaintext m from polynomial v
    compress(1, &mut w);
    let mut m = [0u8; 32];
    byte_encode(1, &w, &mut m)?;

    // 8: return m
    Ok(m)
}


#[cfg(test)]
mod tests {
    use rand_core::SeedableRng;

    use crate::k_pke::{k_pke_decrypt, k_pke_encrypt, k_pke_key_gen};

    #[test]
    #[allow(clippy::similar_names)]
    fn test_result_errs() {
        const ETA1: u32 = 3;
        const ETA2: u32 = 2;
        const DU: u32 = 10;
        const DV: u32 = 4;
        const K: usize = 2;
        const ETA1_64: usize = ETA1 as usize * 64;
        const ETA2_64: usize = ETA2 as usize * 64;
        const EK_LEN: usize = 800;
        const DK_LEN: usize = 1632;
        const CT_LEN: usize = 768;

        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(123);
        let mut ek = [0u8; EK_LEN];
        let mut dk = [0u8; DK_LEN];
        let mut ct = [0u8; CT_LEN];
        let m = [0u8; 32];
        let r = [0u8; 32];


        let pkg = k_pke_key_gen::<K, ETA1_64>;
        let res = pkg(&mut rng, ETA1, &mut ek, &mut dk[0..384 * K]);
        assert!(res.is_ok());

        let mut bad_ek = [0u8; EK_LEN + 1];
        let res = pkg(&mut rng, ETA1, &mut bad_ek, &mut dk);
        assert!(res.is_err());

        let mut bad_dk = [0u8; DK_LEN + 1];
        let res = pkg(&mut rng, ETA1, &mut ek, &mut bad_dk);
        assert!(res.is_err());


        let pke = k_pke_encrypt::<K, ETA1_64, ETA2_64>;
        let res = pke(DU, DV, ETA1, ETA2, &ek, &m, &r, &mut ct);
        assert!(res.is_ok());

        let res = pke(DU, DV, ETA1, ETA2, &bad_ek, &m, &r, &mut ct);
        assert!(res.is_err());

        let bad_m = [0u8; 99];
        let res = pke(DU, DV, ETA1, ETA2, &ek, &bad_m, &r, &mut ct);
        assert!(res.is_err());

        let ff_ek = [0xFFu8; 384 * 2 + 32]; // oversized values
        let res = pke(DU, DV, ETA1, ETA2, &ff_ek, &m, &r, &mut ct);
        assert!(res.is_err());

        let bad_m = [0u8; 32 + 1];
        let res = pke(DU, DV, ETA1, ETA2, &ek, &bad_m, &r, &mut ct);
        assert!(res.is_err());

        let res = pke(DU, DV, ETA1 + 1, ETA2, &ek, &m, &r, &mut ct);
        assert!(res.is_err());

        let res = pke(DU, DV, ETA1, ETA2 + 2, &ek, &m, &r, &mut ct);
        assert!(res.is_err());


        let pkd = k_pke_decrypt::<K>;
        let res = pkd(DU, DV, &dk[0..384 * K], &ct);
        assert!(res.is_ok());

        let res = pkd(DU, DV, &dk, &ct);
        assert!(res.is_err());

        let bad_ct = [0u8; CT_LEN + 1];
        let res = pkd(DU, DV, &dk[0..384 * K], &bad_ct);
        assert!(res.is_err());
    }
}
