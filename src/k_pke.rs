use crate::byte_fns::{byte_decode, byte_encode};
use crate::helpers::{
    add_poly, add_vecs, compress_vector, decompress_vector, dot_t_prod, g, mul_mat_t_vec,
    mul_mat_vec, prf, xof,
};
use crate::ntt::{ntt, ntt_inv};
use crate::sampling::{sample_ntt, sample_poly_cbd};
use crate::types::Z;
use zeroize::Zeroizing;


/// Algorithm 13 `K-PKE.KeyGen(d)` on page 29.
/// Uses randomness to generate an encryption key and a corresponding decryption key.
///
/// # Parameters
/// * Input: randomness `d ∈ B^{32}` (32-byte random seed)
/// * Output: encryption key `ek_PKE ∈ B^{384·k+32}` (public key)
/// * Output: decryption key `dk_PKE ∈ B^{384·k}` (private key)
#[allow(clippy::similar_names)]
pub(crate) fn k_pke_key_gen<const K: usize, const ETA1_64: usize>(
    d: &[u8; 32], ek_pke: &mut [u8], dk_pke: &mut [u8],
) {
    debug_assert_eq!(ek_pke.len(), 384 * K + 32, "Alg 13: ek_pke not 384 * K + 32");
    debug_assert_eq!(dk_pke.len(), 384 * K, "Alg 13: dk_pke not 384 * K");

    // Secret intermediate values are held in `Zeroizing` buffers, which are wiped when they go out
    // of scope (FIPS 203 §3.3), and the NTTs run in place so no other copies are made.

    // 1: (𝜌, 𝜎) ← G(𝑑 ‖ 𝑘)    ▷ expand 32+1 bytes to two pseudorandom 32-byte seeds
    let mut dk = Zeroizing::new([0u8; 33]); // Last byte is 'final' FIPS 203 fix; 'domain' separator
    dk[0..32].copy_from_slice(d);
    dk[32] = K.to_le_bytes()[0];
    let mut rho = [0u8; 32];
    let mut sigma = Zeroizing::new([0u8; 32]);
    g(&[&dk[..]], &mut rho, &mut sigma);

    // 2: N ← 0
    let mut n = 0;

    // Steps 3-7 in gen_a_hat() below
    let a_hat = gen_a_hat(&rho);

    // 8: for (i ← 0; i < k; i ++)    ▷ generate s ∈ (Z_q^{256})^k
    // 9: s[i] ← SamplePolyCBD_η1(PRFη1(σ, N))    ▷ s[i] ∈ Z^{256}_q sampled from CBD
    // 10: N ← N +1
    // 11: end for
    // (s is sampled into `s_hat`, which step 16 transforms in place)
    let mut prf_out = Zeroizing::new([0u8; ETA1_64]);
    let mut s_hat = Zeroizing::new([[Z::default(); 256]; K]);
    for s_i in s_hat.iter_mut() {
        prf(&sigma, n, &mut prf_out);
        sample_poly_cbd(&prf_out[..], s_i);
        n += 1;
    }

    // 12: for (i ← 0; i < k; i++)    ▷ generate e ∈ (Z_q^{256})^k
    // 13: e[i] ← SamplePolyCBD_η1(PRFη1(σ, N))    ▷ e[i] ∈ Z^{256}_q sampled from CBD
    // 14: N ← N +1
    // 15: end for
    // (e is sampled into `e_hat`, which step 17 transforms in place)
    let mut e_hat = Zeroizing::new([[Z::default(); 256]; K]);
    for e_i in e_hat.iter_mut() {
        prf(&sigma, n, &mut prf_out);
        sample_poly_cbd(&prf_out[..], e_i);
        n += 1;
    }

    // 16: s_hat ← NTT(s)    ▷ NTT is run k times (once for each coordinate of s)
    for s_i in s_hat.iter_mut() {
        ntt(s_i);
    }

    // 17: ê ← NTT(e)    ▷ NTT is run k times
    for e_i in e_hat.iter_mut() {
        ntt(e_i);
    }

    // 18: t̂ ← Â ◦ ŝ + ê
    // (t̂ is public, so the secret partial result Â ◦ ŝ only ever exists in the buffer that becomes t̂)
    let mut t_hat = [[Z::default(); 256]; K];
    mul_mat_vec(&a_hat, &s_hat, &mut t_hat);
    add_vecs(&mut t_hat, &e_hat);

    // 19: ek_PKE ← ByteEncode_12(t̂) ∥ ρ    ▷ run ByteEncode12 𝑘 times, then append 𝐀-seed
    for (i, chunk) in ek_pke.chunks_mut(384).enumerate().take(K) {
        byte_encode(12, &t_hat[i], chunk);
    }
    ek_pke[K * 384..].copy_from_slice(&rho);

    // 20: dk_PKE ← ByteEncode_12(ŝ)    ▷ run ByteEncode12 𝑘 times
    for (i, chunk) in dk_pke.chunks_mut(384).enumerate() {
        byte_encode(12, &s_hat[i], chunk);
    }

    // 21: return (ek_PKE , dk_PKE )
}


/// Shared function for generating matrix `A_hat` used in both:
/// * `k_pke_key_gen()` steps 3-7
/// * `k_pke_encrypt()` steps 4-8
///
/// Returns a `[K][K][256]` matrix of coefficients in NTT domain
fn gen_a_hat<const K: usize>(rho: &[u8; 32]) -> [[[Z; 256]; K]; K] {
    //
    // 3: for (i ← 0; i < k; i++)    ▷ generate matrix A ∈ (Z^{256}_q)^{k×k}
    // 4:   for (j ← 0; j < k; j++)
    // 5:     A_hat[i, j] ← SampleNTT(𝜌‖𝑗‖𝑖)    ▷ 𝑗 and 𝑖 are bytes 33 and 34 of the input
    // 6:   end for
    // 7: end for
    core::array::from_fn(|i| {
        core::array::from_fn(|j| sample_ntt(xof(rho, j.to_le_bytes()[0], i.to_le_bytes()[0])))
    })
}


/// Algorithm 14 `K-PKE.Encrypt(ek_PKE, m, r)` on page 30.
/// Uses the encryption key to encrypt a plaintext message using the randomness `r`.
///
/// # Parameters
/// * Input: encryption key `ek_PKE ∈ B^{384·k+32}` (public key)
/// * Input: message `m ∈ B^{32}` (32-byte message to encrypt)
/// * Input: randomness `r ∈ B^{32}` (32-byte random seed)
/// * Output: ciphertext `c ∈ B^{32(du·k+dv)}` (encrypted message)
///
/// # Parameters
/// * `K`: Number of polynomial vectors
/// * `ETA1_64`: Noise parameter for primary sampling
/// * `ETA2_64`: Noise parameter for secondary sampling
/// * `du`: Compression parameter for vector u
/// * `dv`: Compression parameter for vector v
#[allow(clippy::many_single_char_names, clippy::too_many_arguments)]
pub(crate) fn k_pke_encrypt<const K: usize, const ETA1_64: usize, const ETA2_64: usize>(
    du: u32, dv: u32, ek_pke: &[u8], m: &[u8], r: &[u8; 32], ct: &mut [u8],
) -> Result<(), &'static str> {
    debug_assert_eq!(ek_pke.len(), 384 * K + 32, "Alg 14: ek len not 384 * K + 32");
    debug_assert_eq!(m.len(), 32, "Alg 14: m len not 32");

    // 1: N ← 0
    let mut n = 0;

    // 2: t̂ ← ByteDecode_12 (ek_PKE [0 : 384k])    ▷ run ByteDecode_12 𝑘 times to decode `𝐭  ∈ (ℤ^{256}_𝑞)^k`
    let mut t_hat = [[Z::default(); 256]; K];
    for (i, chunk) in ek_pke.chunks(384).enumerate().take(K) {
        byte_decode(12, chunk, &mut t_hat[i])?;
    }

    // 3: ρ ← ek_PKE [384k : 384k + 32]    ▷ extract 32-byte seed from ek_PKE
    let rho = &ek_pke[384 * K..(384 * K + 32)].try_into().unwrap();

    // Steps 4-8 in gen_a_hat() above
    let a_hat = gen_a_hat(rho);

    // Secret intermediate values are held in `Zeroizing` buffers, which are wiped when they go out
    // of scope (FIPS 203 §3.3), and every step runs in place so no other copies are made.

    // 9: for (i ← 0; i < k; i ++)
    // 10: y[i] ← SamplePolyCBD_η1(PRF_η1(r, N))    ▷ r[i] ∈ Z^{256}_q sampled from CBD
    // 11: N ← N +1
    // 12: end for
    // (y is sampled into `y_hat`, which step 18 transforms in place)
    let mut prf_out1 = Zeroizing::new([0u8; ETA1_64]);
    let mut y_hat = Zeroizing::new([[Z::default(); 256]; K]);
    for y_i in y_hat.iter_mut() {
        prf(r, n, &mut prf_out1);
        sample_poly_cbd(&prf_out1[..], y_i);
        n += 1;
    }

    // 13: for (i ← 0; i < k; i ++)    ▷ generate e1 ∈ (Z_q^{256})^k
    // 14: e1 [i] ← SamplePolyCBD_η2(PRF_η2(r, N))    ▷ e1 [i] ∈ Z^{256}_q sampled from CBD
    // 15: N ← N +1
    // 16: end for
    let mut prf_out2 = Zeroizing::new([0u8; ETA2_64]);
    let mut e1 = Zeroizing::new([[Z::default(); 256]; K]);
    for e1_i in e1.iter_mut() {
        prf(r, n, &mut prf_out2);
        sample_poly_cbd(&prf_out2[..], e1_i);
        n += 1;
    }

    // 17: e2 ← SamplePolyCBD_η2(PRF_η2(r, N))    ▷ sample e2 ∈ Z^{256}_q from CBD
    let mut e2 = Zeroizing::new([Z::default(); 256]);
    prf(r, n, &mut prf_out2);
    sample_poly_cbd(&prf_out2[..], &mut e2);

    // 18: 𝐲̂ ← NTT(𝐲)    ▷ NTT is run k times
    for y_i in y_hat.iter_mut() {
        ntt(y_i);
    }

    // 19: u ← NTT−1 (Â⊺ ◦ r̂) + e1
    let mut u = Zeroizing::new([[Z::default(); 256]; K]);
    mul_mat_t_vec(&a_hat, &y_hat, &mut u);
    for u_i in u.iter_mut() {
        ntt_inv(u_i);
    }
    add_vecs(&mut u, &e1);

    // 20: µ ← Decompress1(ByteDecode_1(m)))
    let mut mu = Zeroizing::new([Z::default(); 256]);
    byte_decode(1, m, &mut mu)?;
    decompress_vector(1, &mut mu[..]);

    // 21: v ← NTT−1 (t̂⊺ ◦ r̂) + e2 + µ    ▷ encode plaintext m into polynomial v.
    let mut v = Zeroizing::new([Z::default(); 256]);
    dot_t_prod(&t_hat, &y_hat, &mut v);
    ntt_inv(&mut v);
    add_poly(&mut v, &e2);
    add_poly(&mut v, &mu);

    // 22: c1 ← ByteEncode_du(Compress_du(u))    ▷ ByteEncode_du is run k times
    let step = 32 * du as usize;
    for (i, chunk) in ct.chunks_mut(step).enumerate().take(K) {
        compress_vector(du, &mut u[i]);
        byte_encode(du, &u[i], chunk);
    }


    // 23: c2 ← ByteEncode_dv(Compress_dv(v))
    compress_vector(dv, &mut v[..]);
    byte_encode(dv, &v, &mut ct[K * step..]);

    // 24: return c ← (c1 ∥ c2)
    Ok(())
}


/// Algorithm 15 `K-PKE.Decrypt(dk_PKE, c)` on page 31.
/// Uses the decryption key to decrypt a ciphertext.
///
/// # Parameters
/// * Input: decryption key `dk_PKE ∈ B^{384·k}` (private key)
/// * Input: ciphertext `c ∈ B^{32(du·k+dv)}` (encrypted message)
/// * Output: message `m ∈ B^{32}` (decrypted 32-byte message), written into `m` rather than
///   returned by value, so that the secret leaves no copy outside the caller's buffer (FIPS 203 §3.3)
///
/// # Parameters
/// * `du`: Compression parameter for vector u
/// * `dv`: Compression parameter for vector v
/// * `K`: Number of polynomial vectors
pub(crate) fn k_pke_decrypt<const K: usize>(
    du: u32, dv: u32, dk_pke: &[u8], ct: &[u8], m: &mut [u8; 32],
) -> Result<(), &'static str> {
    debug_assert_eq!(dk_pke.len(), 384 * K, "Alg 15: dk len not 384 * K");
    debug_assert_eq!(
        ct.len(),
        32 * (du as usize * K + dv as usize),
        "Alg 15: ct len not 32 * (DU * K + DV)"
    );

    // 1: c1 ← c[0 : 32·du·k]
    let c1 = &ct[0..32 * du as usize * K];

    // 2: c2 ← c[32du·k : 32·(du·k + dv)]
    let c2 = &ct[32 * du as usize * K..32 * (du as usize * K + dv as usize)];

    // 3: 𝐮′ ← Decompress_𝑑(ByteDecode_𝑑(𝑐1))   ▷ run Decompress𝑑 and ByteDecode𝑑 𝑘 times
    let mut u = [[Z::default(); 256]; K];
    for (i, chunk) in c1.chunks(32 * du as usize).enumerate().take(K) {
        byte_decode(du, chunk, &mut u[i])?;
        decompress_vector(du, &mut u[i]);
    }

    // 4: v ← Decompress_{dv}(ByteDecode_dv(c_2))
    let mut v = [Z::default(); 256];
    byte_decode(dv, c2, &mut v)?;
    decompress_vector(dv, &mut v);

    // Secret intermediate values are held in `Zeroizing` buffers, which are wiped when they go out
    // of scope (FIPS 203 §3.3), and every step runs in place so no other copies are made.

    // 5: s_hat ← ByteDecode_12(dk_PKE)
    let mut s_hat = Zeroizing::new([[Z::default(); 256]; K]);
    for (i, chunk) in dk_pke.chunks(384).enumerate() {
        byte_decode(12, chunk, &mut s_hat[i])?;
    }

    // 6: 𝑤 ← 𝑣 − NTT (𝐬 ̂ ∘ NTT(𝐮))    ▷ run NTT 𝑘 times; run NTT^{−1} once
    // (u now holds NTT(u′), which is public; w holds ŝ⊺ ◦ NTT(u′), then its NTT^{−1}, then w)
    for u_i in &mut u {
        ntt(u_i);
    }
    let mut w = Zeroizing::new([Z::default(); 256]);
    dot_t_prod(&s_hat, &u, &mut w);
    ntt_inv(&mut w);
    for (w_i, v_i) in w.iter_mut().zip(v.iter()) {
        *w_i = v_i.sub(*w_i);
    }

    // 7: m ← ByteEncode_1(Compress_1(w))    ▷ decode plaintext m from polynomial v
    compress_vector(1, &mut w[..]);
    byte_encode(1, &w, m);

    // 8: return m    ▷ in place
    Ok(())
}


#[cfg(test)]
mod tests {
    use rand_core::{RngCore, SeedableRng};

    use crate::k_pke::{k_pke_decrypt, k_pke_encrypt, k_pke_key_gen};

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

    #[test]
    #[allow(clippy::similar_names)]
    fn test_result_errs() {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(123);
        let mut ek = [0u8; EK_LEN];
        let mut dk = [0u8; DK_LEN];
        let mut ct = [0u8; CT_LEN];
        let m = [0u8; 32];
        let r = [0u8; 32];

        let mut d = [0u8; 32];
        rng.try_fill_bytes(&mut d).unwrap();
        k_pke_key_gen::<K, ETA1_64>(&d, &mut ek, &mut dk[0..384 * K]);
        // k_pke_key_gen does not fail because it no longer relies on rng // assert!(res.is_ok());

        let res = k_pke_encrypt::<K, ETA1_64, ETA2_64>(DU, DV, &ek, &m, &r, &mut ct);
        assert!(res.is_ok());

        let ff_ek = [0xFFu8; EK_LEN]; // oversized values
        let res = k_pke_encrypt::<K, ETA1_64, ETA2_64>(DU, DV, &ff_ek, &m, &r, &mut ct);
        assert!(res.is_err());

        let res = k_pke_decrypt::<K>(DU, DV, &dk[0..384 * K], &ct, &mut [0u8; 32]);
        assert!(res.is_ok());
    }


    // K-PKE.Decrypt against the C2SP CCTV intermediate values. The vendored files are from the
    // FIPS 203 draft, so their key-generation values are stale, but Algorithm 15 and the
    // ByteDecode, Decompress and NTT steps it uses did not change in the final standard.
    // Asserting m alone would not catch a wrong Decompress, so u', v' and w are checked first.
    // File-format traps: the first `dkPKE` line reads `dkPKE = NTT(s) = <hex>`, and the second
    // `dkPKE` line actually holds ekPKE.
    fn cctv_k_pke_decrypt<const KK: usize>(du: u32, dv: u32, text: &str) {
        use crate::byte_fns::{byte_decode, byte_encode};
        use crate::helpers::{decompress_vector, dot_t_prod};
        use crate::ntt::{ntt, ntt_inv};
        use crate::types::Z;

        let field = |prefix: &str| {
            let line = text.lines().find(|l| l.starts_with(prefix)).expect(prefix);
            hex::decode(line.rsplit(" = ").next().unwrap()).unwrap()
        };
        let (dk_pke, ct, msg) = (field("dkPKE = NTT(s) = "), field("c = "), field("m = "));
        let (u_d, v_d, w_exp) = (field("uᵈ = "), field("vᵈ = "), field("w = "));
        assert_eq!(dk_pke.len(), 384 * KK);
        assert_eq!(ct.len(), 32 * (du as usize * KK + dv as usize));

        // Steps 1-4: u' and v' must match the ByteEncode_12 of the reference Decompress output
        let (c1, c2) = ct.split_at(32 * du as usize * KK);
        let mut u = [[Z::default(); 256]; KK];
        let mut enc = [0u8; 384];
        for (i, chunk) in c1.chunks(32 * du as usize).enumerate() {
            byte_decode(du, chunk, &mut u[i]).unwrap();
            decompress_vector(du, &mut u[i]);
            byte_encode(12, &u[i], &mut enc);
            assert_eq!(enc[..], u_d[384 * i..384 * (i + 1)], "Decompress_du of u'[{i}]");
        }
        let mut v = [Z::default(); 256];
        byte_decode(dv, c2, &mut v).unwrap();
        decompress_vector(dv, &mut v);
        byte_encode(12, &v, &mut enc);
        assert_eq!(enc[..], v_d[..], "Decompress_dv of v'");

        // Steps 5-6: w = v' - NTT^-1(s_hat^T o NTT(u'))
        let mut s_hat = [[Z::default(); 256]; KK];
        for (i, chunk) in dk_pke.chunks(384).enumerate() {
            byte_decode(12, chunk, &mut s_hat[i]).unwrap();
        }
        let mut ntt_u = u;
        for ntt_u_i in &mut ntt_u {
            ntt(ntt_u_i);
        }
        let mut su = [Z::default(); 256];
        dot_t_prod(&s_hat, &ntt_u, &mut su);
        ntt_inv(&mut su);
        let w: [Z; 256] = core::array::from_fn(|i| v[i].sub(su[i]));
        byte_encode(12, &w, &mut enc);
        assert_eq!(enc[..], w_exp[..], "w");

        // The whole algorithm
        let mut m = [0u8; 32];
        k_pke_decrypt::<KK>(du, dv, &dk_pke, &ct, &mut m).unwrap();
        assert_eq!(m[..], msg[..], "m");
    }

    #[test]
    fn cctv_k_pke_decrypt_512() {
        let text = include_str!("../tests/cctv_vectors/ML-KEM/intermediate/ML-KEM-512.txt");
        cctv_k_pke_decrypt::<2>(10, 4, text);
    }

    #[test]
    fn cctv_k_pke_decrypt_768() {
        let text = include_str!("../tests/cctv_vectors/ML-KEM/intermediate/ML-KEM-768.txt");
        cctv_k_pke_decrypt::<3>(10, 4, text);
    }

    #[test]
    fn cctv_k_pke_decrypt_1024() {
        let text = include_str!("../tests/cctv_vectors/ML-KEM/intermediate/ML-KEM-1024.txt");
        cctv_k_pke_decrypt::<4>(11, 5, text);
    }
}
