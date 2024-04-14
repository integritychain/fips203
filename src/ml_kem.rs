use crate::byte_fns::{byte_decode, byte_encode};
use crate::helpers::{g, h, j};
use crate::k_pke::{k_pke_decrypt, k_pke_encrypt, k_pke_key_gen};
use crate::types::Z;
use crate::SharedSecretKey;
use rand_core::CryptoRngCore;
use subtle::{ConditionallySelectable, ConstantTimeEq};


/// Algorithm 15 `ML-KEM.KeyGen()` on page 29.
/// Generates an encapsulation key and a corresponding decapsulation key.
///
/// Output: Encapsulation key `ek` ∈ `B^{384·k+32}` <br>
/// Output: Decapsulation key `dk` ∈ `B^{768·k+96}`
pub(crate) fn ml_kem_key_gen<const K: usize, const ETA1_64: usize>(
    rng: &mut impl CryptoRngCore, ek: &mut [u8], dk: &mut [u8],
) -> Result<(), &'static str> {
    debug_assert_eq!(ek.len(), 384 * K + 32, "Alg 15: ek len not 384 * K + 32");
    debug_assert_eq!(dk.len(), 768 * K + 96, "Alg 15: dk len not 768 * K + 96");

    // 1: z ←− B32    ▷ z is 32 random bytes (see Section 3.3)
    let mut z = [0u8; 32];
    rng.try_fill_bytes(&mut z)
        .map_err(|_| "Alg 15: Random number generator failed")?;

    // 2: (ek_{PKE}, dk_{PKE}) ← K-PKE.KeyGen()    ▷ run key generation for K-PKE
    let p1 = 384 * K;
    k_pke_key_gen::<K, ETA1_64>(rng, ek, &mut dk[..p1])?; // 3: ek ← ekPKE

    // 4: dk ← (dkPKE ∥ek∥H(ek)∥z)  (first concat element is done above alongside ek)
    let h_ek = h(ek);
    let p2 = p1 + ek.len();
    let p3 = p2 + h_ek.len();
    dk[p1..p2].copy_from_slice(ek);
    dk[p2..p3].copy_from_slice(&h_ek);
    dk[p3..].copy_from_slice(&z);

    // 5: return (ek, dk)
    Ok(())
}


/// Algorithm 16 `ML-KEM.Encaps(ek)` on page 30.
/// Uses the encapsulation key to generate a shared key and an associated ciphertext.
///
/// Validated input: encapsulation key `ek` ∈ `B^{384·k+32}` <br>
/// Output: shared key `K` ∈ `B^{32}` <br>
/// Output: ciphertext `c` ∈ `B^{32(du·k+dv)}` <br>
pub(crate) fn ml_kem_encaps<const K: usize, const ETA1_64: usize, const ETA2_64: usize>(
    rng: &mut impl CryptoRngCore, du: u32, dv: u32, ek: &[u8], ct: &mut [u8],
) -> Result<SharedSecretKey, &'static str> {
    debug_assert_eq!(ek.len(), 384 * K + 32, "Alg 16: ek len not 384 * K + 32"); // also: size check at top level
    debug_assert_eq!(
        ct.len(),
        32 * (du as usize * K + dv as usize),
        "Alg 16: ct len not 32*(DU*K+DV)"
    ); // also: size check at top level

    // modulus check: perform the computation ek ← ByteEncode12(ByteDecode12(ek_tidle)
    // note: *external* ek can only arrive via from_bytes() which does this validation already
    debug_assert!(
        {
            let mut pass = true;
            let mut ek_hat = [Z::default(); 256];
            for i in 0..K {
                let mut ek_tilde = [0u8; 384];
                byte_decode(12, &ek[384 * i..384 * (i + 1)], &mut ek_hat).unwrap(); // btw, going to panic
                byte_encode(12, &ek_hat, &mut ek_tilde);
                pass &= ek_tilde == ek[384 * i..384 * (i + 1)];
            }
            pass
        },
        "Alg 16: ek fails modulus check"
    );

    // 1: m ←− B32          ▷ m is 32 random bytes (see Section 3.3)
    let mut m = [0u8; 32];
    rng.try_fill_bytes(&mut m)
        .map_err(|_| "Alg16: random number generator failed")?;

    // 2: (K, r) ← G(m∥H(ek))    ▷ derive shared secret key K and randomness r
    let h_ek = h(ek);
    let (k, r) = g(&[&m, &h_ek]);

    // 3: c ← K-PKE.Encrypt(ek, m, r)    ▷ encrypt m using K-PKE with randomness r
    k_pke_encrypt::<K, ETA1_64, ETA2_64>(du, dv, ek, &m, &r, ct)?;

    // 4: return (K, c)  (note: ct is mutable input)
    Ok(SharedSecretKey(k))
}


/// Algorithm 17 `ML-KEM.Decaps(c, dk)` on page 32.
/// Uses the decapsulation key to produce a shared key from a ciphertext.
///
/// Validated input: ciphertext `c` ∈ `B^{32(du·k+dv)}` <br>
/// Validated input: decapsulation key `dk` ∈ `B^{768·k+96}` <br>
/// Output: shared key `K` ∈ `B^{32}`
#[allow(clippy::similar_names)]
pub(crate) fn ml_kem_decaps<
    const K: usize,
    const ETA1_64: usize,
    const ETA2_64: usize,
    const J_LEN: usize,
    const CT_LEN: usize,
>(
    du: u32, dv: u32, dk: &[u8], ct: &[u8],
) -> Result<SharedSecretKey, &'static str> {
    // Ciphertext type check
    debug_assert_eq!(ct.len(), 32 * (du as usize * K + dv as usize), "Alg17: ct len not 32 * ...");
    // Decapsulation key type check
    debug_assert_eq!(dk.len(), 768 * K + 96, "Alg17: dk len not 768 ...");
    // Note: decaps key is either correctly sourced from KeyGen, or validated by into_bytes()

    // 1: dkPKE ← dk[0 : 384k]    ▷ extract (from KEM decaps key) the PKE decryption key
    let dk_pke = &dk[0..384 * K];

    // 2: ekPKE ← dk[384k : 768k + 32]    ▷ extract PKE encryption key
    let ek_pke = &dk[384 * K..768 * K + 32];

    // 3: h ← dk[768k + 32 : 768k + 64]    ▷ extract hash of PKE encryption key
    let h = &dk[768 * K + 32..768 * K + 64];

    // 4: z ← dk[768k + 64 : 768k + 96]    ▷ extract implicit rejection value
    let z = &dk[768 * K + 64..768 * K + 96];

    // 5: m′ ← K-PKE.Decrypt(dkPKE,c)
    let m_prime = k_pke_decrypt::<K>(du, dv, dk_pke, ct)?;

    // 6: (K′, r′) ← G(m′ ∥ h)
    let (mut k_prime, r_prime) = g(&[&m_prime, h]);

    // 7: K̄ ← J(z∥c, 32)
    let k_bar = j(z.try_into().unwrap(), ct);

    // 8: c′ ← K-PKE.Encrypt(ekPKE , m′ , r′ )    ▷ re-encrypt using the derived randomness r′
    let mut c_prime = [0u8; CT_LEN];
    k_pke_encrypt::<K, ETA1_64, ETA2_64>(
        du,
        dv,
        ek_pke,
        &m_prime,
        &r_prime,
        &mut c_prime[0..ct.len()],
    )?;

    k_prime.conditional_assign(&k_bar, ct.ct_ne(&c_prime));

    Ok(SharedSecretKey(k_prime))
}


#[cfg(test)]
mod tests {
    use rand_core::SeedableRng;

    use crate::ml_kem::{ml_kem_decaps, ml_kem_encaps, ml_kem_key_gen};

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
    const J_LEN: usize = 32 + 32 * (DU as usize * K + DV as usize);

    #[test]
    #[allow(clippy::similar_names)]
    fn test_result_errs() {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(123);
        let mut ek = [0u8; EK_LEN];
        let mut dk = [0u8; DK_LEN];
        let mut ct = [0u8; CT_LEN];

        let res = ml_kem_key_gen::<K, ETA1_64>(&mut rng, &mut ek, &mut dk);
        assert!(res.is_ok());

        let res = ml_kem_encaps::<K, ETA1_64, ETA2_64>(&mut rng, DU, DV, &ek, &mut ct);
        assert!(res.is_ok());

        let res = ml_kem_decaps::<K, ETA1_64, ETA2_64, J_LEN, CT_LEN>(DU, DV, &dk, &ct);
        assert!(res.is_ok());
    }
}
