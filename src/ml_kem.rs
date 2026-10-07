use crate::byte_fns::{byte_decode, byte_encode};
use crate::helpers::{g, h, j};
use crate::k_pke::{k_pke_decrypt, k_pke_encrypt, k_pke_key_gen};
use crate::SharedSecretKey;
use rand_core::CryptoRngCore;
use subtle::{ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroizing;


/// Algorithm 16 `ML-KEM.KeyGen_internal(d,z)` on page 32.
/// Uses randomness to generate an encapsulation key and a corresponding decapsulation key.
///
/// # Parameters
/// * `d` - 32-byte random seed for key generation
/// * `z` - 32-byte random seed for implicit rejection
/// * `ek` - Output buffer for encapsulation key (size: `384·K+32` bytes)
/// * `dk` - Output buffer for decapsulation key (size: `768·K+96` bytes)
pub(crate) fn ml_kem_key_gen_internal<const K: usize, const ETA1_64: usize>(
    d: &[u8; 32], z: &[u8; 32], ek: &mut [u8], dk: &mut [u8],
) {
    debug_assert_eq!(ek.len(), 384 * K + 32, "Alg 16: ek len not 384 * K + 32");
    debug_assert_eq!(dk.len(), 768 * K + 96, "Alg 16: dk len not 768 * K + 96");

    // 1: (ek_PKE , dk_PKE) ← K-PKE.KeyGen(𝑑)    ▷ run key generation for K-PKE
    // 2: ek ← ek_PKE    ▷ KEM encaps key is just the PKE encryption key
    let p1 = 384 * K;
    k_pke_key_gen::<K, ETA1_64>(d, ek, &mut dk[..p1]); // writes ek and first part of dk

    // 3: dk ← (dk_PKE ‖ ek ‖ H(ek) ‖ 𝑧)    ▷ KEM decaps key includes PKE decryption key
    let h_ek = h(ek);
    let p2 = p1 + ek.len();
    let p3 = p2 + h_ek.len();
    dk[p1..p2].copy_from_slice(ek);
    dk[p2..p3].copy_from_slice(&h_ek);
    dk[p3..].copy_from_slice(z);

    // 4: return (ek, dk)
}


/// Algorithm 17 `ML-KEM.Encaps_internal(ek, m)` on page 33.
/// Generates a shared secret key and ciphertext using the encapsulation key and randomness.
///
/// # Parameters
/// * `du`, `dv` - Parameters affecting ciphertext size
/// * `m` - 32-byte random input
/// * `ek` - Encapsulation key (`384·K+32` bytes)
/// * `ct` - Output buffer for ciphertext (`32(du·K+dv)` bytes)
///
/// # Returns
/// * `Ok(SharedSecretKey)` - 32-byte shared secret key
/// * `Err(&str)` - Error message if encryption fails
fn ml_kem_encaps_internal<const K: usize, const ETA1_64: usize, const ETA2_64: usize>(
    du: u32, dv: u32, m: &[u8; 32], ek: &[u8], ct: &mut [u8],
) -> Result<SharedSecretKey, &'static str> {
    // Note: this is only called via ml_kem_encaps(), whose size and modulus checks are debug-only.
    // Sizes are fixed by array types in lib.rs, and ek is checked by EncapsKey::try_from_bytes().

    // 1: (K, r) ← G(m ∥ H(ek))    ▷ derive shared secret key K and randomness r
    // (K and r are wiped when they go out of scope, FIPS 203 §3.3; K is returned as a copy)
    let h_ek = h(ek);
    let (mut k, mut r) = (Zeroizing::new([0u8; 32]), Zeroizing::new([0u8; 32]));
    g(&[m, &h_ek], &mut k, &mut r);

    // 2: c ← K-PKE.Encrypt(ek, m, r)    ▷ encrypt m using K-PKE with randomness r
    k_pke_encrypt::<K, ETA1_64, ETA2_64>(du, dv, ek, m, &r, ct)?;

    // 3: return (K, c)  (note: ct is mutable input)
    Ok(SharedSecretKey(*k))
}


/// Algorithm 18 `ML-KEM.Decaps_internal(dk, c)` on page 34.
/// Recovers the shared secret key from a ciphertext using the decapsulation key.
/// Includes implicit rejection if the re-encryption check fails.
///
/// # Parameters
/// * `du`, `dv` - Parameters affecting ciphertext size
/// * `dk` - Decapsulation key (`768·K+96` bytes)
/// * `ct` - Input ciphertext (`32(du·K+dv)` bytes)
///
/// # Returns
/// * `Ok(SharedSecretKey)` - 32-byte shared secret key
/// * `Err(&str)` - Only if `dk` holds a coefficient ≥ q in ŝ or in its embedded `ek`, which key
///   generation and `try_from_bytes()` rule out. An invalid `ct` is not an error: implicit
///   rejection returns a pseudorandom key instead.
#[allow(clippy::similar_names)]
fn ml_kem_decaps_internal<
    const K: usize,
    const ETA1_64: usize,
    const ETA2_64: usize,
    const J_LEN: usize,
    const CT_LEN: usize,
>(
    du: u32, dv: u32, dk: &[u8], ct: &[u8; CT_LEN],
) -> Result<SharedSecretKey, &'static str> {
    // Decapsulation key type check
    debug_assert_eq!(dk.len(), 768 * K + 96, "Alg 18: dk len not 768 ...");
    // Note: decaps key is either correctly sourced from KeyGen, or validated by try_from_bytes(). As
    // such, the above check is redundant but will be removed in release builds. It is left
    // here for A) caution, B) give guardrails for future changes

    // 1: dk_PKE ← dk[0 : 384·k]    ▷ extract (from KEM decaps key) the PKE decryption key
    let dk_pke = &dk[0..384 * K];

    // 2: ek_PKE ← dk[384·k : 768·k + 32]    ▷ extract PKE encryption key
    let ek_pke = &dk[384 * K..768 * K + 32];

    // 3: h ← dk[768·k + 32 : 768·k + 64]    ▷ extract hash of PKE encryption key
    let h = &dk[768 * K + 32..768 * K + 64];

    // 4: z ← dk[768·k + 64 : 768·k + 96]    ▷ extract implicit rejection value
    let z = &dk[768 * K + 64..768 * K + 96];

    // m′, K′, r′, K̄ and c′ are wiped when they go out of scope (FIPS 203 §3.3); K′ is returned as a
    // copy. When c′ ≠ c, c′ and m′ are exactly what implicit rejection hides.

    // 5: m′ ← K-PKE.Decrypt(dk_PKE,c)    ▷ decrypt ciphertext
    let mut m_prime = Zeroizing::new([0u8; 32]);
    k_pke_decrypt::<K>(du, dv, dk_pke, ct, &mut m_prime)?;

    // 6: (K′, r′) ← G(m′ ∥ h)
    let (mut k_prime, mut r_prime) = (Zeroizing::new([0u8; 32]), Zeroizing::new([0u8; 32]));
    g(&[&m_prime[..], h], &mut k_prime, &mut r_prime);

    // 7: K̄ ← J(z ∥ c)
    let mut k_bar = Zeroizing::new([0u8; 32]);
    j(z.try_into().unwrap(), ct, &mut k_bar);

    // 8: c′ ← K-PKE.Encrypt(ek_PKE , m′ , r′ )    ▷ re-encrypt using the derived randomness r′
    let mut c_prime = Zeroizing::new([0u8; CT_LEN]);
    k_pke_encrypt::<K, ETA1_64, ETA2_64>(
        du,
        dv,
        ek_pke,
        &m_prime[..],
        &r_prime,
        &mut c_prime[0..ct.len()],
    )?;

    // 9:  if 𝑐 ≠ 𝑐 ′ then
    // 10:   𝐾 ′ ← 𝐾̄    ▷ if ciphertexts do not match, “implicitly reject”
    // 11: end if
    k_prime.conditional_assign(&k_bar, ct.ct_ne(&*c_prime));

    // 12: return 𝐾 ′
    Ok(SharedSecretKey(*k_prime))
}


/// Algorithm 19 `ML-KEM.KeyGen()` on page 35.
/// Entry point for key generation. Generates random seeds and calls internal key generation.
///
/// # Parameters
/// * `rng` - Cryptographically secure random number generator
/// * `ek` - Output buffer for encapsulation key (`384·K+32` bytes)
/// * `dk` - Output buffer for decapsulation key (`768·K+96` bytes)
///
/// # Returns
/// * `Ok(())` - Success
/// * `Err(&str)` - Error message if RNG fails
pub(crate) fn ml_kem_key_gen<const K: usize, const ETA1_64: usize>(
    rng: &mut impl CryptoRngCore, ek: &mut [u8], dk: &mut [u8],
) -> Result<(), &'static str> {
    debug_assert_eq!(ek.len(), 384 * K + 32, "Alg 19: ek len not 384 * K + 32");
    debug_assert_eq!(dk.len(), 768 * K + 96, "Alg 19: dk len not 768 * K + 96");

    // d and z are wiped when they go out of scope, including on an RNG failure (FIPS 203 §3.3)

    // 1: d ←− B^{32}    ▷ d is 32 random bytes (see Section 3.3)
    let mut d = Zeroizing::new([0u8; 32]);
    rng.try_fill_bytes(&mut d[..]).map_err(|_| "Alg 19: Random number generator failed for d")?;

    // 2: z ←− B^{32}    ▷ z is 32 random bytes (see Section 3.3)
    let mut z = Zeroizing::new([0u8; 32]);
    rng.try_fill_bytes(&mut z[..]).map_err(|_| "Alg 19: Random number generator failed for z")?;

    // 3: if 𝑑 == NULL or 𝑧 == NULL then
    // 4:   return ⊥    ▷ return an error indication if random bit generation failed
    // 5: end if
    // Note: the above functionality is present in the map_err() in step 1 and 2

    // 6: (ek, dk) ← ML-KEM.KeyGen_internal(𝑑, 𝑧)    ▷ run internal key generation algorithm
    ml_kem_key_gen_internal::<K, ETA1_64>(&d, &z, ek, dk);

    // 7: return (ek, dk)
    Ok(())
}


/// Algorithm 20 `ML-KEM.Encaps(ek)` on page 37.
/// Uses the encapsulation key to generate a shared key and an associated ciphertext.
///
/// # Parameters
/// * `rng` - Cryptographically secure random number generator
/// * `du`, `dv` - Parameters affecting ciphertext size
/// * `ek` - Encapsulation key (`384·K+32` bytes)
/// * `ct` - Output buffer for ciphertext (`32(du·K+dv)` bytes)
///
/// # Returns
/// * `Ok(SharedSecretKey)` - 32-byte shared secret key
/// * `Err(&str)` - Error message if RNG fails or encryption fails
///
/// # Input Validation
/// The encapsulation key `ek` must pass the modulus check (7.1):
/// `ek[0:384k] = ByteEncode12(ByteDecode12(ek[0:384k]))`.
/// External `ek` values are validated via `try_from_bytes()`.
pub(crate) fn ml_kem_encaps<const K: usize, const ETA1_64: usize, const ETA2_64: usize>(
    rng: &mut impl CryptoRngCore, du: u32, dv: u32, ek: &[u8], ct: &mut [u8],
) -> Result<SharedSecretKey, &'static str> {
    debug_assert_eq!(ek.len(), 384 * K + 32, "Alg 20: ek len not 384 * K + 32"); // also: size check at top level
    debug_assert_eq!(
        ct.len(),
        32 * (du as usize * K + dv as usize),
        "Alg 20: ct len not 32*(DU*K+DV)"
    ); // also: size check at top level

    // modulus check (7.1): confirm ByteEncode12(ByteDecode12(ek[0:384k])) = ek[0:384k].
    // Note: An *external* ek can only arrive via try_from_bytes() which does this validation already.
    // As such, this check is redundant but is left in for caution and as a fuzz target, as it is
    // removed in release builds anyway. It also supports quicker changes if the spec moves...
    debug_assert!(
        {
            let mut pass = true;
            for i in 0..K {
                let mut ek_tilde = [0u8; 384];
                let mut ek_hat = [crate::types::Z::default(); 256];
                byte_decode(12, &ek[384 * i..384 * (i + 1)], &mut ek_hat).unwrap(); // btw, going to panic
                byte_encode(12, &ek_hat, &mut ek_tilde);
                pass &= ek_tilde == ek[384 * i..384 * (i + 1)];
            }
            pass
        },
        "Alg 20: ek fails modulus check"
    );

    // 1: m ← B^{32}          ▷ m is 32 random bytes (see Section 3.3)
    // 2: if 𝑚 == NULL then
    // 3:   return ⊥    ▷ return an error indication if random bit generation failed
    // 4: end if
    // m is wiped when it goes out of scope (FIPS 203 §3.3)
    let mut m = Zeroizing::new([0u8; 32]);
    rng.try_fill_bytes(&mut m[..]).map_err(|_| "Alg 20: random number generator failed")?;

    // 5: (K, c) ← ML-KEM.Encaps_internal(ek, m)    ▷ run internal encapsulation algorithm
    let k = ml_kem_encaps_internal::<K, ETA1_64, ETA2_64>(du, dv, &m, ek, ct)?;

    // 6: return (K, c)
    Ok(k)
}


/// Algorithm 21 `ML-KEM.Decaps(dk, c)` on page 38.
/// Uses the decapsulation key to produce a shared key from a ciphertext.
/// Implements implicit rejection for invalid ciphertexts.
///
/// # Parameters
/// * `du`, `dv` - Parameters affecting ciphertext size
/// * `dk` - Decapsulation key (`768·K+96` bytes)
/// * `ct` - Input ciphertext (`32(du·K+dv)` bytes)
///
/// # Returns
/// * `Ok(SharedSecretKey)` - 32-byte shared secret key
/// * `Err(&str)` - Only if `dk` holds a coefficient ≥ q in ŝ or in its embedded `ek`, which key
///   generation and `try_from_bytes()` rule out. An invalid `ct` is not an error: implicit
///   rejection returns a pseudorandom key instead.
///
/// # Input Validation
/// - Ciphertext size must be exactly `32(du·K+dv)` bytes
/// - Decapsulation key size must be exactly `768·K+96` bytes
/// - External `dk` values are validated via `try_from_bytes()`
#[allow(clippy::similar_names)]
pub(crate) fn ml_kem_decaps<
    const K: usize,
    const ETA1_64: usize,
    const ETA2_64: usize,
    const J_LEN: usize,
    const CT_LEN: usize,
>(
    du: u32, dv: u32, dk: &[u8], ct: &[u8; CT_LEN],
) -> Result<SharedSecretKey, &'static str> {
    // Ciphertext type check
    debug_assert_eq!(ct.len(), 32 * (du as usize * K + dv as usize), "Alg 21: ct len not 32 * ...");
    // Decapsulation key type check
    debug_assert_eq!(dk.len(), 768 * K + 96, "Alg 21: dk len not 768 ...");
    // Note: decaps key is either correctly sourced from KeyGen, or validated by try_from_bytes(). As
    // such, the two above checks are redundant but will be removed in release builds. They are left
    // here for A) caution, B) give guardrails for future changes

    // 1: 𝐾 ′ ← ML-KEM.Decaps_internal(dk, 𝑐)    ▷ run internal decapsulation algorithm
    // 2: return 𝐾 ′
    ml_kem_decaps_internal::<K, ETA1_64, ETA2_64, J_LEN, CT_LEN>(du, dv, dk, ct)
}


#[cfg(test)]
mod tests {
    use rand_core::SeedableRng;

    use crate::ml_kem::{ml_kem_decaps, ml_kem_encaps, ml_kem_key_gen};

    /// Test constants for ML-KEM-512
    const ETA1: u32 = 3;
    const ETA2: u32 = 2;
    const DU: u32 = 10;
    const DV: u32 = 4;
    const K: usize = 2;
    const ETA1_64: usize = ETA1 as usize * 64;
    const ETA2_64: usize = ETA2 as usize * 64;
    /// Size of encapsulation key in bytes
    const EK_LEN: usize = 800;
    /// Size of decapsulation key in bytes
    const DK_LEN: usize = 1632;
    /// Size of ciphertext in bytes
    const CT_LEN: usize = 768;
    /// Size of input to function J (z || c)
    const J_LEN: usize = 32 + 32 * (DU as usize * K + DV as usize);

    /// Tests that the key generation, encapsulation, and decapsulation functions
    /// complete successfully with valid inputs.
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
