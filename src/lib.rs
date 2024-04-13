#![no_std]
#![deny(clippy::pedantic, warnings, missing_docs, unsafe_code)]
// Most of the 'allow' category...
#![deny(absolute_paths_not_starting_with_crate, box_pointers, dead_code)]
#![deny(elided_lifetimes_in_paths, explicit_outlives_requirements, keyword_idents)]
#![deny(let_underscore_drop, macro_use_extern_crate, meta_variable_misuse, missing_abi)]
#![deny(non_ascii_idents, rust_2021_incompatible_closure_captures)]
#![deny(rust_2021_incompatible_or_patterns, rust_2021_prefixes_incompatible_syntax)]
#![deny(rust_2021_prelude_collisions, single_use_lifetimes, trivial_casts)]
#![deny(trivial_numeric_casts, unreachable_pub, unsafe_op_in_unsafe_fn, unstable_features)]
#![deny(unused_extern_crates, unused_import_braces, unused_lifetimes, unused_macro_rules)]
#![deny(unused_qualifications, unused_results, variant_size_differences)]
//
#![doc = include_str!("../README.md")]

// Implements FIPS 203 draft Module-Lattice-based Key-Encapsulation Mechanism Standard.
// See <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.ipd.pdf>

// TODO Roadmap
//   0. Stay current with FIPS 203 updates (due late summer 2024)
//   1. Perf: optimize/minimize modular reductions, minimize u16 arith, consider avx2/aarch64
//      (currently, code is 'optimized' for safety and change-support, with reasonable perf)
//   2. Slightly more intelligent fuzzing (as dk contains h(ek))

// Functionality map per FIPS 203 draft
//
// Algorithm 2 BitsToBytes(b) on page 17                    --> optimized out (byte_fns.rs)
// Algorithm 3 BytesToBits(B) on page 18                    --> optimized out (byte_fns.rs)
// Algorithm 4 ByteEncode_d(F) on page 19                   --> byte_fns.rs
// Algorithm 5 ByteDecode_d(B) on page 19                   --> byte_fns.rs
// Algorithm 6 SampleNTT(B) on page 20                      --> sampling.rs
// Algorithm 7 SamplePolyCBDη(B) on page 20                 --> sampling.rs
// Algorithm 8 NTT(f) on page 22                            --> ntt.rs
// Algorithm 9 NTT−1(fˆ) on page 23                         --> ntt.rs
// Algorithm 10 MultiplyNTTs(fˆ,ĝ) on page 24               --> ntt.rs
// Algorithm 11 BaseCaseMultiply(a0,a1,b0,b1,γ) on page 24  --> ntt.rs
// Algorithm 12 K-PKE.KeyGen() on page 26                   --> k_pke.rs
// Algorithm 13 K-PKE.Encrypt(ekPKE,m,r) on page 27         --> k_pke.rs
// Algorithm 14 K-PKE.Decrypt(dkPKE,c) on page 28           --> k_pke.rs
// Algorithm 15 ML-KEM.KeyGen() on page 29                  --> ml_kem.rs
// Algorithm 16 ML-KEM.Encaps(ek) on page 30                --> ml_kem.rs
// Algorithm 17 ML-KEM.Decaps(c,dk) on page 32              --> ml_kem.rs
// PRF and XOF on page 16                                   --> helpers.rs
// Three hash functions: G, H, J on page 17                 --> helpers.rs
// Compress and Decompress on page 18                       --> helpers.rs
//
// The three parameter sets are modules in this file with injected macro code that connects
// them into the functionality in ml_kem.rs. Some of the 'obtuse' coding style is driven by
// `clippy pedantic`. While the API suggests the code is not constant-time, this has been
// confirmed as constant-time (outside of rho) by both /fips203/dudect and /fips203/ct_cm4
// functionality.
//
// Note that the use of generics has been constrained to storage allocation purposes,
// e.g. `[0u8; EK_LEN];` (where arithmetic expressions are not allowed), while the remainder
// of the security parameters are generally passed as normal function parameters.
//
// The ensure!() instances are for validation purposes and cannot be turned off. The
// debug_assert!() instances are (effectively) targeted by the fuzzer in /fips203/fuzz and
// will support quicker future changes from the FIPS 203 specification update.


/// The `rand_core` types are re-exported so that users of fips203 do not
/// have to worry about using the exact correct version of `rand_core`.
pub use rand_core::{CryptoRng, Error as RngError, RngCore};

use crate::traits::SerDes;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

mod byte_fns;
mod helpers;
mod k_pke;
mod ml_kem;
mod ntt;
mod sampling;
mod types;

/// All functionality is covered by traits, such that consumers can utilize trait objects if desired.
pub mod traits;

// Relevant to all parameter sets
const Q: u16 = 3329;
const ZETA: u16 = 17;


/// Shared Secret Key length for all ML-KEM variants (in bytes)
pub const SSK_LEN: usize = 32;

/// The (opaque) secret key that can be de/serialized by each party.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecretKey([u8; SSK_LEN]);


impl SerDes for SharedSecretKey {
    type ByteArray = [u8; SSK_LEN];

    fn into_bytes(self) -> Self::ByteArray { self.0 }

    fn try_from_bytes(ssk: Self::ByteArray) -> Result<Self, &'static str> {
        // The `try_` is not really needed but implemented for symmetry/consistency, e.g., there
        // is no opportunity for validation (yet), but using a Result for the future possibility
        Ok(SharedSecretKey(ssk))
    }
}


// Conservative (constant-time) support...
impl PartialEq for SharedSecretKey {
    fn eq(&self, other: &Self) -> bool { bool::from(self.0.ct_eq(&other.0)) }
}


// This common functionality is injected into each parameter set module
macro_rules! functionality {
    () => {
        use crate::byte_fns::byte_decode;
        use crate::helpers::{ensure, h};
        use crate::ml_kem::{ml_kem_decaps, ml_kem_encaps, ml_kem_key_gen};
        use crate::traits::{Decaps, Encaps, KeyGen, SerDes};
        use crate::types::Z;
        use crate::SharedSecretKey;
        use rand_core::CryptoRngCore;


        /// Correctly sized encapsulation key specific to the target security parameter set.
        pub type EncapsKey = crate::types::EncapsKey<EK_LEN>;

        /// Correctly sized decapsulation key specific to the target security parameter set.
        pub type DecapsKey = crate::types::DecapsKey<DK_LEN>;

        /// Correctly sized ciphertext specific to the target security parameter set.
        pub type CipherText = crate::types::CipherText<CT_LEN>;

        /// Supports the `KeyGen` trait, allowing for keypair generation
        pub struct KG();


        impl KeyGen for KG {
            type DecapsByteArray = [u8; DK_LEN];
            type DecapsKey = DecapsKey;
            type EncapsByteArray = [u8; EK_LEN];
            type EncapsKey = EncapsKey;

            fn try_keygen_with_rng_vt(
                rng: &mut impl CryptoRngCore,
            ) -> Result<(EncapsKey, DecapsKey), &'static str> {
                let (mut ek, mut dk) = ([0u8; EK_LEN], [0u8; DK_LEN]);
                ml_kem_key_gen::<K, { ETA1 as usize * 64 }>(rng, &mut ek, &mut dk)?;
                Ok((EncapsKey { 0: ek }, DecapsKey { 0: dk }))
            }

            fn validate_keypair_vt(ek: &Self::EncapsByteArray, dk: &Self::DecapsByteArray) -> bool {
                // Note that size is checked by only accepting a ref to a correctly sized byte array
                let len_ek_pke = 384 * K + 32;
                let len_dk_pke = 384 * K;
                // dk should contain ek
                let same_ek = (*ek == dk[len_dk_pke..(len_dk_pke + len_ek_pke)]);
                // dk should contain hash of ek
                let same_h =
                    (h(ek) == dk[(len_dk_pke + len_ek_pke)..(len_dk_pke + len_ek_pke + 32)]);
                same_ek & same_h
            }
        }


        impl Encaps for EncapsKey {
            type CipherText = CipherText;
            type SharedSecretKey = SharedSecretKey;

            fn try_encaps_with_rng_vt(
                &self, rng: &mut impl CryptoRngCore,
            ) -> Result<(Self::SharedSecretKey, Self::CipherText), &'static str> {
                let mut ct = [0u8; CT_LEN];
                let ssk = ml_kem_encaps::<K, { ETA1 as usize * 64 }, { ETA2 as usize * 64 }>(
                    rng, DU, DV, &self.0, &mut ct,
                )?;
                Ok((ssk, CipherText { 0: ct }))
            }
        }


        impl Decaps for DecapsKey {
            type CipherText = CipherText;
            type SharedSecretKey = SharedSecretKey;

            fn try_decaps_vt(&self, ct: &CipherText) -> Result<SharedSecretKey, &'static str> {
                let ssk = ml_kem_decaps::<
                    K,
                    { ETA1 as usize * 64 },
                    { ETA2 as usize * 64 },
                    { 32 + 32 * (DU as usize * K + DV as usize) },
                    CT_LEN,
                >(DU, DV, &self.0, &ct.0);
                ssk
            }
        }


        impl SerDes for EncapsKey {
            type ByteArray = [u8; EK_LEN];

            fn into_bytes(self) -> Self::ByteArray { self.0 }

            fn try_from_bytes(ek: Self::ByteArray) -> Result<Self, &'static str> {
                // Validation per pg 2 "the byte array containing the encapsulation key correctly
                // decodes to an array of integers modulo q without any modular reductions". See
                // also page 30. Note that accepting a byte array of fixed size, rather than a
                // slice of varied size, addresses check #1.
                let mut ek_hat = [Z::default(); 256];
                for i in 0..K {
                    byte_decode(12, &ek[384 * i..384 * (i + 1)], &mut ek_hat)?;
                }
                Ok(EncapsKey { 0: ek })
            }
        }


        impl SerDes for DecapsKey {
            type ByteArray = [u8; DK_LEN];

            fn into_bytes(self) -> Self::ByteArray { self.0 }

            fn try_from_bytes(dk: Self::ByteArray) -> Result<Self, &'static str> {
                // Validation per pg 31. Note that the two checks specify fixed sizes, and these
                // functions take only byte arrays of correct size. Nonetheless, we take the
                // opportunity to validate the ek and h(ek).
                let len_ek_pke = 384 * K + 32;
                let len_dk_pke = 384 * K;
                let ek = &dk[len_dk_pke..len_dk_pke + EK_LEN];
                let _res =
                    EncapsKey::try_from_bytes(ek.try_into().map_err(|_| "Malformed encaps key")?)?;
                ensure!(
                    h(ek) == dk[(len_dk_pke + len_ek_pke)..(len_dk_pke + len_ek_pke + 32)],
                    "Encaps hash wrong"
                );
                Ok(DecapsKey { 0: dk })
            }
        }


        impl SerDes for CipherText {
            type ByteArray = [u8; CT_LEN];

            fn into_bytes(self) -> Self::ByteArray { self.0 }

            fn try_from_bytes(ct: Self::ByteArray) -> Result<Self, &'static str> {
                // Validation per pg 31. Note that the two checks specify fixed sizes, and these
                // functions take only byte arrays of correct size. Nonetheless, we use a Result
                // here in case future opportunities for further validation arise.
                Ok(CipherText { 0: ct })
            }
        }


        #[cfg(test)]
        mod tests {
            use super::*;
            use crate::types::EncapsKey;
            use rand_chacha::rand_core::SeedableRng;

            #[test]
            fn smoke_test() {
                let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(123);
                for _i in 0..100 {
                    let (ek, dk) = KG::try_keygen_with_rng_vt(&mut rng).unwrap();
                    let (ssk1, ct) = ek.try_encaps_with_rng_vt(&mut rng).unwrap();
                    let ssk2 = dk.try_decaps_vt(&ct).unwrap();
                    assert!(KG::validate_keypair_vt(
                        &ek.clone().into_bytes(),
                        &dk.clone().into_bytes()
                    ));
                    assert_eq!(ssk1, ssk2);
                    assert_eq!(ek.clone().0, EncapsKey::try_from_bytes(ek.into_bytes()).unwrap().0);
                    assert_eq!(dk.clone().0, DecapsKey::try_from_bytes(dk.into_bytes()).unwrap().0);
                }
            }
        }
    };
}


/// Functionality for the ML-KEM-512 security parameter set, which is claimed to be in security category 1, see
/// table 2 & 3 on page 33 of spec.
#[cfg(feature = "ml-kem-512")]
pub mod ml_kem_512 {
    //!
    //! See <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.ipd.pdf>
    //!
    //! Typical usage flow entails:
    //! 1. The originator runs `try_keygen_vt()` to get an encaps key `encapsKey` and decaps key `decapsKey`.
    //! 2. The originator serializes the encaps key via `encapsKey.into_bytes()` and sends to the remote party.
    //! 3. The remote party deserializes the bytes via `try_from_bytes(<bytes>)` and runs `try_encaps_vt()` to get the
    //!    shared secret key `ssk` and ciphertext `cipherText`.
    //! 4. The remote party serializes the cipertext via `cipherText.into_bytes()` and sends to the originator.
    //! 5. The originator deserializes the ciphertext via `try_from_bytes(<bytes>)` then
    //!    runs `decapsKey.try_decaps_vt(cipherText)` to the get shared secret ket `ssk`.
    //! 6. Both the originator and remote party now have the same shared secret key `ssk`.
    //!
    //! **--> See [`traits`] for the keygen, encapsulation, decapsulation, and serialization/deserialization functionality.**

    const K: usize = 2;
    const ETA1: u32 = 3;
    const ETA2: u32 = 2;
    const DU: u32 = 10;
    const DV: u32 = 4;

    /// Serialized Encapsulation Key Length (in bytes)
    pub const EK_LEN: usize = 800;
    /// Serialized Decapsulation Key Length (in bytes)
    pub const DK_LEN: usize = 1632;
    /// Serialized Ciphertext Key Length (in bytes)
    pub const CT_LEN: usize = 768;

    functionality!();
}


/// Functionality for the ML-KEM-768 security parameter set, which is claimed to be in security category 3, see
/// table 2 & 3 on page 33 of spec.
#[cfg(feature = "ml-kem-768")]
pub mod ml_kem_768 {
    //!
    //! See <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.ipd.pdf>
    //!
    //! Typical usage flow entails:
    //! 1. The originator runs `try_keygen_vt()` to get an encaps key `encapsKey` and decaps key `decapsKey`.
    //! 2. The originator serializes the encaps key via `encapsKey.into_bytes()` and sends to the remote party.
    //! 3. The remote party deserializes the bytes via `try_from_bytes(<bytes>)` and runs `try_encaps_vt()` to get the
    //!    shared secret key `ssk` and ciphertext `cipherText`.
    //! 4. The remote party serializes the cipertext via `cipherText.into_bytes()` and sends to the originator.
    //! 5. The originator deserializes the ciphertext via `try_from_bytes(<bytes>)` then
    //!    runs `decapsKey.try_decaps_vt(cipherText)` to the get shared secret ket `ssk`.
    //! 6. Both the originator and remote party now have the same shared secret key `ssk`.
    //!
    //! **--> See [`traits`] for the keygen, encapsulation, decapsulation, and serialization/deserialization functionality.**

    const K: usize = 3;
    const ETA1: u32 = 2;
    const ETA2: u32 = 2;
    const DU: u32 = 10;
    const DV: u32 = 4;

    /// Serialized Encapsulation Key Length (in bytes)
    pub const EK_LEN: usize = 1184;
    /// Serialized Decapsulation Key Length (in bytes)
    pub const DK_LEN: usize = 2400;
    /// Serialized Ciphertext Key Length (in bytes)
    pub const CT_LEN: usize = 1088;

    functionality!();
}


/// ML-KEM-1024 is claimed to be in security category 5, see table 2 & 3 on page 33.
#[cfg(feature = "ml-kem-1024")]
pub mod ml_kem_1024 {
    //!
    //! See <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.ipd.pdf>
    //!
    //! Typical usage flow entails:
    //! 1. The originator runs `try_keygen_vt()` to get an encaps key `encapsKey` and decaps key `decapsKey`.
    //! 2. The originator serializes the encaps key via `encapsKey.into_bytes()` and sends to the remote party.
    //! 3. The remote party deserializes the bytes via `try_from_bytes(<bytes>)` and runs `try_encaps_vt()` to get the
    //!    shared secret key `ssk` and ciphertext `cipherText`.
    //! 4. The remote party serializes the cipertext via `cipherText.into_bytes()` and sends to the originator.
    //! 5. The originator deserializes the ciphertext via `try_from_bytes(<bytes>)` then
    //!    runs `decapsKey.try_decaps_vt(cipherText)` to the get shared secret ket `ssk`.
    //! 6. Both the originator and remote party now have the same shared secret key `ssk`.
    //!
    //! **--> See [`traits`] for the keygen, encapsulation, decapsulation, and serialization/deserialization functionality.**

    const K: usize = 4;
    const ETA1: u32 = 2;
    const ETA2: u32 = 2;
    const DU: u32 = 11;
    const DV: u32 = 5;

    /// Serialized Encapsulation Key Length (in bytes)
    pub const EK_LEN: usize = 1568;
    /// Serialized Decapsulation Key Length (in bytes)
    pub const DK_LEN: usize = 3168;
    /// Serialized Ciphertext Key Length (in bytes)
    pub const CT_LEN: usize = 1568;

    functionality!();
}
