use rand_core::CryptoRngCore;


#[cfg(feature = "default-rng")]
use rand_core::OsRng;


/// The `KeyGen` trait is defined to allow trait objects.
pub trait KeyGen {
    /// The (public) encapsulation key sent from the originator to the remote party.
    type EncapsKey;
    /// The (private) decapsulation key used by the originator to generate the shared secret.
    type DecapsKey;
    /// A serialized (public) encapsulation key byte array of the correct length
    type EncapsByteArray;
    /// A serialized (private) decapsulation key of the correct length
    type DecapsByteArray;


    /// Generates an encapsulation and decapsulation key pair specific to this security parameter set. <br>
    /// This function utilizes the OS default random number generator and is intended to operate in constant
    /// time outside of `rho` which crosses the trust boundary in the clear. The function suffix will change
    /// in the forthcoming 0.2.0 release.
    /// # Errors
    /// Returns an error when the random number generator fails.
    /// # Examples
    /// ```rust
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// use fips203::ml_kem_512;                             // Could also be ml_kem_768 or ml_kem_1024.
    /// use fips203::traits::{KeyGen, SerDes, Decaps, Encaps};
    ///
    /// let (ek1, dk1) = ml_kem_512::KG::try_keygen_vt()?;   // Party 1 generates both encaps and decaps keys
    /// let ek1_bytes = ek1.into_bytes();                    // Party 1 serializes the encaps key
    ///
    /// let ek2_bytes = ek1_bytes;                           // Party 1 sends encaps bytes to party 2
    ///
    /// let ek2 = ml_kem_512::EncapsKey::try_from_bytes(ek2_bytes)?;  // Party 2 deserializes the encaps key
    /// let (ssk2, ct2) = ek2.try_encaps_vt()?;              // Party 2 generates shared secret and ciphertext
    /// let ct2_bytes = ct2.into_bytes();                    // Party 2 serializes the ciphertext
    ///
    /// let ct1_bytes = ct2_bytes;                           // Party 2 sends the ciphertext to party 1
    ///
    /// let ct1 = ml_kem_512::CipherText::try_from_bytes(ct1_bytes)?; // Party 1 deserializes the ciphertext
    /// let ssk1 = dk1.try_decaps_vt(&ct1)?;                 // Party 1 runs decaps to generate the shared secret
    ///
    /// assert_eq!(ssk1, ssk2);                              // Each party has the same shared secret
    /// # Ok(())}
    /// ```
    #[cfg(feature = "default-rng")]
    fn try_keygen_vt() -> Result<(Self::EncapsKey, Self::DecapsKey), &'static str> {
        Self::try_keygen_with_rng_vt(&mut OsRng)
    }


    /// Generates an encapsulation and decapsulation key key pair specific to this security parameter set. <br>
    /// This function utilizes a provided random number generator and is intended to operate in constant
    /// time outside of `rho` which crosses the trust boundary in the clear. The function suffix will change
    /// in the forthcoming 0.2.0 release.
    /// # Errors
    /// Returns an error when the random number generator fails.
    /// # Examples
    /// ```rust
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// use rand_core::OsRng;
    /// use fips203::ml_kem_512;                             // Could also be ml_kem_768 or ml_kem_1024.
    /// use fips203::traits::{KeyGen, SerDes, Decaps, Encaps};
    ///
    /// let (ek1, dk1) = ml_kem_512::KG::try_keygen_with_rng_vt(&mut OsRng)?;   // Party 1 generates both encaps and decaps keys
    /// let ek1_bytes = ek1.into_bytes();                    // Party 1 serializes the encaps key
    ///
    /// let ek2_bytes = ek1_bytes;                           // Party 1 sends encaps bytes to party 2
    ///
    /// let ek2 = ml_kem_512::EncapsKey::try_from_bytes(ek2_bytes)?;  // Party 2 deserializes the encaps key
    /// let (ssk2, ct2) = ek2.try_encaps_vt()?;              // Party 2 generates shared secret and ciphertext
    /// let ct2_bytes = ct2.into_bytes();                    // Party 2 serializes the ciphertext
    ///
    /// let ct1_bytes = ct2_bytes;                           // Party 2 sends the ciphertext to party 1
    ///
    /// let ct1 = ml_kem_512::CipherText::try_from_bytes(ct1_bytes)?; // Party 1 deserializes the ciphertext
    /// let ssk1 = dk1.try_decaps_vt(&ct1)?;                 // Party 1 runs decaps to generate the shared secret
    ///
    /// assert_eq!(ssk1, ssk2);                              // Each party has the same shared secret
    /// # Ok(())}
    /// ```
    fn try_keygen_with_rng_vt(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::EncapsKey, Self::DecapsKey), &'static str>;


    /// Performs validation between an encapsulation key and a decapsulation key (both in byte arrays), perhaps in the
    /// scenario where both have been serialized, stored to disk, and then retrieved. This function is not intended
    /// to operate in constant-time. The function suffix will change in the forthcoming 0.2.0 release.
    /// # Examples
    /// ```rust
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// use rand_core::OsRng;
    /// use fips203::ml_kem_512;                             // Could also be ml_kem_768 or ml_kem_1024.
    /// use fips203::traits::{KeyGen, SerDes, Decaps, Encaps};
    ///
    /// let (ek, dk) = ml_kem_512::KG::try_keygen_with_rng_vt(&mut OsRng)?;
    /// let ek_bytes = ek.into_bytes();    // Serialize and perhaps store-then-restore encaps key
    /// let dk_bytes = dk.into_bytes();    // Serialize and perhaps store-then-restore decaps key
    /// assert!(ml_kem_512::KG::validate_keypair_vt(&ek_bytes, &dk_bytes));  // Validate their correspondence
    ///
    /// # Ok(())}
    /// ```
    fn validate_keypair_vt(ek: &Self::EncapsByteArray, dk: &Self::DecapsByteArray) -> bool;
}


/// The `Encaps` trait uses the encapsulation key to generate the ciphertext and shared secret.
pub trait Encaps {
    /// The common shared secret
    type SharedSecretKey;
    /// The ciphertext transmitted from the remote party to the originator.
    type CipherText;


    /// Generates a shared secret and ciphertext from an encapsulation key specific to this security parameter set. <br>
    /// This function utilizes the OS default random number generator and is intended to operate in constant
    /// time outside of `rho` which crosses the trust boundary in the clear. The function suffix will change in the
    /// forthcoming 0.2.0 release.
    /// # Errors
    /// Returns an error when the random number generator fails or an internal error condition arises.
    /// # Examples
    /// ```rust
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// use rand_core::OsRng;
    /// use fips203::ml_kem_512;                             // Could also be ml_kem_768 or ml_kem_1024.
    /// use fips203::traits::{KeyGen, SerDes, Decaps, Encaps};
    ///
    /// let (ek1, dk1) = ml_kem_512::KG::try_keygen_with_rng_vt(&mut OsRng)?;   // Party 1 generates both encaps and decaps keys
    /// let ek1_bytes = ek1.into_bytes();                    // Party 1 serializes the encaps key
    ///
    /// let ek2_bytes = ek1_bytes;                           // Party 1 sends encaps bytes to party 2
    ///
    /// let ek2 = ml_kem_512::EncapsKey::try_from_bytes(ek2_bytes)?;  // Party 2 deserializes the encaps key
    /// let (ssk2, ct2) = ek2.try_encaps_vt()?;              // Party 2 generates shared secret and ciphertext
    /// let ct2_bytes = ct2.into_bytes();                    // Party 2 serializes the ciphertext
    ///
    /// let ct1_bytes = ct2_bytes;                           // Party 2 sends the ciphertext to party 1
    ///
    /// let ct1 = ml_kem_512::CipherText::try_from_bytes(ct1_bytes)?; // Party 1 deserializes the ciphertext
    /// let ssk1 = dk1.try_decaps_vt(&ct1)?;                 // Party 1 runs decaps to generate the shared secret
    ///
    /// assert_eq!(ssk1, ssk2);                              // Each party has the same shared secret
    /// # Ok(())}
    /// ```
    #[cfg(feature = "default-rng")]
    fn try_encaps_vt(&self) -> Result<(Self::SharedSecretKey, Self::CipherText), &'static str> {
        self.try_encaps_with_rng_vt(&mut OsRng)
    }


    /// Generates a shared secret and ciphertext from an encapsulation key specific to this security parameter set. <br>
    /// This function utilizes a provided random number generator and is intended to operate in constant
    /// time. The function suffix will change in the forthcoming 0.2.0 release.
    /// # Errors
    /// Returns an error when the random number generator fails or an internal error condition arises.
    /// # Examples
    /// ```rust
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// use rand_core::OsRng;
    /// use fips203::ml_kem_512;                             // Could also be ml_kem_768 or ml_kem_1024.
    /// use fips203::traits::{KeyGen, SerDes, Decaps, Encaps};
    ///
    /// let (ek1, dk1) = ml_kem_512::KG::try_keygen_with_rng_vt(&mut OsRng)?;   // Party 1 generates both encaps and decaps keys
    /// let ek1_bytes = ek1.into_bytes();                    // Party 1 serializes the encaps key
    ///
    /// let ek2_bytes = ek1_bytes;                           // Party 1 sends encaps bytes to party 2
    ///
    /// let ek2 = ml_kem_512::EncapsKey::try_from_bytes(ek2_bytes)?;  // Party 2 deserializes the encaps key
    /// let (ssk2, ct2) = ek2.try_encaps_with_rng_vt(&mut OsRng)?;    // Party 2 generates shared secret and ciphertext
    /// let ct2_bytes = ct2.into_bytes();                    // Party 2 serializes the ciphertext
    ///
    /// let ct1_bytes = ct2_bytes;                           // Party 2 sends the ciphertext to party 1
    ///
    /// let ct1 = ml_kem_512::CipherText::try_from_bytes(ct1_bytes)?; // Party 1 deserializes the ciphertext
    /// let ssk1 = dk1.try_decaps_vt(&ct1)?;                 // Party 1 runs decaps to generate the shared secret
    ///
    /// assert_eq!(ssk1, ssk2);                              // Each party has the same shared secret
    /// # Ok(())}
    /// ```
    fn try_encaps_with_rng_vt(
        &self, rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::SharedSecretKey, Self::CipherText), &'static str>;
}


/// The `Decaps` trait uses the decapsulation key and ciphertext to generate the shared secret.
pub trait Decaps {
    /// Ciphertext struct
    type CipherText;
    /// Shared secret struct
    type SharedSecretKey;


    /// Generates a shared secret from a decapsulation key and ciphertext specific to this security parameter set. <br>
    /// This function is intended to operate in constant-time. The function suffix will change in the forthcoming 0.2.0
    /// release.
    /// # Errors
    /// Returns an error when the random number generator fails or an internal error condition arises.
    /// # Examples
    /// ```rust
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// use rand_core::OsRng;
    /// use fips203::ml_kem_512;                             // Could also be ml_kem_768 or ml_kem_1024.
    /// use fips203::traits::{KeyGen, SerDes, Decaps, Encaps};
    ///
    /// let (ek1, dk1) = ml_kem_512::KG::try_keygen_with_rng_vt(&mut OsRng)?;   // Party 1 generates both encaps and decaps keys
    /// let ek1_bytes = ek1.into_bytes();                    // Party 1 serializes the encaps key
    ///
    /// let ek2_bytes = ek1_bytes;                           // Party 1 sends encaps bytes to party 2
    ///
    /// let ek2 = ml_kem_512::EncapsKey::try_from_bytes(ek2_bytes)?;  // Party 2 deserializes the encaps key
    /// let (ssk2, ct2) = ek2.try_encaps_with_rng_vt(&mut OsRng)?;    // Party 2 generates shared secret and ciphertext
    /// let ct2_bytes = ct2.into_bytes();                    // Party 2 serializes the ciphertext
    ///
    /// let ct1_bytes = ct2_bytes;                           // Party 2 sends the ciphertext to party 1
    ///
    /// let ct1 = ml_kem_512::CipherText::try_from_bytes(ct1_bytes)?; // Party 1 deserializes the ciphertext
    /// let ssk1 = dk1.try_decaps_vt(&ct1)?;                 // Party 1 runs decaps to generate the shared secret
    ///
    /// assert_eq!(ssk1, ssk2);                              // Each party has the same shared secret
    /// # Ok(())}
    /// ```
    fn try_decaps_vt(&self, ct: &Self::CipherText) -> Result<Self::SharedSecretKey, &'static str>;
}


/// Serialization and Deserialization of structs
pub trait SerDes {
    /// Correctly sized byte array for struct
    type ByteArray;


    /// Produces a byte array of fixed-size specific to the struct being serialized.
    /// # Examples
    /// ```rust
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// use rand_core::OsRng;
    /// use fips203::ml_kem_512;                             // Could also be ml_kem_768 or ml_kem_1024.
    /// use fips203::traits::{KeyGen, SerDes, Decaps, Encaps};
    ///
    /// let (ek1, dk1) = ml_kem_512::KG::try_keygen_with_rng_vt(&mut OsRng)?;   // Party 1 generates both encaps and decaps keys
    /// let ek1_bytes = ek1.into_bytes();                    // Party 1 serializes the encaps key
    ///
    /// let ek2_bytes = ek1_bytes;                           // Party 1 sends encaps bytes to party 2
    ///
    /// let ek2 = ml_kem_512::EncapsKey::try_from_bytes(ek2_bytes)?;  // Party 2 deserializes the encaps key
    /// let (ssk2, ct2) = ek2.try_encaps_with_rng_vt(&mut OsRng)?;    // Party 2 generates shared secret and ciphertext
    /// let ct2_bytes = ct2.into_bytes();                    // Party 2 serializes the ciphertext
    ///
    /// let ct1_bytes = ct2_bytes;                           // Party 2 sends the ciphertext to party 1
    ///
    /// let ct1 = ml_kem_512::CipherText::try_from_bytes(ct1_bytes)?; // Party 1 deserializes the ciphertext
    /// let ssk1 = dk1.try_decaps_vt(&ct1)?;                 // Party 1 runs decaps to generate the shared secret
    ///
    /// assert_eq!(ssk1, ssk2);                              // Each party has the same shared secret
    /// # Ok(())}
    /// ```
    fn into_bytes(self) -> Self::ByteArray;


    /// Consumes a byte array of fixed-size specific to the struct being deserialized; performs validation
    /// # Errors
    /// Returns an error on malformed input.
    /// # Examples
    /// ```rust
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// use rand_core::OsRng;
    /// use fips203::ml_kem_512;                             // Could also be ml_kem_768 or ml_kem_1024.
    /// use fips203::traits::{KeyGen, SerDes, Decaps, Encaps};
    ///
    /// let (ek1, dk1) = ml_kem_512::KG::try_keygen_with_rng_vt(&mut OsRng)?;   // Party 1 generates both encaps and decaps keys
    /// let ek1_bytes = ek1.into_bytes();                    // Party 1 serializes the encaps key
    ///
    /// let ek2_bytes = ek1_bytes;                           // Party 1 sends encaps bytes to party 2
    ///
    /// let ek2 = ml_kem_512::EncapsKey::try_from_bytes(ek2_bytes)?;  // Party 2 deserializes the encaps key
    /// let (ssk2, ct2) = ek2.try_encaps_with_rng_vt(&mut OsRng)?;    // Party 2 generates shared secret and ciphertext
    /// let ct2_bytes = ct2.into_bytes();                    // Party 2 serializes the ciphertext
    ///
    /// let ct1_bytes = ct2_bytes;                           // Party 2 sends the ciphertext to party 1
    ///
    /// let ct1 = ml_kem_512::CipherText::try_from_bytes(ct1_bytes)?; // Party 1 deserializes the ciphertext
    /// let ssk1 = dk1.try_decaps_vt(&ct1)?;                 // Party 1 runs decaps to generate the shared secret
    ///
    /// assert_eq!(ssk1, ssk2);                              // Each party has the same shared secret
    /// # Ok(())}
    /// ```
    fn try_from_bytes(ba: Self::ByteArray) -> Result<Self, &'static str>
    where
        Self: Sized;
}
