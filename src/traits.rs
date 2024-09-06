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
    /// time outside of `rho` which crosses the trust boundary in the clear.
    /// # Errors
    /// Returns an error when the random number generator fails.
    /// # Examples
    /// ```rust
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// # #[cfg(feature = "ml-kem-512")] {
    /// use fips203::ml_kem_512;                             // Could also be ml_kem_768 or ml_kem_1024.
    /// use fips203::traits::{KeyGen, SerDes, Decaps, Encaps};
    ///
    /// let (ek1, dk1) = ml_kem_512::KG::try_keygen()?;   // Party 1 generates both encaps and decaps keys
    /// let ek1_bytes = ek1.into_bytes();                    // Party 1 serializes the encaps key
    ///
    /// let ek2_bytes = ek1_bytes;                           // Party 1 sends encaps bytes to party 2
    ///
    /// let ek2 = ml_kem_512::EncapsKey::try_from_bytes(ek2_bytes)?;  // Party 2 deserializes the encaps key
    /// let (ssk2, ct2) = ek2.try_encaps()?;              // Party 2 generates shared secret and ciphertext
    /// let ct2_bytes = ct2.into_bytes();                    // Party 2 serializes the ciphertext
    ///
    /// let ct1_bytes = ct2_bytes;                           // Party 2 sends the ciphertext to party 1
    ///
    /// let ct1 = ml_kem_512::CipherText::try_from_bytes(ct1_bytes)?; // Party 1 deserializes the ciphertext
    /// let ssk1 = dk1.try_decaps(&ct1)?;                 // Party 1 runs decaps to generate the shared secret
    ///
    /// assert_eq!(ssk1, ssk2);                              // Each party has the same shared secret
    /// # }
    /// # Ok(())}
    /// ```
    #[cfg(feature = "default-rng")]
    fn try_keygen() -> Result<(Self::EncapsKey, Self::DecapsKey), &'static str> {
        Self::try_keygen_with_rng(&mut OsRng)
    }


    /// Generates an encapsulation and decapsulation key key pair specific to this security parameter set. <br>
    /// This function utilizes a provided random number generator and is intended to operate in constant
    /// time outside of `rho` which crosses the trust boundary in the clear.
    /// # Errors
    /// Returns an error when the random number generator fails.
    /// # Examples
    /// ```rust
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// # #[cfg(feature = "ml-kem-512")] {
    /// use rand_core::OsRng;
    /// use fips203::ml_kem_512;                             // Could also be ml_kem_768 or ml_kem_1024.
    /// use fips203::traits::{KeyGen, SerDes, Decaps, Encaps};
    ///
    /// let (ek1, dk1) = ml_kem_512::KG::try_keygen_with_rng(&mut OsRng)?;   // Party 1 generates both encaps and decaps keys
    /// let ek1_bytes = ek1.into_bytes();                    // Party 1 serializes the encaps key
    ///
    /// let ek2_bytes = ek1_bytes;                           // Party 1 sends encaps bytes to party 2
    ///
    /// let ek2 = ml_kem_512::EncapsKey::try_from_bytes(ek2_bytes)?;  // Party 2 deserializes the encaps key
    /// let (ssk2, ct2) = ek2.try_encaps_with_rng(&mut OsRng)?;       // Party 2 generates shared secret and ciphertext
    /// let ct2_bytes = ct2.into_bytes();                    // Party 2 serializes the ciphertext
    ///
    /// let ct1_bytes = ct2_bytes;                           // Party 2 sends the ciphertext to party 1
    ///
    /// let ct1 = ml_kem_512::CipherText::try_from_bytes(ct1_bytes)?; // Party 1 deserializes the ciphertext
    /// let ssk1 = dk1.try_decaps(&ct1)?;                 // Party 1 runs decaps to generate the shared secret
    ///
    /// assert_eq!(ssk1, ssk2);                              // Each party has the same shared secret
    /// # }
    /// # Ok(())}
    /// ```
    fn try_keygen_with_rng(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::EncapsKey, Self::DecapsKey), &'static str>;


    /// Generates an encapsulation and decapsulation key key pair specific to this security parameter set
    /// based on a provided seed. <br>
    /// This function is intended to operate in constant time outside of `rho` which crosses the trust
    /// boundary in the clear.
    /// # Examples
    /// ```rust
    /// # use std::error::Error;
    /// # use crate::fips203::RngCore;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// # #[cfg(feature = "ml-kem-512")] {
    /// use rand_core::OsRng;
    /// use fips203::ml_kem_512;                             // Could also be ml_kem_768 or ml_kem_1024.
    /// use fips203::traits::{KeyGen, SerDes, Decaps, Encaps};
    ///
    /// let (mut d, mut z) = ([0u8; 32], [0u8; 32]);         // Note that (d,z) are secret values
    /// rand::thread_rng().fill_bytes(&mut d);
    /// rand::thread_rng().fill_bytes(&mut z);
    ///
    /// let (ek1, dk1) = ml_kem_512::KG::keygen_from_seed(d, z);   // Party 1 generates both encaps and decaps keys
    /// let ek1_bytes = ek1.into_bytes();                    // Party 1 serializes the encaps key
    ///
    /// let ek2_bytes = ek1_bytes;                           // Party 1 sends encaps bytes to party 2
    ///
    /// let ek2 = ml_kem_512::EncapsKey::try_from_bytes(ek2_bytes)?;  // Party 2 deserializes the encaps key
    /// let (ssk2, ct2) = ek2.try_encaps_with_rng(&mut OsRng)?;       // Party 2 generates shared secret and ciphertext
    /// let ct2_bytes = ct2.into_bytes();                    // Party 2 serializes the ciphertext
    ///
    /// let ct1_bytes = ct2_bytes;                           // Party 2 sends the ciphertext to party 1
    ///
    /// let ct1 = ml_kem_512::CipherText::try_from_bytes(ct1_bytes)?; // Party 1 deserializes the ciphertext
    /// let ssk1 = dk1.try_decaps(&ct1)?;                 // Party 1 runs decaps to generate the shared secret
    ///
    /// assert_eq!(ssk1, ssk2);                              // Each party has the same shared secret
    /// # }
    /// # Ok(())}
    /// ```
    #[must_use]
    fn keygen_from_seed(d: [u8; 32], z: [u8; 32]) -> (Self::EncapsKey, Self::DecapsKey);


    /// Performs validation between an encapsulation key and a decapsulation key (both in byte arrays), perhaps in the
    /// scenario where both have been serialized, stored to disk, and then retrieved. This function is not intended
    /// to operate in constant-time.
    /// # Examples
    /// ```rust
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// # #[cfg(feature = "ml-kem-512")] {
    /// use rand_core::OsRng;
    /// use fips203::ml_kem_512;                             // Could also be ml_kem_768 or ml_kem_1024.
    /// use fips203::traits::{KeyGen, SerDes, Decaps, Encaps};
    ///
    /// let (ek, dk) = ml_kem_512::KG::try_keygen_with_rng(&mut OsRng)?;
    /// let ek_bytes = ek.into_bytes();    // Serialize and perhaps store-then-restore encaps key
    /// let dk_bytes = dk.into_bytes();    // Serialize and perhaps store-then-restore decaps key
    /// assert!(ml_kem_512::KG::validate_keypair_vartime(&ek_bytes, &dk_bytes));  // Validate their correspondence
    ///
    /// # }
    /// # Ok(())}
    /// ```
    fn validate_keypair_vartime(ek: &Self::EncapsByteArray, dk: &Self::DecapsByteArray) -> bool;
}


/// The `Encaps` trait uses the encapsulation key to generate the ciphertext and shared secret.
pub trait Encaps {
    /// The common shared secret
    type SharedSecretKey;
    /// The ciphertext transmitted from the remote party to the originator.
    type CipherText;


    /// Generates a shared secret and ciphertext from an encapsulation key specific to this security parameter set. <br>
    /// This function utilizes the OS default random number generator and is intended to operate in constant
    /// time outside of `rho` which crosses the trust boundary in the clear.
    /// # Errors
    /// Returns an error when the random number generator fails or an internal error condition arises.
    /// # Examples
    /// ```rust
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// # #[cfg(feature = "ml-kem-512")] {
    /// use rand_core::OsRng;
    /// use fips203::ml_kem_512;                             // Could also be ml_kem_768 or ml_kem_1024.
    /// use fips203::traits::{KeyGen, SerDes, Decaps, Encaps};
    ///
    /// let (ek1, dk1) = ml_kem_512::KG::try_keygen_with_rng(&mut OsRng)?;   // Party 1 generates both encaps and decaps keys
    /// let ek1_bytes = ek1.into_bytes();                    // Party 1 serializes the encaps key
    ///
    /// let ek2_bytes = ek1_bytes;                           // Party 1 sends encaps bytes to party 2
    ///
    /// let ek2 = ml_kem_512::EncapsKey::try_from_bytes(ek2_bytes)?;  // Party 2 deserializes the encaps key
    /// let (ssk2, ct2) = ek2.try_encaps()?;              // Party 2 generates shared secret and ciphertext
    /// let ct2_bytes = ct2.into_bytes();                    // Party 2 serializes the ciphertext
    ///
    /// let ct1_bytes = ct2_bytes;                           // Party 2 sends the ciphertext to party 1
    ///
    /// let ct1 = ml_kem_512::CipherText::try_from_bytes(ct1_bytes)?; // Party 1 deserializes the ciphertext
    /// let ssk1 = dk1.try_decaps(&ct1)?;                 // Party 1 runs decaps to generate the shared secret
    ///
    /// assert_eq!(ssk1, ssk2);                              // Each party has the same shared secret
    /// # }
    /// # Ok(())}
    /// ```
    #[cfg(feature = "default-rng")]
    fn try_encaps(&self) -> Result<(Self::SharedSecretKey, Self::CipherText), &'static str> {
        self.try_encaps_with_rng(&mut OsRng)
    }


    /// Generates a shared secret and ciphertext from an encapsulation key specific to this security parameter set. <br>
    /// This function utilizes a provided random number generator and is intended to operate in constant
    /// time.
    /// # Errors
    /// Returns an error when the random number generator fails or an internal error condition arises.
    /// # Examples
    /// ```rust
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// # #[cfg(feature = "ml-kem-512")] {
    /// use rand_core::OsRng;
    /// use fips203::ml_kem_512;                             // Could also be ml_kem_768 or ml_kem_1024.
    /// use fips203::traits::{KeyGen, SerDes, Decaps, Encaps};
    ///
    /// let (ek1, dk1) = ml_kem_512::KG::try_keygen_with_rng(&mut OsRng)?;   // Party 1 generates both encaps and decaps keys
    /// let ek1_bytes = ek1.into_bytes();                    // Party 1 serializes the encaps key
    ///
    /// let ek2_bytes = ek1_bytes;                           // Party 1 sends encaps bytes to party 2
    ///
    /// let ek2 = ml_kem_512::EncapsKey::try_from_bytes(ek2_bytes)?;  // Party 2 deserializes the encaps key
    /// let (ssk2, ct2) = ek2.try_encaps_with_rng(&mut OsRng)?;    // Party 2 generates shared secret and ciphertext
    /// let ct2_bytes = ct2.into_bytes();                    // Party 2 serializes the ciphertext
    ///
    /// let ct1_bytes = ct2_bytes;                           // Party 2 sends the ciphertext to party 1
    ///
    /// let ct1 = ml_kem_512::CipherText::try_from_bytes(ct1_bytes)?; // Party 1 deserializes the ciphertext
    /// let ssk1 = dk1.try_decaps(&ct1)?;                 // Party 1 runs decaps to generate the shared secret
    ///
    /// assert_eq!(ssk1, ssk2);                              // Each party has the same shared secret
    /// # }
    /// # Ok(())}
    /// ```
    fn try_encaps_with_rng(
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
    /// This function is intended to operate in constant-time.
    /// # Errors
    /// Returns an error when the random number generator fails or an internal error condition arises.
    /// # Examples
    /// ```rust
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// # #[cfg(feature = "ml-kem-512")] {
    /// use rand_core::OsRng;
    /// use fips203::ml_kem_512;                             // Could also be ml_kem_768 or ml_kem_1024.
    /// use fips203::traits::{KeyGen, SerDes, Decaps, Encaps};
    ///
    /// let (ek1, dk1) = ml_kem_512::KG::try_keygen_with_rng(&mut OsRng)?;   // Party 1 generates both encaps and decaps keys
    /// let ek1_bytes = ek1.into_bytes();                    // Party 1 serializes the encaps key
    ///
    /// let ek2_bytes = ek1_bytes;                           // Party 1 sends encaps bytes to party 2
    ///
    /// let ek2 = ml_kem_512::EncapsKey::try_from_bytes(ek2_bytes)?;  // Party 2 deserializes the encaps key
    /// let (ssk2, ct2) = ek2.try_encaps_with_rng(&mut OsRng)?;    // Party 2 generates shared secret and ciphertext
    /// let ct2_bytes = ct2.into_bytes();                    // Party 2 serializes the ciphertext
    ///
    /// let ct1_bytes = ct2_bytes;                           // Party 2 sends the ciphertext to party 1
    ///
    /// let ct1 = ml_kem_512::CipherText::try_from_bytes(ct1_bytes)?; // Party 1 deserializes the ciphertext
    /// let ssk1 = dk1.try_decaps(&ct1)?;                 // Party 1 runs decaps to generate the shared secret
    ///
    /// assert_eq!(ssk1, ssk2);                              // Each party has the same shared secret
    /// # }
    /// # Ok(())}
    /// ```
    fn try_decaps(&self, ct: &Self::CipherText) -> Result<Self::SharedSecretKey, &'static str>;
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
    /// # #[cfg(feature = "ml-kem-512")] {
    /// use rand_core::OsRng;
    /// use fips203::ml_kem_512;                             // Could also be ml_kem_768 or ml_kem_1024.
    /// use fips203::traits::{KeyGen, SerDes, Decaps, Encaps};
    ///
    /// let (ek1, dk1) = ml_kem_512::KG::try_keygen_with_rng(&mut OsRng)?;   // Party 1 generates both encaps and decaps keys
    /// let ek1_bytes = ek1.into_bytes();                    // Party 1 serializes the encaps key
    ///
    /// let ek2_bytes = ek1_bytes;                           // Party 1 sends encaps bytes to party 2
    ///
    /// let ek2 = ml_kem_512::EncapsKey::try_from_bytes(ek2_bytes)?;  // Party 2 deserializes the encaps key
    /// let (ssk2, ct2) = ek2.try_encaps_with_rng(&mut OsRng)?;    // Party 2 generates shared secret and ciphertext
    /// let ct2_bytes = ct2.into_bytes();                    // Party 2 serializes the ciphertext
    ///
    /// let ct1_bytes = ct2_bytes;                           // Party 2 sends the ciphertext to party 1
    ///
    /// let ct1 = ml_kem_512::CipherText::try_from_bytes(ct1_bytes)?; // Party 1 deserializes the ciphertext
    /// let ssk1 = dk1.try_decaps(&ct1)?;                 // Party 1 runs decaps to generate the shared secret
    ///
    /// assert_eq!(ssk1, ssk2);                              // Each party has the same shared secret
    /// # }
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
    /// # #[cfg(feature = "ml-kem-512")] {
    /// use rand_core::OsRng;
    /// use fips203::ml_kem_512;                             // Could also be ml_kem_768 or ml_kem_1024.
    /// use fips203::traits::{KeyGen, SerDes, Decaps, Encaps};
    ///
    /// let (ek1, dk1) = ml_kem_512::KG::try_keygen_with_rng(&mut OsRng)?;   // Party 1 generates both encaps and decaps keys
    /// let ek1_bytes = ek1.into_bytes();                    // Party 1 serializes the encaps key
    ///
    /// let ek2_bytes = ek1_bytes;                           // Party 1 sends encaps bytes to party 2
    ///
    /// let ek2 = ml_kem_512::EncapsKey::try_from_bytes(ek2_bytes)?;  // Party 2 deserializes the encaps key
    /// let (ssk2, ct2) = ek2.try_encaps_with_rng(&mut OsRng)?;    // Party 2 generates shared secret and ciphertext
    /// let ct2_bytes = ct2.into_bytes();                    // Party 2 serializes the ciphertext
    ///
    /// let ct1_bytes = ct2_bytes;                           // Party 2 sends the ciphertext to party 1
    ///
    /// let ct1 = ml_kem_512::CipherText::try_from_bytes(ct1_bytes)?; // Party 1 deserializes the ciphertext
    /// let ssk1 = dk1.try_decaps(&ct1)?;                 // Party 1 runs decaps to generate the shared secret
    ///
    /// assert_eq!(ssk1, ssk2);                              // Each party has the same shared secret
    /// # }
    /// # Ok(())}
    /// ```
    fn try_from_bytes(ba: Self::ByteArray) -> Result<Self, &'static str>
    where
        Self: Sized;
}
