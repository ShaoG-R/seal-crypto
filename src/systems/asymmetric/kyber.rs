//! Provides an implementation of the Kyber post-quantum KEM.

use crate::errors::{Error as CryptoError, Error};
use crate::traits::{
    kem::{EncapsulatedKey, Kem, KemError, SharedSecret},
    key::{KeyGenerator, PrivateKey, PublicKey},
};
use pqcrypto_kyber::{kyber1024, kyber512, kyber768};
use pqcrypto_traits::kem::{
    Ciphertext as PqCiphertext, PublicKey as PqPublicKey, SecretKey as PqSecretKey,
    SharedSecret as PqSharedSecret,
};
use std::marker::PhantomData;
use zeroize::Zeroizing;

// ------------------- Marker Structs and Trait for Kyber Parameters -------------------

mod private {
    pub trait Sealed {}
}

/// A trait that defines the parameters for a specific Kyber security level.
/// This is a sealed trait, meaning only types within this crate can implement it.
pub trait KyberParams: private::Sealed + Send + Sync + 'static {
    /// The length in bytes of a public key.
    const PUBLIC_KEY_BYTES: usize;
    /// The length in bytes of a secret key.
    const SECRET_KEY_BYTES: usize;
    /// The length in bytes of the encapsulated key (ciphertext).
    const CIPHERTEXT_BYTES: usize;

    /// The underlying `pqcrypto` public key type.
    type PqPublicKey: PqPublicKey + Clone;
    /// The underlying `pqcrypto` secret key type.
    type PqSecretKey: PqSecretKey + Clone;
    /// The underlying `pqcrypto` ciphertext type.
    type PqCiphertext: PqCiphertext + Clone + Copy;
    /// The underlying `pqcrypto` shared secret type.
    type PqSharedSecret: PqSharedSecret;

    /// Generates a keypair for this security level.
    fn keypair() -> (Self::PqPublicKey, Self::PqSecretKey);
    /// Encapsulates a shared secret.
    fn encapsulate(pk: &Self::PqPublicKey) -> (Self::PqSharedSecret, Self::PqCiphertext);
    /// Decapsulates a shared secret.
    fn decapsulate(ct: &Self::PqCiphertext, sk: &Self::PqSecretKey) -> Self::PqSharedSecret;
}

/// Marker struct for Kyber-512 parameters.
#[derive(Debug, Default)]
pub struct Kyber512;
impl private::Sealed for Kyber512 {}
impl KyberParams for Kyber512 {
    const PUBLIC_KEY_BYTES: usize = kyber512::public_key_bytes();
    const SECRET_KEY_BYTES: usize = kyber512::secret_key_bytes();
    const CIPHERTEXT_BYTES: usize = kyber512::ciphertext_bytes();
    type PqPublicKey = kyber512::PublicKey;
    type PqSecretKey = kyber512::SecretKey;
    type PqCiphertext = kyber512::Ciphertext;
    type PqSharedSecret = kyber512::SharedSecret;
    fn keypair() -> (Self::PqPublicKey, Self::PqSecretKey) { kyber512::keypair() }
    fn encapsulate(pk: &Self::PqPublicKey) -> (Self::PqSharedSecret, Self::PqCiphertext) { kyber512::encapsulate(pk) }
    fn decapsulate(ct: &Self::PqCiphertext, sk: &Self::PqSecretKey) -> Self::PqSharedSecret { kyber512::decapsulate(ct, sk) }
}

/// Marker struct for Kyber-768 parameters.
#[derive(Debug, Default)]
pub struct Kyber768;
impl private::Sealed for Kyber768 {}
impl KyberParams for Kyber768 {
    const PUBLIC_KEY_BYTES: usize = kyber768::public_key_bytes();
    const SECRET_KEY_BYTES: usize = kyber768::secret_key_bytes();
    const CIPHERTEXT_BYTES: usize = kyber768::ciphertext_bytes();
    type PqPublicKey = kyber768::PublicKey;
    type PqSecretKey = kyber768::SecretKey;
    type PqCiphertext = kyber768::Ciphertext;
    type PqSharedSecret = kyber768::SharedSecret;
    fn keypair() -> (Self::PqPublicKey, Self::PqSecretKey) { kyber768::keypair() }
    fn encapsulate(pk: &Self::PqPublicKey) -> (Self::PqSharedSecret, Self::PqCiphertext) { kyber768::encapsulate(pk) }
    fn decapsulate(ct: &Self::PqCiphertext, sk: &Self::PqSecretKey) -> Self::PqSharedSecret { kyber768::decapsulate(ct, sk) }
}

/// Marker struct for Kyber-1024 parameters.
#[derive(Debug, Default)]
pub struct Kyber1024;
impl private::Sealed for Kyber1024 {}
impl KyberParams for Kyber1024 {
    const PUBLIC_KEY_BYTES: usize = kyber1024::public_key_bytes();
    const SECRET_KEY_BYTES: usize = kyber1024::secret_key_bytes();
    const CIPHERTEXT_BYTES: usize = kyber1024::ciphertext_bytes();
    type PqPublicKey = kyber1024::PublicKey;
    type PqSecretKey = kyber1024::SecretKey;
    type PqCiphertext = kyber1024::Ciphertext;
    type PqSharedSecret = kyber1024::SharedSecret;
    fn keypair() -> (Self::PqPublicKey, Self::PqSecretKey) { kyber1024::keypair() }
    fn encapsulate(pk: &Self::PqPublicKey) -> (Self::PqSharedSecret, Self::PqCiphertext) { kyber1024::encapsulate(pk) }
    fn decapsulate(ct: &Self::PqCiphertext, sk: &Self::PqSecretKey) -> Self::PqSharedSecret { kyber1024::decapsulate(ct, sk) }
}

// ------------------- Generic Kyber KEM Implementation -------------------

/// A generic struct representing the Kyber cryptographic system for a given parameter set.
#[derive(Debug, Default)]
pub struct KyberScheme<P: KyberParams> {
    _params: PhantomData<P>,
}

impl<P: KyberParams> KeyGenerator for KyberScheme<P> {

    fn generate_keypair() -> Result<(PublicKey, PrivateKey), Error> {
        let (pk, sk) = P::keypair();
        Ok((
            pk.as_bytes().to_vec(),
            Zeroizing::new(sk.as_bytes().to_vec()),
        ))
    }
}

impl<P: KyberParams> Kem for KyberScheme<P> {
    type PublicKey = PublicKey;
    type PrivateKey = PrivateKey;
    type EncapsulatedKey = EncapsulatedKey;

    fn encapsulate(public_key: &PublicKey) -> Result<(SharedSecret, EncapsulatedKey), Error>
    {
        if public_key.len() != P::PUBLIC_KEY_BYTES {
            return Err(KemError::InvalidPublicKey)?;
        }
        let pk = PqPublicKey::from_bytes(public_key)
            .map_err(|_| KemError::InvalidPublicKey)?;

        let (ss, ct) = P::encapsulate(&pk);

        Ok((
            Zeroizing::new(ss.as_bytes().to_vec()),
            ct.as_bytes().to_vec(),
        ))
    }

    fn decapsulate(
        private_key: &PrivateKey,
        encapsulated_key: &EncapsulatedKey,
    ) -> Result<SharedSecret, Error> {
        if private_key.len() != P::SECRET_KEY_BYTES {
            return Err(KemError::InvalidPrivateKey)?;
        }
        if encapsulated_key.len() != P::CIPHERTEXT_BYTES {
            return Err(KemError::InvalidEncapsulatedKey)?;
        }
        let sk = P::PqSecretKey::from_bytes(private_key)
            .map_err(|_| KemError::InvalidPrivateKey)?;
        let ct = P::PqCiphertext::from_bytes(encapsulated_key)
            .map_err(|_| KemError::InvalidEncapsulatedKey)?;

        let ss = P::decapsulate(&ct, &sk);

        Ok(Zeroizing::new(ss.as_bytes().to_vec()))
    }
}

// ------------------- Tests -------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn run_kyber_tests<P: KyberParams>() {
        type TestScheme<P> = KyberScheme<P>;

        // Test key generation
        let (pk, sk) = TestScheme::<P>::generate_keypair().unwrap();
        assert_eq!(pk.len(), P::PUBLIC_KEY_BYTES);
        assert_eq!(sk.len(), P::SECRET_KEY_BYTES);

        // Test KEM roundtrip
        let (ss1, encapsulated_key) = TestScheme::<P>::encapsulate(&pk).unwrap();
        let ss2 = TestScheme::<P>::decapsulate(&sk, &encapsulated_key).unwrap();
        assert_eq!(ss1, ss2);

        // Test wrong key decapsulation
        let (pk2, _sk2) = TestScheme::<P>::generate_keypair().unwrap();
        let (ss_for_pk2, encapsulated_key_for_pk2) = TestScheme::<P>::encapsulate(&pk2).unwrap();
        let wrong_ss = TestScheme::<P>::decapsulate(&sk, &encapsulated_key_for_pk2).unwrap();
        assert_ne!(ss_for_pk2, wrong_ss);

        // Test tampered ciphertext
        let (ss_orig, mut tampered_ct) = TestScheme::<P>::encapsulate(&pk).unwrap();
        tampered_ct[0] ^= 1;
        let tampered_ss = TestScheme::<P>::decapsulate(&sk, &tampered_ct).unwrap();
        assert_ne!(ss_orig, tampered_ss);
    }

    #[test]
    fn test_kyber_512() {
        run_kyber_tests::<Kyber512>();
    }

    #[test]
    fn test_kyber_768() {
        run_kyber_tests::<Kyber768>();
    }

    #[test]
    fn test_kyber_1024() {
        run_kyber_tests::<Kyber1024>();
    }
} 