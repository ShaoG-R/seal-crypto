//! Provides an implementation of KEM and Signatures using RSA.
//!
//! This module uses:
//! - RSA-OAEP with SHA-256 for the KEM functionality.
//! - RSA-PSS with SHA-256 for the signature functionality.
//! Keys are expected to be in PKCS#8 DER format.

use crate::errors::{Error as CryptoError, Error};
use crate::traits::{
    kem::{EncapsulatedKey, Kem, KemError, SharedSecret},
    key::{KeyGenerator, PrivateKey, PublicKey},
    sign::{Signature, SignatureError, Signer, Verifier},
};
use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    pss::{SigningKey, VerifyingKey, Signature as PssSignature},
    rand_core::{RngCore, OsRng},
    Oaep, RsaPrivateKey, RsaPublicKey,
};
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use sha2::Sha256;
use zeroize::Zeroizing;
use std::marker::PhantomData;

// ------------------- Marker Structs and Trait for RSA Parameters -------------------

mod private {
    pub trait Sealed {}
}

/// A trait that defines the parameters for an RSA scheme, specifically the key size.
/// This is a sealed trait, meaning only types within this crate can implement it.
pub trait RsaParams: private::Sealed + Send + Sync + 'static {
    /// The number of bits for the RSA key.
    const KEY_BITS: usize;
}

/// Marker struct for RSA-2048.
#[derive(Debug, Default)]
pub struct Rsa2048;
impl private::Sealed for Rsa2048 {}
impl RsaParams for Rsa2048 {
    const KEY_BITS: usize = 2048;
}

/// Marker struct for RSA-4096.
#[derive(Debug, Default)]
pub struct Rsa4096;
impl private::Sealed for Rsa4096 {}
impl RsaParams for Rsa4096 {
    const KEY_BITS: usize = 4096;
}

// ------------------- Generic RSA Implementation -------------------

const SHARED_SECRET_SIZE: usize = 32;

/// A generic struct representing the RSA cryptographic system for a given parameter set.
#[derive(Debug, Default)]
pub struct RsaScheme<P: RsaParams> {
    _params: PhantomData<P>,
}

impl<P: RsaParams> KeyGenerator for RsaScheme<P> {

    fn generate_keypair() -> Result<(PublicKey, PrivateKey), Error> {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, P::KEY_BITS)
            .map_err(|e| CryptoError::KeyGeneration(Box::new(e)))?;
        let public_key = private_key.to_public_key();

        let private_key_der = private_key
            .to_pkcs8_der()
            .map_err(|e| CryptoError::KeyGeneration(e.into()))?;
        let public_key_der = public_key
            .to_public_key_der()
            .map_err(|e| CryptoError::KeyGeneration(e.into()))?;

        Ok((
            public_key_der.as_bytes().to_vec(),
            Zeroizing::new(private_key_der.as_bytes().to_vec()),
        ))
    }
}

impl<P: RsaParams> Kem for RsaScheme<P> {
    type PublicKey = PublicKey;
    type PrivateKey = PrivateKey;
    type EncapsulatedKey = EncapsulatedKey;

    fn encapsulate(public_key: &PublicKey) -> Result<(SharedSecret, EncapsulatedKey), Error> {
        let mut rng = OsRng;
        let rsa_public_key = RsaPublicKey::from_public_key_der(public_key)
            .map_err(|_| KemError::InvalidPublicKey)?;
        
        let mut shared_secret_bytes = vec![0u8; SHARED_SECRET_SIZE];
        rng.fill_bytes(&mut shared_secret_bytes);

        let padding = Oaep::new::<Sha256>();
        let encapsulated_key = rsa_public_key
            .encrypt(&mut rng, padding, &shared_secret_bytes)
            .map_err(|e| KemError::Encapsulation(Box::new(e)))?;

        Ok((Zeroizing::new(shared_secret_bytes), encapsulated_key))
    }

    fn decapsulate(
        private_key: &PrivateKey,
        encapsulated_key: &EncapsulatedKey,
    ) -> Result<SharedSecret, Error> {
        let rsa_private_key = RsaPrivateKey::from_pkcs8_der(private_key)
            .map_err(|_| KemError::InvalidPrivateKey)?;

        let padding = Oaep::new::<Sha256>();
        let shared_secret_bytes = rsa_private_key
            .decrypt(padding, encapsulated_key)
            .map_err(|e| KemError::Decapsulation(Box::new(e)))?;

        Ok(Zeroizing::new(shared_secret_bytes))
    }
}

impl<P: RsaParams> Signer for RsaScheme<P> {
    type PrivateKey = PrivateKey;
    type Signature = Signature;

    fn sign(private_key: &PrivateKey, message: &[u8]) -> Result<Signature, Error> {
        let rsa_private_key = RsaPrivateKey::from_pkcs8_der(private_key)
            .map_err(|_| SignatureError::InvalidPrivateKey)?;
        let signing_key = SigningKey::<Sha256>::new(rsa_private_key);
        let mut rng = OsRng;
        let signature = signing_key.sign_with_rng(&mut rng, message);
        Ok(signature.to_vec())
    }
}

impl<P: RsaParams> Verifier for RsaScheme<P> {
    type PublicKey = PublicKey;
    type Signature = Signature;
    
    fn verify(
        public_key: &PublicKey,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), Error> {
        let rsa_public_key = RsaPublicKey::from_public_key_der(public_key)
            .map_err(|_| SignatureError::InvalidPublicKey)?;
        let verifying_key = VerifyingKey::<Sha256>::new(rsa_public_key);
        let pss_signature = PssSignature::try_from(signature.as_slice())
            .map_err(|_| SignatureError::InvalidSignature)?;
        use rsa::signature::Verifier;
        Ok(verifying_key
            .verify(message, &pss_signature)
            .map_err(|e| SignatureError::Verification(Box::new(e)))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_rsa_tests<P: RsaParams>() {
        type TestScheme<P> = RsaScheme<P>;

        // Test key generation
        let (pk, sk) = TestScheme::<P>::generate_keypair().unwrap();
        assert!(!pk.is_empty());
        assert!(!sk.is_empty());

        // Test KEM roundtrip
        let (ss1, encapsulated_key) = TestScheme::<P>::encapsulate(&pk).unwrap();
        let ss2 = TestScheme::<P>::decapsulate(&sk, &encapsulated_key).unwrap();
        assert_eq!(ss1, ss2);

        // Test sign/verify roundtrip
        let message = b"this is the message to be signed";
        let signature = TestScheme::<P>::sign(&sk, message).unwrap();
        assert!(TestScheme::<P>::verify(&pk, message, &signature).is_ok());

        // Test tampered message verification fails
        let tampered_message = b"this is a different message";
        assert!(TestScheme::<P>::verify(&pk, tampered_message, &signature).is_err());

        // Test wrong key verification fails
        let (pk2, _) = TestScheme::<P>::generate_keypair().unwrap();
        assert!(TestScheme::<P>::verify(&pk2, message, &signature).is_err());
    }

    #[test]
    fn test_rsa_2048() {
        run_rsa_tests::<Rsa2048>();
    }

    #[test]
    fn test_rsa_4096() {
        run_rsa_tests::<Rsa4096>();
    }
} 