//! Defines traits for digital signature creation and verification.

use thiserror::Error;
use crate::errors::Error;

/// Represents a digital signature.
pub type Signature = Vec<u8>;

/// Defines the errors that can occur during signing and verification.
#[derive(Error, Debug)]
pub enum SignatureError {
    /// Failed to create a digital signature.
    #[error("Signing failed")]
    Signing(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// Signature verification failed, indicating that the signature is invalid,
    /// the data has been tampered with, or the wrong key was used.
    #[error("Verification failed")]
    Verification(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// The provided public key is invalid for this operation.
    #[error("Invalid public key")]
    InvalidPublicKey,

    /// The provided private key is invalid for this operation.
    #[error("Invalid private key")]
    InvalidPrivateKey,

    /// The provided signature is malformed or has an invalid length.
    #[error("Invalid signature format")]
    InvalidSignature,
}

/// A trait for cryptographic schemes that can create digital signatures.
pub trait Signer {
    type PrivateKey;
    type Signature;
    /// Creates a digital signature for a given message digest.
    fn sign(private_key: &Self::PrivateKey, message: &[u8]) -> Result<Self::Signature, Error>;
}

/// A trait for cryptographic schemes that can verify digital signatures.
pub trait Verifier {
    type PublicKey;
    type Signature;
    /// Verifies a digital signature for a given message digest.
    ///
    /// # Returns
    /// `Ok(())` if the signature is valid, otherwise an `Err`.
    fn verify(
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<(), Error>;
} 