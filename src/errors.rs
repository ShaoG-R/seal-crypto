//! Defines the top-level error type for the `seal-crypto` crate.

use crate::traits::{kem::KemError, sign::SignatureError, symmetric::SymmetricError};
use thiserror::Error;

/// The primary error type for the `seal-crypto` library.
///
/// This enum consolidates all possible failures from the underlying
/// cryptographic traits into a single, unified error type.
#[derive(Error, Debug)]
pub enum Error {
    /// An error occurred during a Key Encapsulation Mechanism (KEM) operation.
    #[error("KEM operation failed")]
    Kem(#[from] KemError),

    /// An error occurred during a digital signature operation.
    #[error("Signature operation failed")]
    Signature(#[from] SignatureError),

    /// An error occurred during a symmetric encryption or decryption operation.
    #[error("Symmetric cipher operation failed")]
    Symmetric(#[from] SymmetricError),

    /// An error occurred during key generation.
    #[error("Key generation failed")]
    KeyGeneration(#[source] Box<dyn std::error::Error + Send + Sync>),
} 