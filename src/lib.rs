//! # Seal-Crypto
//!
//! `seal-crypto` is the underlying cryptographic hybrid for the `seal-kit` ecosystem.
//! It provides a set of clean, composable, trait-based APIs for common
//! cryptographic operations, including:
//!
//! - Symmetric Authenticated Encryption (AEAD)
//! - Key Encapsulation Mechanisms (KEM)
//! - Digital Signatures
//!
//! This crate is designed to be highly modular and backend-agnostic. Implementations
//! for specific cryptographic algorithms (like AES-GCM, RSA, Kyber) are provided
//! and can be enabled via Cargo features.

pub use ::zeroize;
pub mod errors;
pub mod systems;
pub mod traits;

pub mod prelude {
    //! A "prelude" for users of the `seal-crypto` crate.
    //! This prelude is designed to be imported with a glob, i.e., `use seal_crypto::prelude::*;`.
    pub use ::zeroize;
    pub use crate::errors::Error as CryptoError;
    pub use crate::traits::{
        kem::Kem,
        key::KeyGenerator,
        sign::{Signer, Verifier},
        symmetric::{SymmetricDecryptor, SymmetricEncryptor},
    };
} 