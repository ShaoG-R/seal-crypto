//! Defines traits for symmetric authenticated encryption.

use thiserror::Error;
use zeroize::Zeroizing;
use crate::errors::Error;

/// A key for a symmetric cipher.
pub type SymmetricKey = Zeroizing<Vec<u8>>;

/// Authenticated associated data (AAD).
pub type AssociatedData<'a> = &'a [u8];

/// Defines the errors that can occur during symmetric encryption and decryption.
#[derive(Error, Debug)]
pub enum SymmetricError {
    /// Failed to encrypt the plaintext.
    #[error("Encryption failed")]
    Encryption(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// Failed to decrypt the ciphertext. This commonly occurs if the key is wrong,
    /// the ciphertext or AAD has been tampered with, or the authentication tag is invalid.
    #[error("Decryption failed")]
    Decryption(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// The provided key has an invalid size.
    #[error("Invalid key size")]
    InvalidKeySize,

    /// The provided nonce has an invalid size.
    #[error("Invalid nonce size")]
    InvalidNonceSize,

    /// The provided ciphertext is malformed or truncated.
    #[error("Invalid ciphertext")]
    InvalidCiphertext,
}

/// A trait for a symmetric AEAD cipher system.
pub trait SymmetricCipher {
    /// The size of the key in bytes.
    const KEY_SIZE: usize;
    /// The size of the nonce in bytes.
    const NONCE_SIZE: usize;
    /// The size of the authentication tag in bytes.
    const TAG_SIZE: usize;
}

/// A trait for Authenticated Encryption with Associated Data (AEAD) ciphers.
pub trait SymmetricEncryptor: SymmetricCipher {
    type Key: 'static;
    
    /// Encrypts a plaintext with a given nonce, producing a ciphertext with tag.
    ///
    /// # Arguments
    /// * `key` - The secret key.
    /// * `nonce` - The nonce for this specific encryption operation. Must be unique for each call with the same key.
    /// * `plaintext` - The data to encrypt.
    /// * `aad` - Optional associated data to authenticate.
    ///
    /// # Returns
    /// The encrypted data concatenated with the authentication tag: `[ciphertext || tag]`.
    fn encrypt(
        key: &Self::Key,
        nonce: &[u8],
        plaintext: &[u8],
        aad: Option<AssociatedData>,
    ) -> Result<Vec<u8>, Error>;
}

/// A trait for AEAD ciphers that can decrypt a ciphertext.
pub trait SymmetricDecryptor: SymmetricCipher {
    type Key: 'static;
    
    /// Decrypts a ciphertext, producing the original plaintext.
    ///
    /// # Arguments
    /// * `key` - The secret key.
    /// * `nonce` - The nonce that was used to encrypt the data.
    /// * `ciphertext_with_tag` - The encrypted data concatenated with the authentication tag.
    /// * `aad` - Optional associated data that was authenticated.
    ///
    /// # Returns
    /// The original plaintext if decryption and authentication are successful.
    fn decrypt(
        key: &Self::Key,
        nonce: &[u8],
        ciphertext_with_tag: &[u8],
        aad: Option<AssociatedData>,
    ) -> Result<Vec<u8>, Error>;
} 