//! Defines traits for symmetric authenticated encryption (AEAD) cryptographic operations.
//!
//! 定义了对称认证加密（AEAD）操作的 trait。
pub mod aead;

pub use aead::*;

use crate::{errors::Error, traits::key::{Key, SymmetricKeySet}};
use zeroize::Zeroizing;


#[cfg(feature = "std")]
use thiserror::Error;

/// A key for a symmetric cipher.
///
/// 对称密码的密钥。
pub type SymmetricKey = Zeroizing<Vec<u8>>;

impl Key for SymmetricKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Zeroizing::new(bytes.to_vec()))
    }

    fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(self.to_vec())
    }
}



/// Defines the errors that can occur during symmetric encryption and decryption.
///
/// 定义了在对称加密和解密过程中可能发生的错误。
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Error))]
pub enum SymmetricError {
    /// Failed to encrypt the plaintext.
    ///
    /// 加密明文失败。
    #[cfg_attr(feature = "std", error("Encryption failed"))]
    Encryption,

    /// Failed to decrypt the ciphertext. This commonly occurs if the key is wrong,
    /// the ciphertext or AAD has been tampered with, or the authentication tag is invalid.
    ///
    /// 解密密文失败。如果密钥错误、密文或 AAD 被篡改，或认证标签无效，则通常会发生这种情况。
    #[cfg_attr(feature = "std", error("Decryption failed"))]
    Decryption,

    /// The provided key has an invalid size.
    ///
    /// 提供的密钥大小无效。
    #[cfg_attr(feature = "std", error("Invalid key size"))]
    InvalidKeySize,

    /// The provided nonce has an invalid size.
    ///
    /// 提供的 nonce 大小无效。
    #[cfg_attr(feature = "std", error("Invalid nonce size"))]
    InvalidNonceSize,

    /// The provided ciphertext is malformed or truncated.
    ///
    /// 提供的密文格式错误或被截断。
    #[cfg_attr(feature = "std", error("Invalid ciphertext"))]
    InvalidCiphertext,

    /// The provided output buffer is too small.
    ///
    /// 提供的输出缓冲区太小。
    #[cfg_attr(feature = "std", error("Output buffer is too small"))]
    OutputTooSmall,
}

/// A trait for generating symmetric keys.
///
/// 用于生成对称密钥的 trait。
pub trait SymmetricKeyGenerator: SymmetricKeySet {
    /// The size of the key in bytes.
    ///
    /// 密钥的大小（以字节为单位）。
    const KEY_SIZE: usize;
    /// Generates a new symmetric key.
    ///
    /// 生成一个新的对称密钥。
    fn generate_key() -> Result<Self::Key, Error>;
}