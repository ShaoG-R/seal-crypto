//! Defines traits for digital signature creation and verification.
//!
//! 定义了用于数字签名创建和验证的 trait。

use crate::errors::Error;
use crate::traits::key::{Algorithm, KeyGenerator};
#[cfg(feature = "std")]
use thiserror::Error;

/// Represents a digital signature, wrapping a byte vector for type safety.
///
/// 代表一个数字签名，为增强类型安全而包装了一个字节向量。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature(pub Vec<u8>);

impl Signature {
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Defines the errors that can occur during signing and verification.
///
/// 定义了在签名和验证过程中可能发生的错误。
#[cfg_attr(feature = "std", derive(Error))]
#[derive(Debug, PartialEq, Eq)]
pub enum SignatureError {
    /// Failed to create a digital signature.
    ///
    /// 创建数字签名失败。
    #[cfg_attr(feature = "std", error("Signing failed"))]
    Signing,

    /// Signature verification failed, indicating that the signature is invalid,
    /// the data has been tampered with, or the wrong key was used.
    ///
    /// 签名验证失败，表明签名无效、数据被篡改或使用了错误的密钥。
    #[cfg_attr(feature = "std", error("Verification failed"))]
    Verification,

    /// The provided signature is malformed or has an invalid length.
    ///
    /// 提供的签名格式错误或长度无效。
    #[cfg_attr(feature = "std", error("Invalid signature format"))]
    InvalidSignature,
}

/// A trait for cryptographic schemes that can create digital signatures.
///
/// 用于能够创建数字签名的加密方案的 trait。
pub trait Signer: Algorithm {
    /// Creates a digital signature for a given message digest.
    ///
    /// 为给定的消息摘要创建一个数字签名。
    fn sign(private_key: &Self::PrivateKey, message: &[u8]) -> Result<Signature, Error>;
}

/// A trait for cryptographic schemes that can verify digital signatures.
///
/// 用于能够验证数字签名的加密方案的 trait。
pub trait Verifier: Algorithm {
    /// Verifies a digital signature for a given message digest.
    ///
    /// # Returns
    /// `Ok(())` if the signature is valid, otherwise an `Err`.
    ///
    /// 验证给定消息摘要的数字签名。
    ///
    /// # 返回
    /// 如果签名有效，则返回 `Ok(())`，否则返回 `Err`。
    fn verify(
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), Error>;
}

/// A unified trait for a complete signature scheme.
///
/// It combines key generation, signing, and verification capabilities.
/// This is the primary trait that should be implemented by a signature algorithm.
///
/// 一个完整的签名方案的统一 trait。
///
/// 它结合了密钥生成、签名和验证的能力。
/// 这是签名算法应该实现的主要 trait。
pub trait SignatureScheme: Algorithm + KeyGenerator + Signer + Verifier {}

impl<T: Algorithm + KeyGenerator + Signer + Verifier> SignatureScheme for T {}
