//! Defines the top-level error type for the `seal-crypto` crate.
//!
//! 为 `seal-crypto` crate 定义了顶层错误类型。

use crate::traits::{KemError, KeyAgreementError, KeyError, SignatureError, SymmetricError, KdfError};

#[cfg(feature = "std")]
use thiserror::Error;

/// The primary error type for the `seal-crypto` library.
///
/// This enum consolidates all possible failures from the underlying
/// cryptographic traits into a single, unified error type.
///
/// `seal-crypto` 库的主要错误类型。
///
/// 此枚举将来自底层加密 trait 的所有可能失败合并为一个统一的错误类型。
#[cfg_attr(feature = "std", derive(Error))]
#[derive(Debug)]
pub enum Error {
    /// An error occurred during a key operation.
    ///
    /// 在密钥操作期间发生错误。
    #[cfg_attr(feature = "std", error("Key operation failed"))]
    Key(#[cfg_attr(feature = "std", from)] KeyError),

    /// An error occurred during a Key Encapsulation Mechanism (KEM) operation.
    ///
    /// 在密钥封装机制 (KEM) 操作期间发生错误。
    #[cfg_attr(feature = "std", error("KEM operation failed"))]
    Kem(#[cfg_attr(feature = "std", from)] KemError),

    /// An error occurred during a digital signature operation.
    ///
    /// 在数字签名操作期间发生错误。
    #[cfg_attr(feature = "std", error("Signature operation failed"))]
    Signature(#[cfg_attr(feature = "std", from)] SignatureError),

    /// An error occurred during a symmetric encryption or decryption operation.
    ///
    /// 在对称加密或解密操作期间发生错误。
    #[cfg_attr(feature = "std", error("Symmetric encryption/decryption error"))]
    Symmetric(#[cfg_attr(feature = "std", from)] SymmetricError),

    /// An error occurred during a key agreement operation.
    ///
    /// 在密钥协商操作期间发生错误。
    #[cfg_attr(feature = "std", error("Key agreement operation failed"))]
    KeyAgreement(#[cfg_attr(feature = "std", from)] KeyAgreementError),

    /// KDF error.
    ///
    /// 密钥派生函数 (KDF) 错误。
    #[cfg(feature = "kdf")]
    #[cfg_attr(feature = "std", error("KDF error"))]
    Kdf(#[cfg_attr(feature = "std", from)] KdfError),
}

// Manual From impls for no_std
#[cfg(not(feature = "std"))]
impl From<KeyError> for Error {
    fn from(e: KeyError) -> Self {
        Error::Key(e)
    }
}

#[cfg(not(feature = "std"))]
impl From<KemError> for Error {
    fn from(e: KemError) -> Self {
        Error::Kem(e)
    }
}

#[cfg(not(feature = "std"))]
impl From<SignatureError> for Error {
    fn from(e: SignatureError) -> Self {
        Error::Signature(e)
    }
}

#[cfg(not(feature = "std"))]
impl From<SymmetricError> for Error {
    fn from(e: SymmetricError) -> Self {
        Error::Symmetric(e)
    }
}

#[cfg(not(feature = "std"))]
impl From<KeyAgreementError> for Error {
    fn from(e: KeyAgreementError) -> Self {
        Error::KeyAgreement(e)
    }
}

#[cfg(all(not(feature = "std"), feature = "kdf"))]
impl From<KdfError> for Error {
    fn from(e: KdfError) -> Self {
        Error::Kdf(e)
    }
}
