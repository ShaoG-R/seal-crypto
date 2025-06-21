//! Defines the top-level error type for the `seal-crypto` crate.
//!
//! 为 `seal-crypto` crate 定义了顶层错误类型。

use crate::traits::{kem::KemError, sign::SignatureError, symmetric::SymmetricError};
use thiserror::Error;

/// The primary error type for the `seal-crypto` library.
///
/// This enum consolidates all possible failures from the underlying
/// cryptographic traits into a single, unified error type.
///
/// `seal-crypto` 库的主要错误类型。
///
/// 此枚举将来自底层加密 trait 的所有可能失败合并为一个统一的错误类型。
#[derive(Error, Debug)]
pub enum Error {
    /// An error occurred during a Key Encapsulation Mechanism (KEM) operation.
    ///
    /// 在密钥封装机制 (KEM) 操作期间发生错误。
    #[error("KEM operation failed")]
    Kem(#[from] KemError),

    /// An error occurred during a digital signature operation.
    ///
    /// 在数字签名操作期间发生错误。
    #[error("Signature operation failed")]
    Signature(#[from] SignatureError),

    /// An error occurred during a symmetric encryption or decryption operation.
    ///
    /// 在对称加密或解密操作期间发生错误。
    #[error("Symmetric cipher operation failed")]
    Symmetric(#[from] SymmetricError),

    /// An error occurred during key generation.
    ///
    /// 在密钥生成期间发生错误。
    #[error("Key generation failed")]
    KeyGeneration(#[source] Box<dyn std::error::Error + Send + Sync>),
}
