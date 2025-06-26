//! Defines the top-level trait for a cryptographic algorithm.
//!
//! 定义了加密算法的顶层 trait。

/// A trait that provides a unique name for a cryptographic algorithm.
///
/// 为加密算法提供唯一名称的 trait。
pub trait Algorithm: 'static + Sized {
    /// The unique name of the signature algorithm (e.g., "RSA-PSS-SHA256").
    ///
    /// 签名算法的唯一名称（例如，"RSA-PSS-SHA256"）。
    const NAME: &'static str;
}
