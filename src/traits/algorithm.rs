//! Defines the top-level trait for a cryptographic algorithm.
//!
//! 定义了加密算法的顶层 trait。

/// A trait that provides a unique name for a cryptographic algorithm.
///
/// 为加密算法提供唯一名称的 trait。
pub trait Algorithm: 'static + Sized + Send + Sync + Clone + Default + std::fmt::Debug {
    /// The unique name of the signature algorithm (e.g., "RSA-PSS-SHA256").
    ///
    /// 签名算法的唯一名称（例如，"RSA-PSS-SHA256"）。
    fn name() -> String;

    /// A unique, stable, machine-readable identifier for the algorithm.
    ///
    /// 一个唯一的、稳定的、机器可读的算法标识符。
    const ID: u32;
}
