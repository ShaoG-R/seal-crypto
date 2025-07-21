//! Hash function schemes.
//!
//! This module provides access to various cryptographic hash functions from the SHA-2 family.
//! These hash functions are widely used for data integrity verification, digital signatures,
//! and other cryptographic applications.
//!
//! # Available Hash Functions
//! - **SHA-256**: 256-bit output, suitable for most applications
//! - **SHA-384**: 384-bit output, provides higher security margin
//! - **SHA-512**: 512-bit output, highest security level in SHA-2 family
//!
//! # Security Considerations
//! All provided hash functions are cryptographically secure and resistant to collision attacks.
//! Choose the appropriate hash function based on your security requirements and performance needs.
//!
//! 哈希函数方案。
//!
//! 此模块提供对 SHA-2 系列各种加密哈希函数的访问。
//! 这些哈希函数广泛用于数据完整性验证、数字签名和其他加密应用。
//!
//! # 可用的哈希函数
//! - **SHA-256**: 256 位输出，适用于大多数应用
//! - **SHA-384**: 384 位输出，提供更高的安全边际
//! - **SHA-512**: 512 位输出，SHA-2 系列中的最高安全级别
//!
//! # 安全考虑
//! 所有提供的哈希函数都是加密安全的，能够抵抗碰撞攻击。
//! 根据您的安全要求和性能需求选择合适的哈希函数。

/// SHA-256 hash function.
///
/// SHA-256 哈希函数。
#[cfg(feature = "sha2")]
pub use crate::traits::params::hash::Sha256;

/// SHA-384 hash function.
///
/// SHA-384 哈希函数。
#[cfg(feature = "sha2")]
pub use crate::traits::params::hash::Sha384;

/// SHA-512 hash function.
///
/// SHA-512 哈希函数。
#[cfg(feature = "sha2")]
pub use crate::traits::params::hash::Sha512;
