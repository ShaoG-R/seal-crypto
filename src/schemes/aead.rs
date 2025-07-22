//! Symmetric cryptographic schemes.
//!
//! This module provides access to various symmetric authenticated encryption schemes.
//! These schemes provide both confidentiality and authenticity, ensuring that data
//! is both encrypted and protected against tampering.
//!
//! # Available Schemes
//! - **AES-GCM**: Advanced Encryption Standard with Galois/Counter Mode
//! - **ChaCha20-Poly1305**: ChaCha20 stream cipher with Poly1305 authenticator
//!
//! # Security Considerations
//! - Always use unique nonces for each encryption operation with the same key
//! - Never reuse nonces as this can compromise security
//! - Use appropriate key sizes (128, 192, or 256 bits for AES)
//!
//! 对称加密方案。
//!
//! 此模块提供对各种对称认证加密方案的访问。
//! 这些方案同时提供机密性和真实性，确保数据既被加密又受到防篡改保护。
//!
//! # 可用方案
//! - **AES-GCM**: 高级加密标准与伽罗瓦/计数器模式
//! - **ChaCha20-Poly1305**: ChaCha20 流密码与 Poly1305 认证器
//!
//! # 安全考虑
//! - 对于同一密钥的每次加密操作，始终使用唯一的 nonce
//! - 永远不要重复使用 nonce，因为这会危及安全性
//! - 使用适当的密钥大小（AES 为 128、192 或 256 位）

/// AES-GCM authenticated encryption.
///
/// AES-GCM (Advanced Encryption Standard with Galois/Counter Mode) is a widely-used
/// authenticated encryption scheme that provides both confidentiality and authenticity.
/// It is standardized and recommended for most applications requiring symmetric encryption.
///
/// AES-GCM 认证加密。
///
/// AES-GCM（高级加密标准与伽罗瓦/计数器模式）是一种广泛使用的认证加密方案，
/// 同时提供机密性和真实性。它是标准化的，推荐用于大多数需要对称加密的应用程序。
pub mod aes_gcm {
    #[cfg(feature = "aes-gcm-default")]
    pub use crate::systems::aead::aes_gcm::*;
}

/// ChaCha20-Poly1305 authenticated encryption.
///
/// ChaCha20-Poly1305 is a modern authenticated encryption scheme that combines
/// the ChaCha20 stream cipher with the Poly1305 message authentication code.
/// It offers excellent performance on software implementations and is resistant
/// to timing attacks.
///
/// ChaCha20-Poly1305 认证加密。
///
/// ChaCha20-Poly1305 是一种现代的认证加密方案，结合了 ChaCha20 流密码和
/// Poly1305 消息认证码。它在软件实现上提供出色的性能，并且能够抵抗时序攻击。
#[cfg(feature = "chacha20-poly1305-default")]
pub mod chacha20_poly1305 {
    pub use crate::systems::aead::chacha20_poly1305::*;
    pub use chacha20poly1305::aead::Nonce;
}
