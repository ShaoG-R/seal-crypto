//! Entry point for symmetric algorithm implementations.
//!
//! 对称算法实现的入口点。

#[cfg(feature = "aes-gcm-default")]
pub mod aes_gcm;

#[cfg(feature = "chacha20-poly1305-default")]
pub mod chacha20_poly1305;
