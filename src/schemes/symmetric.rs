//! Symmetric cryptographic schemes.
//!
//! 对称加密方案。

/// AES-GCM authenticated encryption.
///
/// AES-GCM 认证加密。
pub mod aes_gcm {
    #[cfg(feature = "aes-gcm")]
    pub use crate::systems::symmetric::aes_gcm::*;
}

/// ChaCha20-Poly1305 authenticated encryption.
///
/// ChaCha20-Poly1305 认证加密。
#[cfg(feature = "chacha20-poly1305")]
pub mod chacha20_poly1305 {
    pub use crate::systems::symmetric::chacha20_poly1305::*;
    pub use chacha20poly1305::aead::Nonce;
}
