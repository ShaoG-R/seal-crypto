//! Schemes for Authenticated Encryption with Associated Data (AEAD).
//!
//! 带关联数据的认证加密 (AEAD) 方案。

#[cfg(feature = "aes-gcm")]
pub use crate::systems::symmetric::aes_gcm::AesGcmScheme;

#[cfg(feature = "chacha20-poly1305")]
pub use crate::systems::symmetric::chacha20_poly1305::Chacha20Poly1305Scheme;

/// Parameters for the AES-GCM scheme.
///
/// AES-GCM 方案的参数。
#[cfg(feature = "aes-gcm")]
pub mod aes_gcm {
    pub use crate::systems::symmetric::aes_gcm::{Aes128, Aes256};
}

/// Parameters for the ChaCha20-Poly1305 scheme.
///
/// ChaCha20-Poly1305 方案的参数。
#[cfg(feature = "chacha20-poly1305")]
pub mod chacha20_poly1305 {
    pub use crate::systems::symmetric::chacha20_poly1305::Chacha20;
} 