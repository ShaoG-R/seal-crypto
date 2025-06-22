//! Symmetric cryptographic schemes.
//!
//! 对称加密方案。

/// AES-GCM authenticated encryption.
///
/// AES-GCM 认证加密。
pub mod aes_gcm {
    pub use crate::systems::symmetric::aes_gcm::{Aes128Gcm, Aes256Gcm, AesGcmParams, Nonce, Tag};
}

/// ChaCha20-Poly1305 authenticated encryption.
///
/// ChaCha20-Poly1305 认证加密。
pub mod chacha20_poly1305 {
    pub use crate::systems::symmetric::chacha20_poly1305::{
        ChaCha20Poly1305Scheme, Chacha20Poly1305Params, Tag, XChaCha20Poly1305Scheme,
    };
    pub use chacha20poly1305::aead::Nonce;
}
