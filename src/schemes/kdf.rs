//! Key Derivation Function (KDF) schemes.
//!
//! 密钥派生函数 (KDF) 方案。

/// HMAC-based Key Derivation Function (HKDF).
///
/// 基于 HMAC 的密钥派生函数 (HKDF)。
#[cfg(feature = "hkdf")]
pub mod hkdf {
    pub use crate::systems::kdf::hkdf::*;
}

#[cfg(feature = "pbkdf2")]
pub mod pbkdf2 {
    pub use crate::systems::kdf::pbkdf2::*;
}
