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

/// SHAKE (Secure Hash Algorithm and Keccak) family of Extendable-Output Functions (XOFs).
///
/// SHAKE (安全哈希算法和 Keccak) 系列的可扩展输出函数 (XOFs)。
#[cfg(feature = "shake")]
pub mod shake {
    pub use crate::systems::kdf::shake::*;
}
