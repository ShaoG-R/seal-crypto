//! Key Derivation Function (KDF) schemes.
//!
//! 密钥派生函数 (KDF) 方案。

/// HMAC-based Key Derivation Function (HKDF).
///
/// 基于 HMAC 的密钥派生函数 (HKDF)。
#[cfg(feature = "hkdf-default")]
pub mod hkdf {
    pub use crate::systems::kdf::hkdf::*;
}

/// Password-Based Key Derivation Function 2 (PBKDF2).
///
/// 基于密码的密钥派生函数 2 (PBKDF2)。
#[cfg(feature = "pbkdf2-default")]
pub mod pbkdf2 {
    pub use crate::systems::kdf::pbkdf2::*;
}

/// SHAKE (Secure Hash Algorithm and Keccak) family of Extendable-Output Functions (XOFs).
///
/// SHAKE (安全哈希算法和 Keccak) 系列的可扩展输出函数 (XOFs)。
#[cfg(feature = "shake-default")]
pub mod shake {
    pub use crate::systems::kdf::shake::*;
}

#[cfg(feature = "argon2-default")]
pub mod argon2 {
    pub use crate::systems::kdf::argon2::*;
}
