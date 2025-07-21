//! Key Derivation Function (KDF) schemes.
//!
//! This module provides access to various key derivation functions that can derive
//! cryptographic keys from input keying material or passwords. KDFs are essential
//! for secure key management and password-based cryptography.
//!
//! # Available KDFs
//! - **HKDF**: HMAC-based KDF, suitable for deriving keys from high-entropy sources
//! - **PBKDF2**: Password-based KDF, designed for deriving keys from passwords
//! - **Argon2**: Modern password hashing function, resistant to various attacks
//!
//! # Security Considerations
//! - Use HKDF when you have high-entropy input keying material
//! - Use PBKDF2 or Argon2 for password-based key derivation
//! - Always use appropriate iteration counts and salt values
//!
//! 密钥派生函数 (KDF) 方案。
//!
//! 此模块提供对各种密钥派生函数的访问，这些函数可以从输入密钥材料或密码派生加密密钥。
//! KDF 对于安全的密钥管理和基于密码的密码学至关重要。
//!
//! # 可用的 KDF
//! - **HKDF**: 基于 HMAC 的 KDF，适用于从高熵源派生密钥
//! - **PBKDF2**: 基于密码的 KDF，专为从密码派生密钥而设计
//! - **Argon2**: 现代密码哈希函数，能够抵抗各种攻击
//!
//! # 安全考虑
//! - 当您有高熵输入密钥材料时使用 HKDF
//! - 对于基于密码的密钥派生使用 PBKDF2 或 Argon2
//! - 始终使用适当的迭代次数和盐值

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

/// Argon2 password hashing function.
///
/// Argon2 is a modern, memory-hard password hashing function that is resistant to
/// GPU-based attacks and side-channel attacks. It is the winner of the Password
/// Hashing Competition and is recommended for new applications.
///
/// Argon2 密码哈希函数。
///
/// Argon2 是一种现代的、内存困难的密码哈希函数，能够抵抗基于 GPU 的攻击和侧信道攻击。
/// 它是密码哈希竞赛的获胜者，推荐用于新应用程序。
#[cfg(feature = "argon2-default")]
pub mod argon2 {
    pub use crate::systems::kdf::argon2::*;
}
