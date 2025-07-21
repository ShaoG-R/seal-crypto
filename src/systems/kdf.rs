//! Key Derivation Function (KDF) implementations.
//!
//! This module provides implementations of various key derivation functions
//! that can derive cryptographic keys from input material or passwords.
//!
//! # Available Implementations
//! - **HKDF**: HMAC-based key derivation for high-entropy inputs
//! - **PBKDF2**: Password-based key derivation with configurable iterations
//! - **Argon2**: Modern memory-hard password hashing function
//!
//! # Usage Guidelines
//! - Use HKDF when deriving keys from high-entropy sources like shared secrets
//! - Use PBKDF2 or Argon2 when deriving keys from user passwords
//! - Always use appropriate iteration counts and unique salts
//!
//! 密钥派生函数 (KDF) 实现。
//!
//! 此模块提供各种密钥派生函数的实现，这些函数可以从输入材料或密码派生加密密钥。
//!
//! # 可用实现
//! - **HKDF**: 基于 HMAC 的密钥派生，用于高熵输入
//! - **PBKDF2**: 基于密码的密钥派生，具有可配置的迭代次数
//! - **Argon2**: 现代内存困难密码哈希函数
//!
//! # 使用指南
//! - 从高熵源（如共享密钥）派生密钥时使用 HKDF
//! - 从用户密码派生密钥时使用 PBKDF2 或 Argon2
//! - 始终使用适当的迭代次数和唯一的盐

/// HMAC-based Key Derivation Function (HKDF) implementation.
///
/// 基于 HMAC 的密钥派生函数 (HKDF) 实现。
#[cfg(feature = "hkdf-default")]
pub mod hkdf;

/// Password-Based Key Derivation Function 2 (PBKDF2) implementation.
///
/// 基于密码的密钥派生函数 2 (PBKDF2) 实现。
#[cfg(feature = "pbkdf2-default")]
pub mod pbkdf2;

/// Argon2 password hashing function implementation.
///
/// Argon2 密码哈希函数实现。
#[cfg(feature = "argon2-default")]
pub mod argon2;
