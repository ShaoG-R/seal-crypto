//! Public-facing schemes for cryptographic operations.
//!
//! This module provides high-level, user-friendly interfaces to various cryptographic schemes.
//! It organizes cryptographic functionality into logical categories such as asymmetric cryptography,
//! symmetric cryptography, key derivation functions, hash functions, and extendable-output functions.
//!
//! Each submodule contains concrete implementations that users can directly import and use
//! without needing to understand the underlying implementation details.
//!
//! 面向用户的加密操作方案。
//!
//! 此模块为各种加密方案提供了高级的、用户友好的接口。
//! 它将加密功能组织为逻辑类别，如非对称密码学、对称密码学、密钥派生函数、哈希函数和可扩展输出函数。
//!
//! 每个子模块都包含用户可以直接导入和使用的具体实现，
//! 而无需了解底层实现细节。

pub mod asymmetric;
pub mod hash;
pub mod kdf;
pub mod symmetric;
pub mod xof;
