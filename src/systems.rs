//! The `systems` module provides concrete implementations of the cryptographic traits.
//!
//! This module contains the actual implementations of various cryptographic algorithms
//! and schemes. It is organized into submodules based on the type of cryptographic
//! operation: asymmetric cryptography, aead cryptography, key derivation functions,
//! and extendable-output functions.
//!
//! These implementations are typically not used directly by end users, but rather
//! through the higher-level interfaces provided in the `schemes` module.
//!
//! # Internal Organization
//! - `asymmetric`: Implementations of public-key cryptographic schemes
//! - `aead`: Implementations of symmetric authenticated encryption schemes
//! - `kdf`: Implementations of key derivation functions
//! - `xof`: Implementations of extendable-output functions
//!
//! `systems` 模块提供了加密 trait 的具体实现。
//!
//! 此模块包含各种加密算法和方案的实际实现。它根据加密操作的类型组织为子模块：
//! 非对称密码学、对称认证加密、密钥派生函数和可扩展输出函数。
//!
//! 这些实现通常不被最终用户直接使用，而是通过 `schemes` 模块中提供的更高级接口使用。
//!
//! # 内部组织
//! - `asymmetric`: 公钥密码方案的实现
//! - `aead`: 对称认证加密方案的实现
//! - `kdf`: 密钥派生函数的实现
//! - `xof`: 可扩展输出函数的实现

pub mod asymmetric;
pub mod aead;
pub mod kdf;
pub mod xof;
