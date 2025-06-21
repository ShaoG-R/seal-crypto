//! # Seal-Crypto
//!
//! `seal-crypto` is the underlying cryptographic hybrid for the `seal-kit` ecosystem.
//! It provides a set of clean, composable, trait-based APIs for common
//! cryptographic operations, including:
//!
//! - Symmetric Authenticated Encryption (AEAD)
//! - Key Encapsulation Mechanisms (KEM)
//! - Digital Signatures
//!
//! This crate is designed to be highly modular and backend-agnostic. Implementations
//! for specific cryptographic algorithms (like AES-GCM, RSA, Kyber) are provided
//! and can be enabled via Cargo features.
//!
//! `seal-crypto` 是 `seal-kit` 生态系统的底层混合加密库。
//! 它为常见的加密操作提供了一套简洁、可组合、基于 trait 的 API，包括：
//!
//! - 对称认证加密 (AEAD)
//! - 密钥封装机制 (KEM)
//! - 数字签名
//!
//! 这个 crate 的设计是高度模块化和后端无关的。
//! 针对特定加密算法（如 AES-GCM、RSA、Kyber）的实现已提供，并可通过 Cargo features 启用。

pub use ::zeroize;
pub mod errors;
pub mod systems;
pub mod traits;

pub mod prelude {
    //! A "prelude" for users of the `seal-crypto` crate.
    //! This prelude is designed to be imported with a glob, i.e., `use seal_crypto::prelude::*;`.
    //!
    //! `seal-crypto` crate 用户的 "prelude"。
    //! 这个 prelude 设计为通过 glob 导入，即 `use seal_crypto::prelude::*;`。
    pub use crate::errors::Error as CryptoError;
    pub use crate::traits::{
        kem::Kem,
        key::KeyGenerator,
        sign::{Signer, Verifier},
        symmetric::{SymmetricDecryptor, SymmetricEncryptor, SymmetricKeyGenerator},
    };
    pub use ::zeroize;
}
