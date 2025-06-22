//! Public-facing schemes for cryptographic operations.
//!
//! This module provides a user-friendly API for accessing specific cryptographic
//! schemes, organized by capability (e.g., `sign`, `kem`, `aead`). It re-exports
//! types from the internal `systems` and `traits` modules to provide a stable,
//! intuitive "facade" for consumers of the library.
//!
//! # Example
//!
//! To use the RSA-4096 signature scheme with SHA-256, you can now do:
//!
//! ```rust,ignore
//! use seal_crypto::schemes::sign::{self, RsaScheme};
//!
//! type MyRsaSigner = RsaScheme<sign::rsa::Rsa<sign::rsa::Rsa4096, sign::rsa::Sha256>>;
//! ```
//!
//! 公开的加密操作方案。
//!
//! 本模块为访问特定的加密方案提供了一个用户友好的 API，按功能（例如 `sign`、`kem`、`aead`）进行组织。
//! 它从内部的 `systems` 和 `traits` 模块中重新导出类型，为库的使用者提供一个稳定、直观的"外观"。

pub mod aead;
pub mod hash;
pub mod kem;
pub mod sign;
