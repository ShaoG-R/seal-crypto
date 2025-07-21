#![forbid(unsafe_code)]

//! The `seal-crypto` library provides a set of pure, trait-based cryptographic
//! capability abstractions and implementations.
//!
//! This library offers a comprehensive, modular approach to cryptography with a focus on
//! type safety, performance, and ease of use. It provides both traditional and post-quantum
//! cryptographic algorithms through a unified trait-based interface.
//!
//! # Design Philosophy
//! - **Type Safety**: Extensive use of the type system to prevent misuse
//! - **Modularity**: Clean separation between abstractions and implementations
//! - **Performance**: Optimized implementations with hardware acceleration where available
//! - **Security**: Constant-time implementations and secure defaults
//! - **Flexibility**: Support for both `std` and `no_std` environments
//!
//! # Core Components
//! - **Traits**: Abstract interfaces for cryptographic operations
//! - **Schemes**: High-level, user-friendly implementations
//! - **Systems**: Low-level algorithm implementations
//! - **Errors**: Comprehensive error handling
//!
//! # Supported Algorithms
//! ## Symmetric Cryptography
//! - AES-GCM (128, 256-bit keys)
//! - ChaCha20-Poly1305
//! - XChaCha20-Poly1305
//!
//! ## Asymmetric Cryptography
//! ### Traditional
//! - RSA (OAEP, PSS)
//! - ECDSA
//! - ECDH
//!
//! ### Post-Quantum
//! - Kyber (KEM)
//! - Dilithium (Signatures)
//!
//! ## Key Derivation Functions
//! - HKDF
//! - PBKDF2
//! - Argon2
//!
//! ## Hash Functions & XOFs
//! - SHA-2 family (SHA-256, SHA-384, SHA-512)
//! - SHAKE (SHAKE128, SHAKE256)
//!
//! # Quick Start
//! ```rust
//! use seal_crypto::prelude::*;
//!
//! // Symmetric encryption example
//! # #[cfg(feature = "aes-gcm-default")]
//! # {
//! use seal_crypto::schemes::symmetric::aes_gcm::*;
//! let scheme = Aes256Gcm::default();
//! let key = Aes256Gcm::generate_key().unwrap();
//! let nonce = [0u8; 12]; // In practice, use a random nonce
//! let plaintext = b"Hello, World!";
//! let ciphertext = Aes256Gcm::encrypt(&key, &nonce, plaintext, None).unwrap();
//! let decrypted = Aes256Gcm::decrypt(&key, &nonce, &ciphertext, None).unwrap();
//! assert_eq!(plaintext, &decrypted[..]);
//! # }
//! ```
//!
//! # Feature Flags
//! The library uses feature flags to enable specific algorithms and reduce binary size:
//! - `std`: Enable standard library support (enabled by default)
//! - `aes-gcm-default`: Enable AES-GCM implementations
//! - `chacha20-poly1305-default`: Enable ChaCha20-Poly1305 implementations
//! - `rsa-default`: Enable RSA implementations
//! - `kyber-default`: Enable Kyber post-quantum KEM
//! - `dilithium-default`: Enable Dilithium post-quantum signatures
//! - And many more...
//!
//! `seal-crypto` 库提供了一套纯粹的、基于 Trait 的加密能力抽象和实现。
//!
//! 此库提供了一种全面的、模块化的密码学方法，专注于类型安全、性能和易用性。
//! 它通过统一的基于 trait 的接口提供传统和后量子密码算法。
//!
//! # 设计理念
//! - **类型安全**: 广泛使用类型系统防止误用
//! - **模块化**: 抽象和实现之间的清晰分离
//! - **性能**: 优化的实现，在可用时使用硬件加速
//! - **安全性**: 恒定时间实现和安全默认值
//! - **灵活性**: 支持 `std` 和 `no_std` 环境
//!
//! # 核心组件
//! - **Traits**: 加密操作的抽象接口
//! - **Schemes**: 高级的、用户友好的实现
//! - **Systems**: 低级算法实现
//! - **Errors**: 全面的错误处理
//!
//! # 支持的算法
//! ## 对称密码学
//! - AES-GCM (128, 256 位密钥)
//! - ChaCha20-Poly1305
//! - XChaCha20-Poly1305
//!
//! ## 非对称密码学
//! ### 传统算法
//! - RSA (OAEP, PSS)
//! - ECDSA
//! - ECDH
//!
//! ### 后量子算法
//! - Kyber (KEM)
//! - Dilithium (签名)
//!
//! ## 密钥派生函数
//! - HKDF
//! - PBKDF2
//! - Argon2
//!
//! ## 哈希函数和 XOF
//! - SHA-2 系列 (SHA-256, SHA-384, SHA-512)
//! - SHAKE (SHAKE128, SHAKE256)
//!
//! # 快速开始
//! ```rust
//! use seal_crypto::prelude::*;
//!
//! // 对称加密示例
//! # #[cfg(feature = "aes-gcm-default")]
//! # {
//! use seal_crypto::schemes::symmetric::aes_gcm::*;
//! let scheme = Aes256Gcm::default();
//! let key = Aes256Gcm::generate_key().unwrap();
//! let nonce = [0u8; 12]; // 实际使用中，请使用随机 nonce
//! let plaintext = b"Hello, World!";
//! let ciphertext = Aes256Gcm::encrypt(&key, &nonce, plaintext, None).unwrap();
//! let decrypted = Aes256Gcm::decrypt(&key, &nonce, &ciphertext, None).unwrap();
//! assert_eq!(plaintext, &decrypted[..]);
//! # }
//! ```
//!
//! # 特性标志
//! 库使用特性标志来启用特定算法并减少二进制大小：
//! - `std`: 启用标准库支持（默认启用）
//! - `aes-gcm-default`: 启用 AES-GCM 实现
//! - `chacha20-poly1305-default`: 启用 ChaCha20-Poly1305 实现
//! - `rsa-default`: 启用 RSA 实现
//! - `kyber-default`: 启用 Kyber 后量子 KEM
//! - `dilithium-default`: 启用 Dilithium 后量子签名
//! - 以及更多...

pub mod errors;
pub mod prelude;
pub mod schemes;

pub(crate) mod systems;
pub(crate) mod traits;

pub use ::zeroize;

#[cfg(feature = "secrecy")]
pub use ::secrecy;
