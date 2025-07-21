//! Entry point for symmetric algorithm implementations.
//!
//! This module provides implementations of symmetric authenticated encryption algorithms.
//! These algorithms provide both confidentiality and authenticity in a single operation,
//! making them suitable for most encryption needs.
//!
//! # Available Implementations
//! - **AES-GCM**: Industry standard, hardware-accelerated on many platforms
//! - **ChaCha20-Poly1305**: Software-optimized, constant-time implementation
//!
//! # Security Considerations
//! All implementations provide authenticated encryption with associated data (AEAD),
//! ensuring both confidentiality and integrity of the encrypted data.
//!
//! 对称算法实现的入口点。
//!
//! 此模块提供对称认证加密算法的实现。
//! 这些算法在单个操作中同时提供机密性和真实性，使其适用于大多数加密需求。
//!
//! # 可用实现
//! - **AES-GCM**: 行业标准，在许多平台上有硬件加速
//! - **ChaCha20-Poly1305**: 软件优化，恒定时间实现
//!
//! # 安全考虑
//! 所有实现都提供带关联数据的认证加密 (AEAD)，确保加密数据的机密性和完整性。

/// AES-GCM (Advanced Encryption Standard with Galois/Counter Mode) implementation.
///
/// AES-GCM (高级加密标准与伽罗瓦/计数器模式) 实现。
#[cfg(feature = "aes-gcm-default")]
pub mod aes_gcm;

/// ChaCha20-Poly1305 authenticated encryption implementation.
///
/// ChaCha20-Poly1305 认证加密实现。
#[cfg(feature = "chacha20-poly1305-default")]
pub mod chacha20_poly1305;
