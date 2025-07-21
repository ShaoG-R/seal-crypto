//! Extendable-Output Function (XOF) implementations.
//!
//! This module provides implementations of extendable-output functions that can
//! produce variable-length outputs from fixed-length inputs. XOFs are useful
//! for applications requiring flexible output lengths.
//!
//! # Available Implementations
//! - **SHAKE**: SHA-3 based XOFs with different security levels
//!
//! # Security Considerations
//! XOFs maintain their security properties regardless of output length,
//! making them suitable for generating keys, nonces, and other cryptographic material.
//!
//! 可扩展输出函数 (XOF) 实现。
//!
//! 此模块提供可扩展输出函数的实现，这些函数可以从固定长度的输入产生可变长度的输出。
//! XOF 对于需要灵活输出长度的应用程序很有用。
//!
//! # 可用实现
//! - **SHAKE**: 基于 SHA-3 的 XOF，具有不同的安全级别
//!
//! # 安全考虑
//! XOF 无论输出长度如何都保持其安全属性，使其适用于生成密钥、nonce 和其他加密材料。

/// SHAKE family of extendable-output functions implementation.
///
/// SHAKE 系列可扩展输出函数实现。
#[cfg(feature = "shake-default")]
pub mod shake;
