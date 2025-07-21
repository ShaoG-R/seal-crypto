//! Extendable-Output Function (XOF) schemes.
//!
//! This module provides access to extendable-output functions that can produce
//! variable-length outputs from fixed-length inputs. XOFs are useful for applications
//! that need flexible output lengths, such as key derivation and random number generation.
//!
//! # Available XOFs
//! - **SHAKE128**: Provides 128 bits of security strength
//! - **SHAKE256**: Provides 256 bits of security strength
//!
//! # Security Considerations
//! - Choose the appropriate security level based on your requirements
//! - SHAKE functions are part of the SHA-3 family and are cryptographically secure
//! - Output length can be arbitrary, but should be appropriate for the intended use
//!
//! 可扩展输出函数 (XOF) 方案。
//!
//! 此模块提供对可扩展输出函数的访问，这些函数可以从固定长度的输入产生可变长度的输出。
//! XOF 对于需要灵活输出长度的应用程序很有用，如密钥派生和随机数生成。
//!
//! # 可用的 XOF
//! - **SHAKE128**: 提供 128 位的安全强度
//! - **SHAKE256**: 提供 256 位的安全强度
//!
//! # 安全考虑
//! - 根据您的要求选择适当的安全级别
//! - SHAKE 函数是 SHA-3 系列的一部分，是加密安全的
//! - 输出长度可以是任意的，但应该适合预期用途

/// SHAKE (Secure Hash Algorithm and Keccak) family of Extendable-Output Functions (XOFs).
///
/// The SHAKE family provides cryptographically secure extendable-output functions
/// based on the Keccak sponge construction. These functions can produce outputs
/// of any desired length while maintaining security properties.
///
/// SHAKE (安全哈希算法和 Keccak) 系列的可扩展输出函数 (XOFs)。
///
/// SHAKE 系列基于 Keccak 海绵结构提供加密安全的可扩展输出函数。
/// 这些函数可以产生任何所需长度的输出，同时保持安全属性。
#[cfg(feature = "shake-default")]
pub mod shake {
    pub use crate::systems::xof::shake::*;
}
