//! Extendable-Output Function (XOF) schemes.
//!
//! 可扩展输出函数 (XOF) 方案。

/// SHAKE (Secure Hash Algorithm and Keccak) family of Extendable-Output Functions (XOFs).
///
/// SHAKE (安全哈希算法和 Keccak) 系列的可扩展输出函数 (XOFs)。
#[cfg(feature = "shake-default")]
pub mod shake {
    pub use crate::systems::xof::shake::*;
}
