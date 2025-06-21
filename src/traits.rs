//! The `traits` module serves as the single entry point for all cryptographic capability traits.
//! It re-exports the individual trait definitions from its submodules.
//!
//! `traits` 模块是所有加密能力 trait 的统一入口。
//! 它从其子模块中重新导出各个 trait 的定义。

pub mod kem;
pub mod key;
pub mod sign;
pub mod symmetric;