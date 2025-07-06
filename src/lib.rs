//! The `seal-crypto` library provides a set of pure, trait-based cryptographic
//! capability abstractions and implementations.
//!
//! `seal-crypto` 库提供了一套纯粹的、基于 Trait 的加密能力抽象和实现。

pub mod errors;
pub mod prelude;
pub mod schemes;

pub(crate) mod systems;
pub(crate) mod traits;

pub use ::zeroize;

#[cfg(feature = "secrecy")]
pub use ::secrecy;
